from fastapi import FastAPI, UploadFile, File, HTTPException, Path, Request, Response
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import httpx
import re
import uuid
import time
import random
from typing import Dict

SHOW_MATCH_DETAIL = False
AVAILABLE_LABS = ["lab1", "lab2"]
RATE_LIMIT_SECONDS = 60
SESSION_EXPIRY_SECONDS = 3600  # 1 hour, matching cookie max_age
SCANNER_URL = "http://scanner:5000/scan"

app = FastAPI(title="YARA Rule Submission Platform")

# Session storage: session_id -> {"created_at": timestamp, "last_upload": timestamp}
session_data: Dict[str, Dict[str, float]] = {}


def validate_yara_rule(content: str) -> bool:
    """Basic YARA rule syntax validation."""
    if not content.strip():
        return False
    
    # Check for 'rule' keyword
    if not re.search(r'\brule\s+\w+', content):
        return False
    
    # Check for basic structure: rule name { ... }
    if not re.search(r'\brule\s+\w+\s*\{[\s\S]*\}', content):
        return False
    
    return True


def is_session_expired(session_id: str) -> bool:
    """Check if a session has expired based on its creation time."""
    if session_id not in session_data:
        return True
    
    current_time = time.time()
    created_at = session_data[session_id].get("created_at", 0)
    
    return (current_time - created_at) >= SESSION_EXPIRY_SECONDS


def cleanup_expired_sessions():
    """Remove expired sessions from memory to prevent memory leaks."""
    current_time = time.time()
    expired_sessions = [
        session_id for session_id, data in session_data.items()
        if (current_time - data.get("created_at", 0)) >= SESSION_EXPIRY_SECONDS
    ]
    
    for session_id in expired_sessions:
        del session_data[session_id]
    
    return len(expired_sessions)


def get_or_create_session(request: Request, response: Response) -> str:
    """Get existing session ID from cookie or create a new one."""
    if random.random() < 0.1:
        cleanup_expired_sessions()
    
    session_id = request.cookies.get("session_id")
    
    if not session_id or is_session_expired(session_id):
        if session_id and session_id in session_data:
            del session_data[session_id]
        
        session_id = str(uuid.uuid4())
        current_time = time.time()
        session_data[session_id] = {
            "created_at": current_time,
            "last_upload": 0
        }
        response.set_cookie(
            key="session_id",
            value=session_id,
            max_age=SESSION_EXPIRY_SECONDS,
            httponly=True,
            samesite="lax"
        )
    else:
        if session_id not in session_data:
            current_time = time.time()
            session_data[session_id] = {
                "created_at": current_time,
                "last_upload": 0
            }
    
    return session_id


def check_rate_limit(session_id: str) -> tuple[bool, int]:
    """Check if session can upload based on rate limit."""
    current_time = time.time()
    session_info = session_data.get(session_id, {})
    last_upload = session_info.get("last_upload", 0)
    
    if current_time - last_upload >= RATE_LIMIT_SECONDS:
        return True, 0
    
    seconds_remaining = int(RATE_LIMIT_SECONDS - (current_time - last_upload)) + 1
    return False, seconds_remaining


def determine_scan_status(result: dict) -> str:
    """Determine the scan status message based on scanner results."""
    benign_matched = result.get("benign", {}).get("matched_files", 0)
    random_matched = result.get("random", {}).get("matched_files", 0)
    lab_matched = result.get("lab", {}).get("matched_files", 0)
    lab_total = result.get("lab", {}).get("total_files", 0)
    
    if benign_matched > 0:
        return "False Positive Detected (benign)"
    if random_matched > 0:
        return "False Positive Detected (random)"
    if lab_matched == 0:
        return "None Detected"
    if lab_matched < lab_total:
        return "Partial Samples Detected"

    return "All Samples Detected"


@app.get("/")
async def root():
    return FileResponse("static/index.html", media_type="text/html")


@app.get("/labs")
async def list_labs():
    return {
        "labs": AVAILABLE_LABS,
        "count": len(AVAILABLE_LABS)
    }


@app.post("/submit/{lab_id}")
async def submit_rule(
    request: Request,
    response: Response,
    lab_id: str = Path(..., description="Lab identifier (e.g., 'lab1', 'lab2')"),
    file: UploadFile = File(...)
):
    """Submit a YARA rule file for scanning against a specific lab."""
    
    session_id = get_or_create_session(request, response)
    
    # Check rate limit
    # FIXME: Users can bypass this rate limit by clearing cookies or using incognito mode
    # This is acceptable for a lab environment but not suitable for production
    can_upload, seconds_remaining = check_rate_limit(session_id)
    if not can_upload:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Please wait {seconds_remaining} seconds before uploading again."
        )
    
    # Validate lab_id
    if lab_id not in AVAILABLE_LABS:
        raise HTTPException(
            status_code=404,
            detail=f"Lab '{lab_id}' not found. Available labs: {', '.join(AVAILABLE_LABS)}"
        )
    
    # Read file content
    try:
        content = await file.read()
        rule_text = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be a valid text file")
    
    # Validate YARA rule syntax
    if not validate_yara_rule(rule_text):
        raise HTTPException(
            status_code=400, 
            detail="Invalid YARA rule format. Must contain 'rule <name> { ... }'"
        )
    
    # Send to scanner service
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                SCANNER_URL,
                json={
                    "rule": rule_text,
                    "lab_id": lab_id
                }
            )
            response.raise_for_status()
            result = response.json()
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail="Scanner service unavailable")
    except httpx.ConnectError as e:
        raise HTTPException(status_code=503, detail="Scanner service connection failed")
    except httpx.TimeoutException as e:
        raise HTTPException(status_code=504, detail="Scanner service timeout")
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Scanner error: {e.response.text}"
        )
    
    # Update last upload timestamp for this session
    current_time = time.time()
    if session_id in session_data:
        session_data[session_id]["last_upload"] = current_time
    else:
        # Shouldn't happen, but create entry if missing
        session_data[session_id] = {
            "created_at": current_time,
            "last_upload": current_time
        }

    scan_status = determine_scan_status(result)

    response_data = {
        "status": "success",
        "lab_id": lab_id,
        "scan_status": scan_status,
    }
    if SHOW_MATCH_DETAIL:
        response_data["result"] = result
    
    return JSONResponse(content=response_data)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


# Mount static files for the frontend
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except Exception:
    pass  # Static files optional, in case the directory doesn't exist


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

