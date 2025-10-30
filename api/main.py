from fastapi import FastAPI, UploadFile, File, HTTPException, Path, Request, Response
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import httpx
import re
import uuid
import time
from typing import Dict

app = FastAPI(title="YARA Rule Submission Platform")

SCANNER_URL = "http://scanner:5000/scan"

# Hardcoded lab configuration
AVAILABLE_LABS = ["lab1", "lab2"]

# Rate limiting configuration
RATE_LIMIT_SECONDS = 60
session_uploads: Dict[str, float] = {}  # session_id -> last_upload_timestamp


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


def get_or_create_session(request: Request, response: Response) -> str:
    """Get existing session ID from cookie or create a new one."""
    session_id = request.cookies.get("session_id")
    if not session_id:
        session_id = str(uuid.uuid4())
        response.set_cookie(
            key="session_id",
            value=session_id,
            max_age=3600,  # 1 hour
            httponly=True,
            samesite="lax"
        )
    return session_id


def check_rate_limit(session_id: str) -> tuple[bool, int]:
    """
    Check if session can upload based on rate limit.
    
    Returns:
        (can_upload: bool, seconds_remaining: int)
    """
    current_time = time.time()
    last_upload = session_uploads.get(session_id, 0)
    
    if current_time - last_upload >= RATE_LIMIT_SECONDS:
        return True, 0
    
    seconds_remaining = int(RATE_LIMIT_SECONDS - (current_time - last_upload)) + 1
    return False, seconds_remaining


@app.get("/")
async def root():
    """Serve the frontend HTML."""
    return FileResponse("static/index.html", media_type="text/html")


@app.get("/labs")
async def list_labs():
    """
    List all available labs.
    
    Returns:
        List of available lab IDs
    """
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
    """
    Submit a YARA rule file for scanning against a specific lab.
    
    The rule will be validated and then run against lab-specific samples and benign files.
    
    Args:
        lab_id: The lab identifier (e.g., 'lab1', 'lab2')
        file: YARA rule file to submit
    
    Returns:
        Detailed scan results including matches for lab samples and benign files
    """
    
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
    session_uploads[session_id] = time.time()
    
    return JSONResponse(content={
        "status": "success",
        "lab_id": lab_id,
        "result": result
    })


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

