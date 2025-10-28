from fastapi import FastAPI, UploadFile, File, HTTPException, Path
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import httpx
import re

app = FastAPI(title="YARA Rule Submission Platform")

SCANNER_URL = "http://scanner:5000/scan"

# Hardcoded lab configuration
AVAILABLE_LABS = ["lab1", "lab2"]


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

