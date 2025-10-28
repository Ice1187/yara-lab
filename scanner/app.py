from flask import Flask, request, jsonify
import subprocess
import tempfile
from pathlib import Path
import json

app = Flask(__name__)

SAMPLES_DIR = Path("/samples").resolve()
BENIGN_DIR = SAMPLES_DIR / "benign"
RANDOM_DIR = SAMPLES_DIR / "random"


def scan_directory(rule_path: Path, directory: Path) -> dict:
    """
    Scan all files in a directory with a YARA rule.
    
    Args:
        rule_path: Path to the YARA rule file
        directory: Directory containing files to scan
    
    Returns:
        dict: Results with total files, matched count, and matched file names
    """
    # Get all files in directory to count total
    sample_files = list(directory.glob("*"))
    sample_files = [f for f in sample_files if f.is_file()]
    
    if not sample_files:
        return {
            "total_files": 0,
            "matched_files": 0,
            "matches": []
        }
    
    try:
        # Scan entire directory at once with JSON output
        result = subprocess.run(
            ["/usr/local/bin/yr", "scan", "-o", "json", str(rule_path), str(directory)],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Parse JSON output
        if result.stdout.strip():
            json_output = json.loads(result.stdout)
            matches = json_output.get("matches", [])
            
            # Extract unique matched file names
            matched_files = list(set([Path(m["file"]).name for m in matches]))
            
            return {
                "total_files": len(sample_files),
                "matched_files": len(matched_files),
                # "matches": matched_files
            }
        else:
            # No matches found
            return {
                "total_files": len(sample_files),
                "matched_files": 0,
                # "matches": []
            }
    
    except subprocess.TimeoutExpired:
        return {
            "total_files": len(sample_files),
            "matched_files": 0,
            # "matches": []
        }
    except Exception:
        return {
            "total_files": len(sample_files),
            "matched_files": 0,
            # "matches": []
        }


def scan_with_yara(rule_content: str, lab_id: str) -> dict:
    """
    Run YARA rule against lab-specific samples and benign files.
    
    Args:
        rule_content: YARA rule content
        lab_id: Lab identifier (e.g., 'lab1', 'lab2')
    
    Returns:
        dict: Detailed scan results for both lab and benign directories
    """
    lab_dir = SAMPLES_DIR / lab_id
    
    # Validate lab directory exists
    if not lab_dir.is_dir():
        return {
            "error": f"Lab directory '{lab_id}' not found"
        }
    
    # Create temporary rule file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yara', delete=False) as rule_file: # type: ignore
        rule_file.write(rule_content)
        rule_path = rule_file.name
    
    try:
        # Scan lab directory
        lab_results = scan_directory(rule_path, lab_dir)
        
        # Scan benign directory
        benign_results = scan_directory(rule_path, BENIGN_DIR)

        # Scan random directory
        random_results = scan_directory(rule_path, RANDOM_DIR)

        # Determine if submission passed (no benign matches)
        lab_passed = lab_results["matched_files"] == lab_results["total_files"]
        benign_passed = benign_results["matched_files"] == 0
        random_passed = random_results["matched_files"] == 0
        passed = lab_passed and benign_passed and random_passed

        return {
            "lab": lab_results,
            "benign": benign_results,
            "random": random_results,
            "passed": passed
        }
    
    finally:
        # Clean up temporary rule file
        if Path(rule_path).exists():
            Path(rule_path).unlink() # type: ignore


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy"})


@app.route("/scan", methods=["POST"])
def scan():
    """
    Scan endpoint that receives YARA rule and lab ID, runs against lab samples and benign files.
    
    Expected JSON body:
        {
            "rule": "<yara rule content>",
            "lab_id": "lab1"
        }
    """
    data = request.get_json()
    
    if not data or "rule" not in data:
        return jsonify({"error": "Missing 'rule' in request body"}), 400
    
    if "lab_id" not in data:
        return jsonify({"error": "Missing 'lab_id' in request body"}), 400
    
    rule_content = data["rule"]
    lab_id = data["lab_id"]
    
    try:
        result = scan_with_yara(rule_content, lab_id)
        
        # Check for errors in result
        if "error" in result:
            return jsonify(result), 404
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

