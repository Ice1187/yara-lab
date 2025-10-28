# YARA Rule Lecture Platform

A simple platform for teaching and testing YARA rules. Students can submit YARA rule files for different labs, which are validated and executed against lab-specific malware samples plus a shared benign dataset in an isolated environment.

## Features

- **Multiple Labs**: Support for multiple independent lab exercises
- **False Positive Detection**: All submissions automatically scanned against benign files
- **Detailed Results**: See exactly which files matched your YARA rules
- **Isolated Execution**: Scanner runs with no internet access

## Architecture

- **FastAPI Service**: Receives YARA rule submissions, validates syntax, forwards to scanner
- **Scanner Service**: Isolated service with yara-x that scans sample files
- **Lab Structure**: Each lab has its own sample directory; shared benign dataset for all labs
- **Docker Networks**: 
  - `yara-internal`: Internal-only network for API ↔ Scanner communication (no internet)
  - `default`: Bridge network for FastAPI to access the internet
- **Security**: Scanner truly isolated with no route to internet, minimal Linux capabilities

## Prerequisites

- Docker
- Docker Compose

## Quick Start

1. **Start the platform:**
   ```bash
   cd /home/ice1187/ntnu-lecture/yara
   docker compose up --build
   ```

2. **The API will be available at:** `http://localhost:9000`

3. **List available labs:**
   ```bash
   curl http://localhost:9000/labs
   ```

4. **Submit a YARA rule:**
   ```bash
   curl -X POST -F "file=@your_rule.yar" http://localhost:9000/submit/lab1
   ```

## API Endpoints

### `GET /health`
Health check endpoint.

**Response:**
```json
{
  "status": "healthy"
}
```

### `GET /labs`
List all available labs.

**Response:**
```json
{
  "labs": ["lab1", "lab2"],
  "count": 2
}
```

### `POST /submit/{lab_id}`
Submit a YARA rule file for validation and scanning against a specific lab.

**Parameters:**
- `lab_id`: Lab identifier (e.g., "lab1", "lab2")

**Request:**
- Method: `POST`
- Content-Type: `multipart/form-data`
- Body: File upload with key `file`

**Response (Success):**
```json
{
  "status": "success",
  "lab_id": "lab1",
  "result": {
    "lab": {
      "total_files": 1,
      "matched_files": 1,
    },
    "benign": {
      "total_files": 3,
      "matched_files": 0,
    },
    "passed": true
  }
}
```

**Response (Invalid Rule):**
```json
{
  "detail": "Invalid YARA rule format. Must contain 'rule <name> { ... }'"
}
```

**Response (Invalid Lab):**
```json
{
  "detail": "Lab 'lab99' not found. Available labs: lab1, lab2"
}
```

## Example Usage

### List available labs:
```bash
curl http://localhost:9000/labs
```

### Create a test YARA rule:
```yara
rule lab1_test {
    meta:
        description = "Test rule for Lab 1"
    strings:
        $mz = "MZ"
        $pe = "PE"
    condition:
        $mz at 0 and $pe
}
```

### Submit via curl:
```bash
# Submit to lab1
curl -X POST -F "file=@test_rule.yar" http://localhost:9000/submit/lab1

# Submit to lab2
curl -X POST -F "file=@test_rule.yar" http://localhost:9000/submit/lab2
```

### Submit via Python:
```python
import requests

lab_id = "lab1"
with open('test_rule.yar', 'rb') as f:
    response = requests.post(
        f'http://localhost:9000/submit/{lab_id}',
        files={'file': f}
    )
    result = response.json()
    print(f"Lab matches: {result['lab_id']}")
    print(f"Benign matches: {result['result']['benign']['matched_files']}")
    print(f"Passed: {result['result']['passed']}")
```

## Scaling Scanner Services

To run multiple scanner instances:
```bash
docker compose up --scale scanner=3
```

**Note:** For production use with multiple scanners, you'll need to implement load balancing.

## Sample Files

Sample files are organized by lab in the `./sample/` directory. These are mounted read-only into the scanner container.

### Directory Structure:
```
sample/
├── lab1/
│   └── lab1.exe
├── lab2/
│   └── lab2.exe
└── benign/
    ├── benign.dll
    ├── benign.exe
    ├── config.json
    └── script.sh
```

### Adding New Labs:
1. Create a new directory under `sample/` (e.g., `sample/lab3/`)
2. Add malware samples to the new directory
3. Update `AVAILABLE_LABS` in `api/main.py` to include the new lab ID

## Development

### Rebuild containers:
```bash
docker compose up --build
```

### View logs:
```bash
docker compose logs -f
```

### Test network isolation:
```bash
./test/test_network_isolation.sh
```

This verifies:
- ✓ API container can access the internet
- ✓ Scanner container cannot access the internet
- ✓ API can communicate with scanner

### Stop services:
```bash
docker compose down
```

## Security Notes

- **Network Isolation**: Scanner service connected ONLY to internal network (no internet route)
- **FastAPI Access**: API service connected to both internal network and default bridge (can access internet)
- **Capabilities**: Scanner runs with minimal Linux capabilities (ALL dropped, only essential added)
- **No Privilege Escalation**: `no-new-privileges` security option enabled
- **Read-Only Samples**: Sample files are mounted read-only
- **Cleanup**: Temporary rule files are cleaned up after scanning

## Troubleshooting

**Scanner service unavailable:**
- Check if scanner container is running: `docker compose ps`
- Check scanner logs: `docker compose logs scanner`

**No sample files found:**
- Verify files exist in `./sample/` directory
- Check volume mount in docker-compose.yml

**YARA rule validation fails:**
- Ensure rule contains `rule <name> { ... }` structure
- Check for syntax errors in the rule

**Network isolation concerns:**
- Run `test/test_network_isolation.sh` to verify isolation is working
- Scanner should NOT be able to ping external hosts
- API should be able to access internet and communicate with scanner

**Permission errors in scanner:**
- The scanner runs with minimal capabilities
- If you encounter permission issues, check the `cap_add` section in docker-compose.yml
