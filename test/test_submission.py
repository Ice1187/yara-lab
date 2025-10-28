#!/usr/bin/env python3
"""
Simple test script for the YARA Rule Lecture Platform.
Usage: python test_submission.py <rule_file.yar> [lab_id]
"""

import sys
import requests

API_URL = "http://localhost:9000"


def test_health():
    """Test the health endpoint."""
    response = requests.get(f"{API_URL}/health")
    print(f"Health check: {response.status_code}")
    print(f"Response: {response.json()}\n")
    return response.status_code == 200


def list_labs():
    """List available labs."""
    print("=" * 50)
    print("Available Labs")
    print("=" * 50)
    response = requests.get(f"{API_URL}/labs")
    print(f"Status code: {response.status_code}")
    if response.status_code == 200:
        labs_data = response.json()
        print(f"Labs: {', '.join(labs_data['labs'])}")
        print(f"Total: {labs_data['count']}\n")
        return labs_data['labs']
    return []


def submit_rule(rule_file, lab_id):
    """Submit a YARA rule file for a specific lab."""
    print(f"Submitting rule: {rule_file}")
    print(f"Target lab: {lab_id}\n")
    
    try:
        with open(rule_file, 'rb') as f:
            files = {'file': f}
            response = requests.post(f"{API_URL}/submit/{lab_id}", files=files)
        
        print(f"Status code: {response.status_code}")
        result = response.json()
        print(f"Response: {result}\n")
        
        if response.status_code == 200:
            if 'result' in result:
                lab_result = result['result']['lab']
                benign_result = result['result']['benign']
                random_result = result['result']['random']
                passed = result['result']['passed']
                
                print("Lab Results:")
                print(f"  Lab: {result['lab_id']}")
                print(f"  Total files: {lab_result['total_files']}")
                print(f"  Matched files: {lab_result['matched_files']}")
                print(f"  Matches: {', '.join(lab_result['matches']) if lab_result['matches'] else 'None'}")
                
                print("\nBenign Results:")
                print(f"  Total files: {benign_result['total_files']}")
                print(f"  Matched files: {benign_result['matched_files']}")
                print(f"  Matches: {', '.join(benign_result['matches']) if benign_result['matches'] else 'None'}")

                print("\nRandom Results:")
                print(f"  Total files: {random_result['total_files']}")
                print(f"  Matched files: {random_result['matched_files']}")
                print(f"  Matches: {', '.join(random_result['matches']) if random_result['matches'] else 'None'}")
                
                print(f"\nPassed: {'✓ YES' if passed else '✗ NO (false positives detected)'}")
        
        return response.status_code == 200
    
    except FileNotFoundError:
        print(f"Error: File '{rule_file}' not found")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python test_submission.py <rule_file.yar> [lab_id]")
        print("If lab_id is not provided, 'lab1' will be used by default")
        sys.exit(1)
    
    rule_file = sys.argv[1]
    lab_id = sys.argv[2] if len(sys.argv) == 3 else "lab1"
    
    # Test health endpoint
    print("=" * 50)
    print("Testing Health Endpoint")
    print("=" * 50)
    if not test_health():
        print("Health check failed! Is the server running?")
        sys.exit(1)
    
    # List available labs
    list_labs()
    
    # Submit rule
    print("=" * 50)
    print("Testing Rule Submission")
    print("=" * 50)
    if submit_rule(rule_file, lab_id):
        print("\n✓ Submission successful!")
    else:
        print("\n✗ Submission failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()

