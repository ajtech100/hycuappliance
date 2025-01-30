import requests
from typing import Dict, Optional
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_bucket(pc_ip: str, username: str, password: str, objectstore_uuid: str, bucket_name: str) -> Optional[Dict]:
    """Create a bucket in the specified object store."""
    
    url = f"https://{pc_ip}:9440/oss/api/nutanix/v3/objectstore_proxy/{objectstore_uuid}/buckets"
    
    payload = {
        "api_version": "3.0",
        "metadata": {
            "kind": "bucket"
        },
        "spec": {
            "name": bucket_name,
            "description": "",
            "resources": {
                "features": []
            }
        }
    }
    
    try:
        response = requests.post(
            url=url,
            auth=(username, password),
            verify=False,
            headers={'Content-Type': 'application/json'},
            json=payload
        )
        response.raise_for_status()
        return response.json()
        
    except requests.exceptions.RequestException as e:
        print(f"Error creating bucket: {str(e)}")
        if hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return None

# Example usage:
"""
result = create_bucket(
    pc_ip="10.10.10.10",
    username="admin",
    password="password",
    objectstore_uuid="uuid-here",
    bucket_name="my-bucket"
)
if result:
    print("Bucket created successfully")
"""