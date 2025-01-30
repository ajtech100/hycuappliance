import requests
from typing import Optional
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def share_bucket(pc_ip: str, username: str, password: str, objectstore_uuid: str, 
                bucket_name: str, user_email: str) -> bool:
    """Share a bucket with a user."""
    
    url = f"https://{pc_ip}:9440/oss/api/nutanix/v3/objectstore_proxy/{objectstore_uuid}/buckets/{bucket_name}/policy"
    
    payload = {
        "Statement": [{
            "Action": "s3:*",
            "Effect": "Allow",
            "Principal": {
                "AWS": [user_email]
            },
            "Resource": f"arn:aws:s3:::{bucket_name}",
            "Sid": ""
        }],
        "Version": "2.0"
    }
    
    try:
        response = requests.put(
            url=url,
            auth=(username, password),
            verify=False,
            headers={'Content-Type': 'application/json'},
            json=payload
        )
        response.raise_for_status()
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"Error sharing bucket: {str(e)}")
        if hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return False

# Example usage:
"""
success = share_bucket(
    pc_ip="10.10.10.10",
    username="admin",
    password="password",
    objectstore_uuid="uuid-here",
    bucket_name="my-bucket",
    user_email="user@example.com"
)

if success:
    print("Bucket shared successfully")
else:
    print("Failed to share bucket")
"""