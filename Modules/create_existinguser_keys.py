import requests
from typing import Dict, Optional
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_user_keys(pc_ip: str, username: str, password: str, ext_user_id: str) -> Optional[Dict]:
    """
    Create new access keys for an existing user.
    
    Args:
        pc_ip: IP address of the PC instance
        username: Admin username for authentication
        password: Admin password for authentication
        ext_user_id: External ID of the user for whom to create keys
        
    Returns:
        Dictionary containing the new key information if successful, None if failed
        The dictionary contains:
            - access_key_id: The access key ID
            - secret_access_key: The secret access key
            - access_key_name: Name of the access key
            - created_time: Creation timestamp
            - user_id: ID of the user the key belongs to
    """
    
    url = f"https://{pc_ip}:9440/oss/iam_proxy/users/{ext_user_id}/buckets_access_keys"
    
    try:
        response = requests.post(
            url=url,
            auth=(username, password),
            verify=False,
            headers={'Content-Type': 'application/json'},
            json={}  # Empty payload as we're creating keys for existing user
        )
        response.raise_for_status()
        
        # Return the response directly as it matches our desired structure
        return response.json()
        
    except requests.exceptions.RequestException as e:
        print(f"Error creating access keys: {str(e)}")
        if hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return None

# Example usage:
"""
new_keys = create_user_keys(
    pc_ip="10.10.72.110",
    username="admin",
    password="password",
    ext_user_id="206ad009-5b09-5ec5-8713-14cfc2f0948b"
)

if new_keys:
    print(f"Access Key ID: {new_keys['access_key_id']}")
    print(f"Secret Access Key: {new_keys['secret_access_key']}")
    print(f"Key Name: {new_keys['access_key_name']}")
    print(f"Created Time: {new_keys['created_time']}")
    print(f"User ID: {new_keys['user_id']}")
"""