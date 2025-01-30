import requests
from typing import Dict, Optional, Tuple
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_access_keys(pc_ip: str, username: str, password: str, user_email: str, display_name: str) -> Optional[Tuple[str, str, str, str]]:
    """
    Create access keys for a user.
    Returns tuple of (access_key_id, secret_access_key, display_name, username) if successful.
    """
    
    url = f"https://{pc_ip}:9440/oss/iam_proxy/buckets_access_keys"
    
    payload = {
        "users": [{
            "type": "external",
            "username": user_email,
            "display_name": display_name
        }]
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
        
        data = response.json()
        user = data['users'][0]
        access_key = user['buckets_access_keys'][0]
        
        return (
            access_key['access_key_id'],
            access_key['secret_access_key'],
            user['display_name'],
            user['username']
        )
        
    except requests.exceptions.RequestException as e:
        print(f"Error creating access keys: {str(e)}")
        if hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return None

# Example usage:
"""
result = create_access_keys(
    pc_ip="10.10.10.10",
    username="admin",
    password="password",
    user_email="user@example.com",
    display_name="Test User"
)

if result:
    access_key_id, secret_key, display_name, username = result
    print(f"Access Key ID: {access_key_id}")
    print(f"Secret Key: {secret_key}")
    print(f"Display Name: {display_name}")
    print(f"Username: {username}")
"""