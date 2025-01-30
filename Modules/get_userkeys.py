import requests
from typing import Dict, List, Optional
from datetime import datetime
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_user_keys(pc_ip: str, username: str, password: str, ext_user_id: str) -> Optional[List[Dict]]:
    """
    Retrieve access keys for an existing user.
    
    Args:
        pc_ip: IP address of the PC instance
        username: Admin username for authentication
        password: Admin password for authentication
        ext_user_id: External ID of the user whose keys are being retrieved
        
    Returns:
        List of dictionaries containing key information if successful, None if failed
        Each dictionary contains:
            - name: Key name
            - access_key: Access key string
            - ext_id: External ID of the key
            - status: Key status (e.g., VALID)
            - created_time: Creation timestamp
            - expiry_time: Expiration timestamp
            - last_used_time: Last usage timestamp
            - key_type: Type of key (e.g., OBJECT_KEY)
            - description: Key description
    """
    
    url = f"https://{pc_ip}:9440/api/iam/v4.0/authn/users/{ext_user_id}/keys"
    
    try:
        response = requests.get(
            url=url,
            auth=(username, password),
            verify=False,
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        
        data = response.json()
        
        # Extract keys from the nested data structure
        keys_list = []
        if data.get('data'):
            for key in data['data']:
                key_info = {
                    'name': key.get('name'),
                    'access_key': key.get('keyDetails', {}).get('accessKey'),
                    'ext_id': key.get('extId'),
                    'status': key.get('status'),
                    'created_time': key.get('createdTime'),
                    'expiry_time': key.get('expiryTime'),
                    'last_used_time': key.get('lastUsedTime'),
                    'key_type': key.get('keyType'),
                    'description': key.get('description')
                }
                keys_list.append(key_info)
                
        return keys_list
        
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving access keys: {str(e)}")
        if hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return None

# Example usage:
"""
keys = get_user_keys(
    pc_ip="10.10.72.110",
    username="admin",
    password="password",
    ext_user_id="206ad009-5b09-5ec5-8713-14cfc2f0948b"
)

if keys:
    for key in keys:
        print(f"Key Name: {key['name']}")
        print(f"Access Key: {key['access_key']}")
        print(f"External ID: {key['ext_id']}")
        print(f"Status: {key['status']}")
        print(f"Created: {key['created_time']}")
        print(f"Expires: {key['expiry_time']}")
        print(f"Last Used: {key['last_used_time']}")
        print(f"Key Type: {key['key_type']}")
        print(f"Description: {key['description']}")
        print("---")
"""