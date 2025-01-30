import requests
from typing import Dict, Optional, List
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def list_users(pc_ip: str, username: str, password: str) -> Optional[List[Dict]]:
    """List all users in Prism Central."""
    
    url = f"https://{pc_ip}:9440/api/iam/v4.0/authn/users"
    
    try:
        response = requests.get(
            url=url,
            auth=(username, password),
            verify=False,
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        
        result = []
        for user in response.json()['data']:
            user_info = {
                'display_name': user['displayName'],
                'username': user['username'],
                'user_type': user['userType'],
                'status': user['status'],
                'ext_id': user['extId']
            }
            result.append(user_info)
            
        return result
        
    except requests.exceptions.RequestException as e:
        print(f"Error listing users: {str(e)}")
        if hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return None

# Example usage:
"""
users = list_users(
    pc_ip="10.10.72.110",
    username="admin",
    password="password"
)
if users:
    print(f"{'Display Name':<20} {'Username':<30} {'Type':<15} {'Status':<10} {'UUID'}")
    print("-" * 90)
    for user in users:
        print(f"{user['display_name']:<20} {user['username']:<30} {user['user_type']:<15} "
              f"{user['status']:<10} {user['ext_id']}")
"""