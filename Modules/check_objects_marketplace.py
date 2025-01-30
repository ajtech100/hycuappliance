import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json
from typing import Dict, Optional

def check_objects_marketplace(pc_ip: str, username: str, password: str, verify_ssl: bool = False) -> Optional[Dict]:
    """
    Check if Objects app is available in Nutanix Marketplace.
    
    Args:
        pc_ip (str): Prism Central IP address
        username (str): Username for authentication
        password (str): Password for authentication
        verify_ssl (bool): Whether to verify SSL certificate (default: False)
    
    Returns:
        dict: Marketplace app status response if successful, None if failed
    """
    
    # Disable SSL warnings if verify_ssl is False
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Construct the API URL
    url = f"https://{pc_ip}:9440/api/nutanix/v3/calm_marketplace_items/apps/list"
    
    # Prepare the payload
    payload = {
        "length": 1,
        "offset": 0,
        "filter": "source_marketplace_name==Objects"
    }
    
    try:
        # Make API request
        response = requests.post(
            url=url,
            auth=HTTPBasicAuth(username, password),
            verify=verify_ssl,
            headers={'Content-Type': 'application/json'},
            data=json.dumps(payload),
            timeout=30
        )
        
        # Check if request was successful
        response.raise_for_status()
        
        # Return JSON response
        return response.json()
    
    except requests.exceptions.RequestException as e:
        print(f"Error checking Objects in marketplace: {str(e)}")
        return None

# Example of how the main calling script would use this:
"""
from check_objects_marketplace import check_objects_marketplace

def check_objects_app():
    pc_ip = "10.10.72.110"
    username = "admin"
    password = "your_password"
    
    marketplace_status = check_objects_marketplace(pc_ip, username, password)
    
    if marketplace_status:
        # Check if Objects app exists in marketplace
        entities = marketplace_status.get('entities', [])
        if entities:
            app_status = entities[0].get('status', {})
            app_name = app_status.get('name', 'Unknown')
            app_state = app_status.get('state', 'Unknown')
            print(f"Objects App Name: {app_name}")
            print(f"Objects App State: {app_state}")
        else:
            print("Objects app not found in marketplace")
        return marketplace_status
    else:
        print("Failed to check Objects app status")
        return None
"""
