import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json
from typing import Dict, Optional

def enable_pc_marketplace(pc_ip: str, username: str, password: str, verify_ssl: bool = False) -> Optional[Dict]:
    """
    Enable Prism Central Marketplace (Calm) service.
    
    Args:
        pc_ip (str): Prism Central IP address
        username (str): Username for authentication
        password (str): Password for authentication
        verify_ssl (bool): Whether to verify SSL certificate (default: False)
    
    Returns:
        dict: API response if successful, None if failed
    """
    
    # Disable SSL warnings if verify_ssl is False
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Construct the API URL
    url = f"https://{pc_ip}:9440/api/nutanix/v3/services/nucalm"
    
    # Prepare the payload
    payload = {
        "perform_validation_only": False,
        "enable_lite": True,
        "enable_nutanix_apps": True
    }
    
    # Prepare headers
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    try:
        # Make API request
        response = requests.post(
            url=url,
            auth=HTTPBasicAuth(username, password),
            verify=verify_ssl,
            headers=headers,
            data=json.dumps(payload),
            timeout=30
        )
        
        # Check if request was successful
        response.raise_for_status()
        
        # Return JSON response if available, else return raw response
        try:
            return response.json()
        except json.JSONDecodeError:
            return {"status_code": response.status_code, "text": response.text}
    
    except requests.exceptions.RequestException as e:
        print(f"Error enabling PC Marketplace: {str(e)}")
        return None

# Example of how the main calling script would use this:
"""
from enable_marketplace import enable_pc_marketplace

def enable_marketplace():
    pc_ip = "10.10.72.110"
    username = "admin"
    password = "your_password"
    
    response = enable_pc_marketplace(pc_ip, username, password)
    
    if response:
        print("Successfully initiated Marketplace enablement:")
        print(json.dumps(response, indent=2))
        return response
    else:
        print("Failed to enable Marketplace")
        return None
"""
