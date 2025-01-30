import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json
from typing import Dict, Optional

def update_lcm_config(pc_ip: str, username: str, password: str, etag: str, 
                     darksite_url: str, verify_ssl: bool = False) -> Optional[Dict]:
    """
    Update LCM configuration in Nutanix Prism Central.
    
    Args:
        pc_ip (str): Prism Central IP address
        username (str): Username for authentication
        password (str): Password for authentication
        etag (str): ETag value for configuration versioning
        darksite_url (str): Darksite webserver URL
        verify_ssl (bool): Whether to verify SSL certificate (default: False)
    
    Returns:
        dict: API response if successful, None if failed
    """
    
    # Disable SSL warnings if verify_ssl is False
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Construct the API URL
    url = f"https://{pc_ip}:9440/api/lcm/v4.0.a1/resources/config"
    
    # Prepare the payload
    payload = {
        "url": darksite_url,
        "autoInventoryEnabled": False,
        "autoInventoryScheduledTime": "03:00",
        "isDarksite": True,
        "enableHttps": False,
        "uploadedBundle": False,
        "moduleAutoUpgradeEnabled": False,
        "$reserved": {
            "ETag": etag,
            "lcm_api_ver": "v4.0.a1"
        },
        "$objectType": "lcm.v4.resources.LcmConfig",
        "$unknownFields": {}
    }
    
    # Prepare headers
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'If-Match': etag
    }
    
    try:
        # Make API request
        response = requests.put(
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
        print(f"Error updating LCM config: {str(e)}")
        return None

# Example of how the main calling script would use this:
"""
from lcm_config_update import update_lcm_config

def main():
    # Parameters to be passed from main script
    pc_ip = "10.10.72.11"
    username = "admin"
    password = "your_password"
    etag = "1327f5abe00f4c4b4b1b725f0fb60e6ec7ef5423e1d8515a0113156b510ef706"
    darksite_url = "http://10.10.74.161/release/"
    
    # Update LCM config
    response = update_lcm_config(pc_ip, username, password, etag, darksite_url)
    
    if response:
        print("Successfully updated LCM configuration:")
        print(json.dumps(response, indent=2))
    else:
        print("Failed to update LCM configuration")

if __name__ == "__main__":
    main()
"""
