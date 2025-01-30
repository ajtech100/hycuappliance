import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json
from typing import Dict, Optional

def get_lcm_configs(pc_ip: str, username: str, password: str, verify_ssl: bool = False) -> Optional[Dict]:
    """
    Fetch LCM configurations from Nutanix Prism Central.
    
    Args:
        pc_ip (str): Prism Central IP address
        username (str): Username for authentication
        password (str): Password for authentication
        verify_ssl (bool): Whether to verify SSL certificate (default: False)
    
    Returns:
        dict: LCM configuration response if successful, None if failed
    """
    
    # Disable SSL warnings if verify_ssl is False
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Construct the API URL
    url = f"https://{pc_ip}:9440/api/lcm/v4.0.a1/resources/config"
    
    try:
        # Make API request
        response = requests.get(
            url=url,
            auth=HTTPBasicAuth(username, password),
            verify=verify_ssl,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        # Check if request was successful
        response.raise_for_status()
        
        # Return JSON response
        return response.json()
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching LCM configs: {str(e)}")
        return None

# Example of how the main calling script would use this:
"""
from lcm_config import get_lcm_configs

def main():
    pc_ip = "10.10.72.110"
    username = "admin"
    password = "password"
    
    lcm_configs = get_lcm_configs(pc_ip, username, password)
    if lcm_configs:
        # Process the configurations
        print(json.dumps(lcm_configs, indent=2))
    else:
        print("Failed to retrieve LCM configurations")

if __name__ == "__main__":
    main()
"""
