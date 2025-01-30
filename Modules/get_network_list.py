import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json
from typing import Dict, Optional

def get_network_list(pe_ip: str, username: str, password: str, verify_ssl: bool = False) -> Optional[Dict]:
    """
    Get network list from Prism Element.
    
    Args:
        pe_ip (str): Prism Element IP address
        username (str): Username for authentication
        password (str): Password for authentication
        verify_ssl (bool): Whether to verify SSL certificate (default: False)
    
    Returns:
        dict: Network list response if successful, None if failed
    """
    
    # Disable SSL warnings if verify_ssl is False
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Construct the API URL
    url = f"https://{pe_ip}:9440/PrismGateway/services/rest/v2.0/networks/"
    
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
        print(f"Error fetching network list: {str(e)}")
        return None

# Example of how the main calling script would use this:
"""
from get_network_list import get_network_list

def fetch_networks():
    pe_ip = "10.10.72.208"
    username = "admin"
    password = "your_password"
    
    network_list = get_network_list(pe_ip, username, password)
    
    if network_list:
        print("Successfully retrieved network list")
        return network_list
    else:
        print("Failed to retrieve network list")
        return None
"""
