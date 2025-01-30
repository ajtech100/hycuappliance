import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json
from typing import Dict, Optional

def get_cluster_details(pe_ip: str, username: str, password: str, verify_ssl: bool = False) -> Optional[Dict]:
    """
    Get cluster details from Prism Element.
    
    Args:
        pe_ip (str): Prism Element IP address
        username (str): Username for authentication
        password (str): Password for authentication
        verify_ssl (bool): Whether to verify SSL certificate (default: False)
    
    Returns:
        dict: Cluster details response if successful, None if failed
    """
    
    # Disable SSL warnings if verify_ssl is False
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Construct the API URL
    url = f"https://{pe_ip}:9440/PrismGateway/services/rest/v2.0/cluster/"
    
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
        print(f"Error fetching cluster details: {str(e)}")
        return None

# Example of how the main calling script would use this:
"""
from get_cluster_details import get_cluster_details

def fetch_cluster_info():
    pe_ip = "10.10.72.208"
    username = "admin"
    password = "your_password"
    
    cluster_info = get_cluster_details(pe_ip, username, password)
    
    if cluster_info:
        print("Successfully retrieved cluster details")
        # Process cluster details as needed
        cluster_name = cluster_info.get('name', 'Unknown')
        cluster_id = cluster_info.get('id', 'Unknown')
        cluster_version = cluster_info.get('version', 'Unknown')
        print(f"Cluster Name: {cluster_name}")
        print(f"Cluster ID: {cluster_id}")
        print(f"Cluster Version: {cluster_version}")
        return cluster_info
    else:
        print("Failed to retrieve cluster details")
        return None
"""
