import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json
from typing import Dict, Optional

def get_cluster_list(pc_ip: str, username: str, password: str, verify_ssl: bool = False) -> Optional[Dict]:
    """
    Get list of clusters registered to Prism Central.
    
    Args:
        pc_ip (str): Prism Central IP address
        username (str): Username for authentication
        password (str): Password for authentication
        verify_ssl (bool): Whether to verify SSL certificate (default: False)
    
    Returns:
        dict: Cluster list response if successful, None if failed
    """
    
    # Disable SSL warnings if verify_ssl is False
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Construct the API URL
    url = f"https://{pc_ip}:9440/api/nutanix/v3/clusters/list"
    
    # Prepare the payload
    payload = {
        "kind": "cluster",
        "sort_attribute": "name",  # Default sort by name
        "length": 500,            # High number to get all clusters
        "sort_order": "ASCENDING",
        "offset": 0
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
        print(f"Error fetching cluster list: {str(e)}")
        return None

# Example of how the main calling script would use this:
"""
from get_cluster_list import get_cluster_list

def fetch_clusters():
    pc_ip = "10.10.72.110"
    username = "admin"
    password = "your_password"
    
    cluster_list = get_cluster_list(pc_ip, username, password)
    
    if cluster_list:
        print("Successfully retrieved cluster list")
        # Process the cluster list as needed
        clusters = cluster_list.get('entities', [])
        for cluster in clusters:
            name = cluster.get('spec', {}).get('name', 'Unknown')
            uuid = cluster.get('metadata', {}).get('uuid', 'Unknown')
            print(f"Cluster Name: {name}, UUID: {uuid}")
        return cluster_list
    else:
        print("Failed to retrieve cluster list")
        return None
"""
