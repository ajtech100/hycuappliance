import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json
from typing import Dict, Optional

def get_task_status(cluster_ip: str, username: str, password: str, task_uuid: str, verify_ssl: bool = False) -> Optional[Dict]:
    """
    Get task status from Nutanix cluster using task UUID.
    
    Args:
        cluster_ip (str): Cluster/PC IP address
        username (str): Username for authentication
        password (str): Password for authentication
        task_uuid (str): UUID of the task to check
        verify_ssl (bool): Whether to verify SSL certificate (default: False)
    
    Returns:
        dict: Task status response if successful, None if failed
    """
    
    # Disable SSL warnings if verify_ssl is False
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Construct the API URL
    url = f"https://{cluster_ip}:9440/api/nutanix/v3/tasks/{task_uuid}"
    
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
        print(f"Error fetching task status: {str(e)}")
        return None

# Example of how the main calling script would use this:
"""
from task_status import get_task_status

def check_task_progress():
    cluster_ip = "10.10.72.11"
    username = "admin"
    password = "your_password"
    task_uuid = "00000000-0000-0000-0000-000000000000"
    
    task_status = get_task_status(cluster_ip, username, password, task_uuid)
    
    if task_status:
        print("Task Status:")
        print(json.dumps(task_status, indent=2))
        return task_status
    else:
        print("Failed to get task status")
        return None
"""
