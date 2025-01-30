import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json
from typing import Dict, Optional
from time import sleep
from prettytable import PrettyTable

def get_objectstore_status(pc_ip: str, username: str, password: str, objectstore_uuid: str, verify_ssl: bool = False) -> Optional[Dict]:
    """
    Get Object Store deployment status and details.
    
    Args:
        pc_ip (str): Prism Central IP address
        username (str): Username for authentication
        password (str): Password for authentication
        objectstore_uuid (str): UUID of the Object Store
        verify_ssl (bool): Whether to verify SSL certificate (default: False)
    
    Returns:
        dict: Object Store status response if successful, None if failed
    """
    
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def get_new_token() -> Optional[str]:
        """Get new token for Object Store inspection"""
        url = f"https://{pc_ip}:9440/oss/api/nutanix/v3/objectstores/{objectstore_uuid}?get_new_token=true"
        try:
            response = requests.get(
                url=url,
                auth=HTTPBasicAuth(username, password),
                verify=verify_ssl,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            response.raise_for_status()
            return response.json().get('token')
        except requests.exceptions.RequestException as e:
            print(f"Error getting token: {str(e)}")
            return None

    def get_deployment_progress() -> Optional[int]:
        """Get Object Store deployment progress"""
        url = f"https://{pc_ip}:9440/PrismGateway/services/rest/v1/progress_monitors"
        try:
            response = requests.get(
                url=url,
                auth=HTTPBasicAuth(username, password),
                verify=verify_ssl,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            response.raise_for_status()
            tasks = response.json()
            for task in tasks.get('entities', []):
                if task.get('operation') == 'create_object_store':
                    return task.get('percentageCompleted', 0)
            return None
        except requests.exceptions.RequestException as e:
            print(f"Error getting progress: {str(e)}")
            return None

    def get_status(token: str) -> Optional[Dict]:
        """Get detailed Object Store status"""
        url = f"https://{pc_ip}:9440/oss/api/nutanix/v3/objectstores/inspector/{objectstore_uuid}?token={token}"
        try:
            response = requests.post(
                url=url,
                auth=HTTPBasicAuth(username, password),
                verify=verify_ssl,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error getting status: {str(e)}")
            return None

    def print_status_table(status_data: Dict):
        """Print status information in table format"""
        table = PrettyTable()
        table.field_names = ["Component", "Status"]
        for plugin in status_data.get('plugins_status', []):
            name = plugin.get('name', '')
            status = plugin.get('status', '')
            table.add_row([name, status])
        print(table)

    # Main execution flow
    token = get_new_token()
    if not token:
        return None

    status_data = get_status(token)
    if not status_data:
        return None

    # Print current status table
    print("\nObject Store Deployment Status:")
    print_status_table(status_data)
    
    # Print deployment progress
    progress = get_deployment_progress()
    if progress is not None:
        print(f"\nOverall Deployment Progress: {progress}%")

    return status_data

# Example usage:
"""
from get_objectstore_status import get_objectstore_status

def check_objectstore_status():
    pc_ip = "10.10.72.210"
    username = "admin"
    password = "password"
    objectstore_uuid = "986926b6-232a-40a9-435a-3e89a4a185d2"
    
    status = get_objectstore_status(pc_ip, username, password, objectstore_uuid)
    if status:
        print("Successfully retrieved Object Store status")
        return status
    else:
        print("Failed to get Object Store status")
        return None
"""
