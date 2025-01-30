import requests
from typing import List, Optional, Tuple
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_storage_containers(pe_ip: str, username: str, password: str) -> Optional[List[Tuple[str, str]]]:
    """
    Get list of storage containers from Prism Element.
    Returns list of tuples containing (container_name, container_uuid).
    """
    
    url = f"https://{pe_ip}:9440/api/nutanix/v2.0/storage_containers"
    
    try:
        response = requests.get(
            url=url,
            auth=(username, password),
            verify=False,
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        
        data = response.json()
        containers = []
        
        for entity in data.get('entities', []):
            name = entity.get('name')
            uuid = entity.get('storage_container_uuid')
            if name and uuid:
                containers.append((name, uuid))
                
        return containers
        
    except requests.exceptions.RequestException as e:
        print(f"Error getting storage containers: {str(e)}")
        if hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return None

# Example usage:
"""
containers = get_storage_containers(
    pe_ip="10.10.10.10",
    username="admin",
    password="password"
)

if containers:
    for name, uuid in containers:
        print(f"Container: {name}, UUID: {uuid}")
"""