import requests
from typing import List, Optional, Tuple
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_images(pe_ip: str, username: str, password: str) -> Optional[List[Tuple[str, str, str]]]:
    """Get list of images from Prism Element."""
    
    url = f"https://{pe_ip}:9440/api/nutanix/v2.0/images/"
    
    try:
        response = requests.get(
            url=url,
            auth=(username, password),
            verify=False,
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        
        data = response.json()
        images = []
        
        for entity in data.get('entities', []):
            name = entity.get('name')
            uuid = entity.get('uuid')
            vm_disk_id = entity.get('vm_disk_id')
            if name and uuid and vm_disk_id:
                images.append((name, uuid, vm_disk_id))
                
        return images
        
    except requests.exceptions.RequestException as e:
        print(f"Error getting images: {str(e)}")
        if hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return None

# Example usage:
"""
images = get_images(
    pe_ip="10.10.10.10",
    username="admin",
    password="password"
)

if images:
    for name, uuid, vm_disk_id in images:
        print(f"Image: {name}, UUID: {uuid}, VM Disk ID: {vm_disk_id}")
"""