import requests
from typing import Dict, Optional
import urllib3
import time

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_job_status(hycu_ip: str, username: str, password: str, job_id: str) -> Optional[Dict]:
    """Get status of a HYCU job."""
    url = f"https://{hycu_ip}:8443/rest/v1.0/jobs/{job_id}"
    
    try:
        response = requests.get(
            url=url,
            auth=(username, password),
            verify=False,
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        job_info = response.json()
        entity = job_info['entities'][0]
        
        status_info = {
            'status': entity['status'],
            'completion': entity['completitionPct'] * 100
        }
        
        # Add error details if available
        if entity.get('taskExitMessage'):
            status_info['error_message'] = entity['taskExitMessage'].get('debug', '')
            
        return status_info
        
    except requests.exceptions.RequestException as e:
        print(f"Error getting job status: {str(e)}")
        return None

def add_hycu_target(
    hycu_ip: str,
    username: str,
    password: str,
    target_name: str,
    service_endpoint: str,
    bucket_name: str,
    access_key: str,
    secret_key: str,
    backup_streams: str,
    capacity_bytes: int,
    compression: bool
) -> Optional[Dict]:
    """Add a Nutanix Objects target to HYCU controller and monitor job status."""
    
    url = f"https://{hycu_ip}:8443/rest/v1.0/targets"
    
    payload = {
        "name": target_name,
        "description": "",
        "targetType": "NUTANIX_OBJECTS",
        "allowedBackupStreams": backup_streams,
        "advertisedCapacityInBytes": capacity_bytes,
        "archive": False,
        "compression": compression,
        "encryption": False,
        "metered": False,
        "nutanixObjectsStorageDetails": {
            "serviceEndPoint": service_endpoint,
            "bucketName": bucket_name,
            "accessKeyId": access_key,
            "secretAccessKey": secret_key,
            "pathStyleAccess": True
        }
    }
    
    try:
        response = requests.post(
            url=url,
            auth=(username, password),
            verify=False,
            headers={'Content-Type': 'application/json'},
            json=payload
        )
        response.raise_for_status()
        result = response.json()
        
        if result.get('entities') and result['entities'][0].get('jobUuid'):
            job_id = result['entities'][0]['jobUuid']
            print(f"Target add job in progress. Job ID: {job_id}")
            
            # Monitor job status
            while True:
                status = get_job_status(hycu_ip, username, password, job_id)
                if status:
                    print(f"Status: {status['status']}, Completion: {status['completion']}%")
                    
                    if status['status'] == 'OK':
                        return status
                    elif status['status'] == 'ERROR':
                        if status.get('error_message'):
                            print(f"Error details: {status['error_message']}")
                        return status
                        
                time.sleep(5)  # Wait 5 seconds before checking again
                
        return None
        
    except requests.exceptions.RequestException as e:
        print(f"Error adding HYCU target: {str(e)}")
        if hasattr(e, 'response') and hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return None

# Example usage:
"""
result = add_hycu_target(
    hycu_ip="10.10.74.118",
    username="admin",
    password="admin",
    target_name="NUS",
    service_endpoint="http://HycuAuto.prism-central.cluster.local",
    bucket_name="test",
    access_key="your-access-key",
    secret_key="your-secret-key",
    backup_streams="3",
    capacity_bytes=5497558138880,
    compression=True
)
if result:
    print(f"Final status: {result['status']}")
"""