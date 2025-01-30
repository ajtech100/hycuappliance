import requests
from typing import Dict, Any
from requests.exceptions import RequestException
import urllib3
import time

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ObjectStoreDeployError(Exception):
    """Custom exception for object store deployment errors"""
    pass

def get_task_progress(pc_ip: str, username: str, password: str, objectstore_uuid: str) -> Dict[str, Any]:
    """Gets the progress of a task using the progress monitor API."""
    url = f"https://{pc_ip}:9440/PrismGateway/services/rest/v1/progress_monitors"
    
    try:
        response = requests.get(
            url,
            auth=(username, password),
            verify=False,
            headers={"Accept": "application/json"}
        )
        response.raise_for_status()
        
        tasks = response.json()["entities"]
        for task in tasks:
            if ('entityId' in task and objectstore_uuid in task['entityId'] and 
                task.get('operation') == 'create_object_store'):
                return task
        return {}
    except RequestException as e:
        raise ObjectStoreDeployError(f"Failed to get task progress: {str(e)}")

def deploy_object_store(pc_ip: str, username: str, password: str, object_store_uuid: str, token: str) -> Dict[str, Any]:
    """Deploys an object store using its UUID and token via Prism Central API."""
    
    url = f"https://{pc_ip}:9440/oss/api/nutanix/v3/objectstores/{object_store_uuid}?token={token}&deploy=true"
    
    try:
        response = requests.put(
            url,
            auth=(username, password),
            verify=False,
            headers={"Content-Type": "application/json", "Accept": "application/json"}
        )
        response.raise_for_status()
        deploy_response = response.json()
        
        print("\nStarting deployment monitoring...")
        
        while True:
            progress_data = get_task_progress(pc_ip, username, password, object_store_uuid)
            
            if progress_data:
                print(f"\rProgress: {progress_data.get('percentageCompleted', 0)}% | Status: {progress_data.get('status', '')} | Task: {progress_data.get('subTaskMessage', '')}", end='', flush=True)
                
                if progress_data.get('status') == 'succeeded':
                    print("\nDeployment completed successfully!")
                    break
                elif progress_data.get('status') == 'failed':
                    print()
                    raise ObjectStoreDeployError(f"Deployment failed: {progress_data.get('subTaskMessage', '')}")
            
            time.sleep(30)
        
        return deploy_response
        
    except RequestException as e:
        raise ObjectStoreDeployError(f"Failed to deploy object store: {str(e)}")
    except Exception as e:
        raise ObjectStoreDeployError(f"Error during object store deployment: {str(e)}")

if __name__ == "__main__":
    # Configuration
    PC_IP = "your_pc_ip"
    USERNAME = "username"
    PASSWORD = "password"
    OBJECT_STORE_UUID = "your_objectstore_uuid"
    TOKEN = "your_token"
    
    try:
        result = deploy_object_store(
            pc_ip=PC_IP,
            username=USERNAME,
            password=PASSWORD,
            object_store_uuid=OBJECT_STORE_UUID,
            token=TOKEN
        )
    except ObjectStoreDeployError as e:
        print(f"\nError: {str(e)}")
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
