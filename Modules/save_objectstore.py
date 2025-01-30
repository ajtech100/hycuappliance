import requests
from typing import List, Dict, Any, Union
from requests.exceptions import RequestException
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ObjectStoreConfigError(Exception):
    """Custom exception for object store save configuration errors"""
    pass

def save_object_store_config(
    pc_ip: str,
    username: str,
    password: str,
    name: str,
    domain: str,
    cluster_uuid: str,
    num_worker_nodes: int,
    storage_network_dns: str,
    storage_network_vip: str,
    storage_network_uuid: str,
    client_network_uuid: str,
    client_network_ips: List[str]
) -> Dict[str, Any]:
    """
    Saves an object store configuration via Prism Central API.
    
    Args:
        pc_ip (str): Prism Central IP address
        username (str): Authentication username
        password (str): Authentication password
        name (str): Name of the object store
        domain (str): Domain name
        cluster_uuid (str): Cluster UUID
        num_worker_nodes (int): Number of worker nodes
        storage_network_dns (str): Storage network DNS
        storage_network_vip (str): Storage network VIP
        storage_network_uuid (str): Storage network UUID
        client_network_uuid (str): Client network UUID
        client_network_ips (List[str]): List of client network IPs
    
    Returns:
        Dict[str, Any]: API response data after saving configuration
    
    Raises:
        ObjectStoreConfigError: If the save configuration API request fails
    """
    
    # Construct the API URL for saving configuration
    url = f"https://{pc_ip}:9440/oss/api/nutanix/v3/objectstores?save=true"
    
    # Prepare the save configuration payload
    payload = {
        "api_version": "3.0",
        "metadata": {
            "kind": "objectstore"
        },
        "spec": {
            "name": name,
            "description": name,
            "resources": {
                "domain": domain,
                "cluster_reference": {
                    "kind": "cluster",
                    "uuid": cluster_uuid
                },
                "num_worker_nodes": num_worker_nodes,
                "buckets_infra_network_dns": storage_network_dns,
                "buckets_infra_network_vip": storage_network_vip,
                "buckets_infra_network_reference": {
                    "kind": "subnet",
                    "uuid": storage_network_uuid
                },
                "client_access_network_reference": {
                    "kind": "subnet",
                    "uuid": client_network_uuid
                },
                "aggregate_resources": {
                    "total_vcpu_count": 0,
                    "total_memory_size_mib": 0,
                    "total_capacity_gib": 0
                },
                "client_access_network_ip_list": client_network_ips
            }
        }
    }
    
    try:
        # Make the save configuration API request
        response = requests.post(
            url,
            json=payload,
            auth=(username, password),
            verify=False,  # Disable SSL verification
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
        )
        
        # Check if the save request was successful
        response.raise_for_status()
        
        # Return the save configuration response data
        return response.json()
        
    except RequestException as e:
        # Handle any save configuration request-related errors
        error_message = f"Failed to save object store configuration: {str(e)}"
        if hasattr(e.response, 'text'):
            error_message += f"\nResponse: {e.response.text}"
        raise ObjectStoreConfigError(error_message)
    
    except Exception as e:
        # Handle any other unexpected errors during save configuration
        raise ObjectStoreConfigError(f"Unexpected error while saving object store configuration: {str(e)}")