import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json
from typing import Dict, Optional, List

def create_object_store(
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
    client_network_ips: List[str],
    verify_ssl: bool = False
) -> Optional[Dict]:
    """
    Create Nutanix Objects Store.
    
    Args:
        pc_ip (str): Prism Central IP address
        username (str): Username for authentication
        password (str): Password for authentication
        name (str): Object store name
        domain (str): Prism Central domain
        cluster_uuid (str): UUID of the cluster
        num_worker_nodes (int): Number of worker nodes
        storage_network_dns (str): Storage network DNS IP
        storage_network_vip (str): Storage network VIP
        storage_network_uuid (str): UUID of storage network
        client_network_uuid (str): UUID of client network
        client_network_ips (List[str]): List of client network IPs
        verify_ssl (bool): Whether to verify SSL certificate (default: False)
    
    Returns:
        dict: API response if successful, None if failed
    """
    
    # Disable SSL warnings if verify_ssl is False
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Construct the API URL
    url = f"https://{pc_ip}:9440/oss/api/nutanix/v3/objectstores?save=true"
    
    # Prepare the payload
    payload = {
        "api_version": "3.0",
        "metadata": {
            "kind": "objectstore"
        },
        "spec": {
            "name": name,
            "description": f"{name}",
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
    
    # Prepare headers
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    try:
        # Make API request
        response = requests.post(
            url=url,
            auth=HTTPBasicAuth(username, password),
            verify=verify_ssl,
            headers=headers,
            data=json.dumps(payload),
            timeout=30
        )
        
        # Check if request was successful
        response.raise_for_status()
        
        # Return JSON response if available, else return raw response
        try:
            return response.json()
        except json.JSONDecodeError:
            return {"status_code": response.status_code, "text": response.text}
    
    except requests.exceptions.RequestException as e:
        print(f"Error creating Object Store: {str(e)}")
        return None

# Example of how the main calling script would use this:
"""
from create_objectstore import create_object_store

def deploy_objectstore():
    # PC details
    pc_ip = "10.10.72.210"
    username = "admin"
    password = "your_password"
    
    # Object Store parameters
    name = "ObjectAuto"
    domain = "prism-central.cluster.local"
    cluster_uuid = "000620c6-177a-5d0c-0000-000000019a4c"
    num_worker_nodes = 3
    storage_network_dns = "10.10.72.115"
    storage_network_vip = "10.10.72.116"
    storage_network_uuid = "313be57a-b4ce-4ad9-a974-e7defaa5fcbe"
    client_network_uuid = "ca5871d2-1dec-46ea-9e25-a7b77dbec12f"
    client_network_ips = ["10.10.74.115", "10.10.74.116"]
    
    response = create_object_store(
        pc_ip=pc_ip,
        username=username,
        password=password,
        name=name,
        domain=domain,
        cluster_uuid=cluster_uuid,
        num_worker_nodes=num_worker_nodes,
        storage_network_dns=storage_network_dns,
        storage_network_vip=storage_network_vip,
        storage_network_uuid=storage_network_uuid,
        client_network_uuid=client_network_uuid,
        client_network_ips=client_network_ips
    )
    
    if response:
        print("Successfully initiated Object Store creation:")
        print(json.dumps(response, indent=2))
        return response
    else:
        print("Failed to create Object Store")
        return None
"""
