import requests
from typing import Dict, Optional
import urllib3
import time
import base64
import platform
import subprocess
from dataclasses import dataclass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class HYCUDeploymentStatus:
    """Status object for HYCU deployment stages"""
    vm_created: bool = False
    vm_powered_on: bool = False
    network_reachable: bool = False
    api_accessible: bool = False
    error_message: Optional[str] = None
    vm_uuid: Optional[str] = None

def get_task_status(pe_ip: str, username: str, password: str, task_uuid: str) -> Optional[Dict]:
    """Get task status from Prism Element."""
    url = f"https://{pe_ip}:9440/api/nutanix/v2.0/tasks/{task_uuid}?include_subtasks_info=true"
    
    try:
        response = requests.get(
            url=url,
            auth=(username, password),
            verify=False,
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return None

def ping_host(host: str) -> bool:
    """
    Test network connectivity to host using ping.
    Returns True if host responds to ping, False otherwise.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', host]
    try:
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except subprocess.SubprocessError:
        return False

def verify_hycu_api(vm_ip: str) -> bool:
    """
    Verify HYCU API accessibility and get authentication token.
    Returns True if API is accessible and returns valid token.
    """
    url = f"https://{vm_ip}:8443/rest/v1.0/requestToken"
    
    # Base64 encode default credentials (admin:admin)
    credentials = base64.b64encode(b"admin:admin").decode()
    
    headers = {
        'Authorization': f'Basic {credentials}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.post(
            url=url,
            headers=headers,
            verify=False
        )
        response.raise_for_status()
        
        # Verify response contains expected fields
        response_data = response.json()
        if 'token' in response_data:
            print(f"\nHYCU Controller UI is now accessible at https://{vm_ip}:8443/login")
            return True
            
        return False
        
    except requests.exceptions.RequestException as e:
        print(f"Error verifying HYCU API: {str(e)}")
        return False

def power_on_vm(pe_ip: str, username: str, password: str, vm_uuid: str) -> bool:
    """Power on a VM."""
    url = f"https://{pe_ip}:9440/api/nutanix/v2.0/vms/{vm_uuid}/set_power_state/"
    
    payload = {
        "transition": "ON"
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
        task_uuid = response.json()['task_uuid']
        
        print("\nMonitoring VM power on progress...")
        while True:
            task_info = get_task_status(pe_ip, username, password, task_uuid)
            if task_info:
                status = task_info.get('progress_status')
                percentage = task_info.get('percentage_complete', 0)
                
                print(f"\rProgress: {percentage}% | Status: {status}", end='', flush=True)
                
                if status == "Succeeded":
                    print("\nVM powered on successfully!")
                    return True
                elif status == "Failed":
                    print(f"\nVM power on failed: {task_info.get('message', 'Unknown error')}")
                    return False
                    
            time.sleep(5)
            
    except requests.exceptions.RequestException as e:
        print(f"Error powering on VM: {str(e)}")
        return False

def create_hycu_vm(pe_ip: str, username: str, password: str, vm_name: str, 
                  image_uuid: str, storage_uuid: str, network_uuid: str,
                  hostname: str, vm_ip: str, subnet_prefix: str, gateway: str, 
                  dns: str, domain: str) -> HYCUDeploymentStatus:
    """Create HYCU VM with specified configuration and power it on."""
    
    status = HYCUDeploymentStatus()
    url = f"https://{pe_ip}:9440/PrismGateway/services/rest/v2.0/vms?include_vm_disk_config=true&include_vm_nic_config=true"
    
    payload = {
        "name": vm_name,
        "memory_mb": 8192,
        "num_vcpus": 4,
        "description": "",
        "num_cores_per_vcpu": 1,
        "timezone": "UTC",
        "boot": {
            "uefi_boot": False,
            "boot_device_order": ["CDROM", "DISK", "NIC"]
        },
        "machine_type": "PC",
        "vm_disks": [
            {
                "is_cdrom": False,
                "disk_address": {"device_bus": "scsi", "device_index": 0},
                "vm_disk_clone": {
                    "disk_address": {"vmdisk_uuid": image_uuid},
                    "minimum_size": 10737418240
                }
            },
            {
                "is_cdrom": False,
                "disk_address": {"device_bus": "scsi", "device_index": 1},
                "vm_disk_create": {
                    "storage_container_uuid": storage_uuid,
                    "size": 34359738368
                }
            }
        ],
        "vm_nics": [
            {
                "network_uuid": network_uuid,
                "is_connected": True
            }
        ],
        "hypervisor_type": "ACROPOLIS",
        "vm_customization_config": {
            "userdata": f"#cloud-config\nbootcmd:\n- /opt/grizzly/bin/cloud_init_setup.sh {hostname} {vm_ip}/{subnet_prefix} {gateway} {dns} {domain} controller",
            "files_to_inject_list": []
        },
        "vm_features": {
            "AGENT_VM": False
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
        task_uuid = response.json()['task_uuid']
        
        print("\nMonitoring VM creation progress...")
        while True:
            task_info = get_task_status(pe_ip, username, password, task_uuid)
            if task_info:
                task_status = task_info.get('progress_status')
                percentage = task_info.get('percentage_complete', 0)
                
                print(f"\rProgress: {percentage}% | Status: {task_status}", end='', flush=True)
                
                if task_status == "Succeeded":
                    print("\nVM creation completed successfully!")
                    status.vm_created = True
                    status.vm_uuid = task_info['entity_list'][0]['entity_id']
                    
                    # Power on the VM
                    if power_on_vm(pe_ip, username, password, status.vm_uuid):
                        status.vm_powered_on = True
                        print("\nWaiting 300 seconds for HYCU services to start...")
                        time.sleep(300)
                        
                        print("\nTesting network connectivity to HYCU VM...")
                        if ping_host(vm_ip):
                            print("Network connectivity established!")
                            status.network_reachable = True
                            
                            # Test API accessibility
                            if verify_hycu_api(vm_ip):
                                status.api_accessible = True
                            else:
                                status.error_message = "VM deployed but API not yet accessible (services may still be initializing)"
                        else:
                            status.error_message = "VM deployed but network connectivity test failed"
                    else:
                        status.error_message = "VM created but failed to power on"
                    break
                    
                elif task_status == "Failed":
                    status.error_message = task_info.get('message', 'Unknown error during VM creation')
                    break
                    
            time.sleep(10)
            
    except requests.exceptions.RequestException as e:
        status.error_message = f"Error during VM creation: {str(e)}"
        if hasattr(e, 'response') and e.response is not None and hasattr(e.response, 'text'):
            status.error_message += f"\nResponse: {e.response.text}"
    
    return status