from typing import Dict, Optional, List
import requests
import urllib3
import logging

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def list_objectstores(pc_ip: str, username: str, password: str) -> Optional[List[Dict]]:
    """List all object stores in Prism Central."""
    
    url = f"https://{pc_ip}:9440/api/objects/v4.0.a2/operations/object-stores"
    
    try:
        response = requests.get(
            url=url,
            auth=(username, password),
            verify=False,
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        
        data = response.json().get('data', [])
        if not data:
            logging.warning("No object stores found in Prism Central")
            return []

        result = []
        for store in data:
            try:
                store_info = {
                    'name': store['name'],
                    'ext_id': store['extId'],
                    'version': store['deploymentVersion'],
                    'public_ips': [ip['ipv4']['value'] for ip in store.get('publicNetworkIps', [])]
                }
                result.append(store_info)
            except KeyError as e:
                logging.warning(f"Skipping malformed object store entry, missing field: {e}")
                continue
            
        return result
        
    except requests.exceptions.RequestException as e:
        error_msg = f"Error listing object stores: {str(e)}"
        if hasattr(e, 'response') and e.response is not None:
            if hasattr(e.response, 'text'):
                error_msg += f"\nResponse: {e.response.text}"
        logging.error(error_msg)
        raise ValueError(error_msg)

    except Exception as e:
        error_msg = f"Unexpected error listing object stores: {str(e)}"
        logging.error(error_msg)
        raise ValueError(error_msg)