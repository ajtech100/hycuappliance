import requests
from typing import List, Optional
import urllib3
import logging

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def list_buckets(pc_ip: str, username: str, password: str, objectstore_uuid: str) -> Optional[List[str]]:
    """List all buckets in the object store."""
    
    url = f"https://{pc_ip}:9440/oss/api/nutanix/v3/objectstore_proxy/{objectstore_uuid}/groups"
    
    payload = {
        "entity_type": "bucket",
        "group_member_sort_attribute": "name",
        "group_member_sort_order": "ASCENDING",
        "group_member_count": 20,
        "group_member_offset": 0,
        "filter_criteria": "federation_name==\"\"",
        "group_member_attributes": [
            {"attribute": "name"},
            {"attribute": "storage_usage_bytes"},
            {"attribute": "object_count"},
            {"attribute": "bucket_state"}
        ]
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
        
        data = response.json()
        buckets = []
        
        for group in data.get('group_results', []):
            for entity in group.get('entity_results', []):
                bucket_name = entity.get('entity_id')
                if bucket_name:
                    buckets.append(bucket_name)
        
        logging.debug(f"Found buckets: {', '.join(buckets) if buckets else 'none'}")
        return buckets
        
    except requests.exceptions.RequestException as e:
        error_msg = f"Error listing buckets: {str(e)}"
        if hasattr(e, 'response') and e.response is not None:
            if hasattr(e.response, 'text'):
                error_msg += f"\nResponse: {e.response.text}"
        logging.error(error_msg)
        return None

    except Exception as e:
        logging.error(f"Unexpected error listing buckets: {str(e)}")
        return None