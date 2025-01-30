import requests
from typing import Dict, Any
from requests.exceptions import RequestException
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ObjectStoreTokenError(Exception):
    """Custom exception for object store token errors"""
    pass

def get_object_store_token(
    pc_ip: str,
    username: str,
    password: str,
    object_store_uuid: str
) -> str:
    """
    Retrieves token for specified object store from Prism Central API.
    
    Args:
        pc_ip (str): Prism Central IP address
        username (str): Authentication username
        password (str): Authentication password
        object_store_uuid (str): UUID of the object store
    
    Returns:
        str: Object store token
    
    Raises:
        ObjectStoreTokenError: If the API request fails or token not found
    """
    
    # Construct the API URL
    url = f"https://{pc_ip}:9440/oss/api/nutanix/v3/objectstores/{object_store_uuid}?get_new_token=true"
    
    try:
        # Make the API request
        response = requests.get(
            url,
            auth=(username, password),
            verify=False,  # Disable SSL verification
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
        )
        
        # Check if the request was successful
        response.raise_for_status()
        
        # Parse the response
        response_data = response.json()
        
        # Extract and return the token
        token = response_data.get("token")
        if not token:
            raise ObjectStoreTokenError("Token not found in response")
            
        return token
        
    except RequestException as e:
        # Handle any request-related errors
        error_message = f"Failed to retrieve object store token: {str(e)}"
        if hasattr(e.response, 'text'):
            error_message += f"\nResponse: {e.response.text}"
        raise ObjectStoreTokenError(error_message)
    
    except Exception as e:
        # Handle any other unexpected errors
        raise ObjectStoreTokenError(f"Unexpected error while retrieving object store token: {str(e)}")