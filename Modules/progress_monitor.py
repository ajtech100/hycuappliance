import requests
from typing import Dict, Any
from requests.exceptions import RequestException
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ProgressMonitorError(Exception):
    """Custom exception for progress monitor errors"""
    pass

def get_progress_monitor(
    pc_ip: str,
    username: str,
    password: str
) -> Dict[str, Any]:
    """
    Retrieves progress monitor data from Prism Central API.
    
    Args:
        pc_ip (str): Prism Central IP address
        username (str): Authentication username
        password (str): Authentication password
    
    Returns:
        Dict[str, Any]: Progress monitor response data
    
    Raises:
        ProgressMonitorError: If the API request fails
    """
    
    # Construct the API URL
    url = f"https://{pc_ip}:9440/PrismGateway/services/rest/v1/progress_monitors"
    
    try:
        # Make the API request
        response = requests.get(
            url,
            auth=(username, password),
            verify=False,  # Disable SSL verification
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            timeout=30  # Add timeout for request
        )
        
        # Check if the request was successful
        response.raise_for_status()
        
        # Return the response data
        return response.json()
        
    except RequestException as e:
        # Handle any request-related errors
        error_message = f"Failed to retrieve progress monitor data: {str(e)}"
        if hasattr(e.response, 'text'):
            error_message += f"\nResponse: {e.response.text}"
        raise ProgressMonitorError(error_message)
    
    except Exception as e:
        # Handle any other unexpected errors
        raise ProgressMonitorError(f"Unexpected error while retrieving progress monitor data: {str(e)}")