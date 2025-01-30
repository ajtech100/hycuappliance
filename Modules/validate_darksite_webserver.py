import requests
import urllib3
from bs4 import BeautifulSoup
from typing import Dict, Optional, List
from urllib.parse import urljoin

def validate_darksite_webserver(webserver_url: str, verify_ssl: bool = False) -> Dict:
    """
    Validate darksite webserver and its contents.
    
    Args:
        webserver_url (str): Darksite webserver URL with /release/ directory
        verify_ssl (bool): Whether to verify SSL certificate (default: False)
    
    Returns:
        dict: Validation results including status and file list
    """
    
    # Initialize result dictionary
    result = {
        "status": False,
        "message": "",
        "files": [],
        "error": None
    }
    
    # Disable SSL warnings if verify_ssl is False
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Validate URL format
    if not webserver_url.endswith('/release/'):
        result["message"] = "Invalid URL format. URL must end with /release/"
        result["error"] = "URL_FORMAT_ERROR"
        return result

    try:
        # Make HTTP request to the webserver
        response = requests.get(
            url=webserver_url,
            verify=verify_ssl,
            timeout=30
        )
        
        # Check if request was successful
        response.raise_for_status()
        
        # Parse HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all links/files in the directory
        files = []
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and not href.startswith('?') and not href == '../':
                files.append(href)
        
        # Update result with success
        result["status"] = True
        result["message"] = "Successfully connected to darksite webserver"
        result["files"] = files
        
        # Validate required components
        required_components = [
            "lcm-",
            "nutanix_installer_package",
            "cluster_check",
            "foundation",
            "ncc"
        ]
        
        missing_components = []
        for component in required_components:
            if not any(component in file.lower() for file in files):
                missing_components.append(component)
        
        if missing_components:
            result["message"] = f"Missing required components: {', '.join(missing_components)}"
            result["status"] = False
            result["error"] = "MISSING_COMPONENTS"
        
    except requests.exceptions.ConnectionError:
        result["message"] = "Failed to connect to darksite webserver"
        result["error"] = "CONNECTION_ERROR"
    
    except requests.exceptions.RequestException as e:
        result["message"] = f"Error accessing darksite webserver: {str(e)}"
        result["error"] = "REQUEST_ERROR"
    
    except Exception as e:
        result["message"] = f"Unexpected error: {str(e)}"
        result["error"] = "UNEXPECTED_ERROR"
    
    return result

def print_validation_results(result: Dict):
    """Print validation results in a formatted way"""
    print("\nDarksite Webserver Validation Results:")
    print("=" * 40)
    print(f"Status: {'Success' if result['status'] else 'Failed'}")
    print(f"Message: {result['message']}")
    
    if result['files']:
        print("\nFiles found in directory:")
        print("-" * 40)
        for file in sorted(result['files']):
            print(f"- {file}")
    
    if result['error']:
        print(f"\nError Code: {result['error']}")

# Example of how the main calling script would use this:
"""
from validate_darksite_webserver import validate_darksite_webserver, print_validation_results

def check_darksite():
    webserver_url = "http://10.10.74.161/release/"
    
    validation_result = validate_darksite_webserver(webserver_url)
    print_validation_results(validation_result)
    
    if validation_result['status']:
        print("\nDarksite webserver validation successful")
        return validation_result
    else:
        print("\nDarksite webserver validation failed")
        return None
"""
