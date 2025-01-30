#!/usr/bin/env python3

import os
import sys
import yaml
import argparse
import logging
import time
import traceback
from typing import Optional, List, Dict, Tuple
import urllib3
from getpass import getpass
import socket
import subprocess

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add modules directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'Modules'))

# Import required modules
from lcm_config_get import get_lcm_configs
from lcm_config_update import update_lcm_config
from save_objectstore import save_object_store_config
from get_token import get_object_store_token
from deploy_objectstore import deploy_object_store
from get_cluster_list import get_cluster_list
from get_cluster_details import get_cluster_details
from get_network_list import get_network_list
from get_storagecontainer_list import get_storage_containers
from get_images_list import get_images
from create_hycuvm import create_hycu_vm
from get_objectstore_list import list_objectstores
from create_bucket import create_bucket
from share_bucket import share_bucket
from add_hycu_target import add_hycu_target
from get_userkeys import get_user_keys
from get_pcuser_list import list_users
from create_userkeys import create_access_keys
from create_existinguser_keys import create_user_keys
from get_bucket_list import list_buckets

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('hycu_deployment.log'),
        logging.StreamHandler()
    ]
)

class ValidationSeverity:
    ERROR = "ERROR"      # Must be fixed to proceed
    WARNING = "WARNING"  # Can proceed but might cause issues

class ValidationResult:
    def __init__(self):
        self.issues = []

    def add_issue(self, message: str, severity: str):
        self.issues.append({"message": message, "severity": severity})

    @property
    def has_errors(self):
        return any(issue["severity"] == ValidationSeverity.ERROR for issue in self.issues)

    @property
    def has_warnings(self):
        return any(issue["severity"] == ValidationSeverity.WARNING for issue in self.issues)

class ConfigSelector:
    def __init__(self, config_dir: str = "config"):
        self.config_dir = os.path.join(os.path.dirname(__file__), config_dir)

    def list_available_configs(self) -> List[dict]:
        """List all available configurations"""
        configs = []
        unparseable_files = []
        
        for file in os.listdir(self.config_dir):
            if file.endswith(('-hycu-config.yaml', '-hycu-config.yml')):
                file_path = os.path.join(self.config_dir, file)
                try:
                    env, clusters, _ = file.split('-', 2)
                    pc_name, pe_name = clusters.split('_')
                    
                    with open(file_path, 'r') as f:
                        config = yaml.safe_load(f)
                    
                    configs.append({
                        'file_path': file_path,
                        'environment': env,
                        'pc_name': pc_name,
                        'pe_name': pe_name,
                        'pc_ip': config['prism_central']['pc_ip'],
                        'pe_ip': config['prism_element']['pe_ip']
                    })
                except Exception as e:
                    unparseable_files.append((file, str(e)))
                    logging.warning(f"Could not parse {file}: {str(e)}")
        
        if unparseable_files:
            print("\nWarning: The following configuration files could not be parsed:")
            for file, error in unparseable_files:
                print(f"- {file}")
            print("\nPlease verify the structure and contents of these files. Configuration files should:")
            print("1. Follow the naming convention: <env>-<pc_name>_<pe_name>-hycu-config.yaml")
            print("2. Contain valid YAML syntax")
            print("3. Include all required sections: prism_central, prism_element, object_store, hycu_controller, hycu_target")
            print("\nRefer to the configuration template for the correct format.")
        
        return configs

    def select_config(self, pc_ip: Optional[str] = None, pe_ip: Optional[str] = None) -> str:
        """Select configuration file based on PC/PE IPs"""
        configs = self.list_available_configs()
        
        if not configs:
            raise FileNotFoundError("No configuration files found in config directory")

        if pc_ip and pe_ip:
            for config in configs:
                if config['pc_ip'] == pc_ip and config['pe_ip'] == pe_ip:
                    return config['file_path']
            raise ValueError(f"No configuration found for PC: {pc_ip} and PE: {pe_ip}")

        while True:
            print("\nAvailable Configurations:")
            print("{:<4} {:<10} {:<8} {:<8} {:<15} {:<15}".format(
                "Idx", "Env", "PC", "PE", "PC IP", "PE IP"))
            print("-" * 65)
            
            for idx, config in enumerate(configs, 1):
                print("{:<4} {:<10} {:<8} {:<8} {:<15} {:<15}".format(
                    idx,
                    config['environment'],
                    config['pc_name'],
                    config['pe_name'],
                    config['pc_ip'],
                    config['pe_ip']
                ))

            try:
                choice = int(input("\nSelect configuration index: ")) - 1
                if 0 <= choice < len(configs):
                    selected_file = configs[choice]['file_path']
                    
                    print("\nSelected Configuration Details:")
                    print("=" * 30)
                    with open(selected_file, 'r') as f:
                        print(f.read().rstrip())
                    
                    print("\nOptions:")
                    print("1. Proceed with this configuration")
                    print("2. Select another configuration")
                    print("3. Exit to update configuration file")
                    
                    while True:
                        option = input("\nEnter your choice (1-3): ")
                        if option == "1":
                            return selected_file
                        elif option == "2":
                            break  # Go back to configuration selection
                        elif option == "3":
                            print("\nExiting. Please update the configuration file and run the script again.")
                            sys.exit(0)
                        else:
                            print("Invalid choice. Please try again.")
                else:
                    print("Invalid selection. Please enter a valid index.")
            except ValueError:
                print("Please enter a valid number")
            except Exception as e:
                print(f"Error processing configuration: {str(e)}")
                print("Please verify the configuration file format and try again.")


def get_user_ext_id(pc_ip: str, username: str, password: str, target_username: str) -> Optional[str]:
    """
    Get user's ext_id based on display name
    
    Args:
        pc_ip: Prism Central IP
        username: Admin username
        password: Admin password
        target_username: Display name to find
        
    Returns:
        str: User's ext_id if found, None otherwise
    """
    try:
        users = list_users(pc_ip, username, password)
        if users:
            # Compare against display_name instead of username
            user = next((u for u in users if u['display_name'].lower() == target_username.lower()), None)
            if user:
                logging.info(f"Found existing user: {user['display_name']}")
                return user['ext_id']
    except Exception as e:
        logging.error(f"Error finding user: {str(e)}")
        return None
    return None


def check_bucket_exists(pc_ip: str, username: str, password: str, objectstore_uuid: str, bucket_name: str) -> bool:
    """Check if bucket already exists"""
    try:
        buckets = list_objectstores(pc_ip, username, password, objectstore_uuid)
        return any(bucket['name'] == bucket_name for bucket in buckets)
    except Exception:
        return False


def is_dns_resolvable(dns_server: str) -> bool:
    """Check if DNS server is reachable"""
    try:
        socket.gethostbyname(dns_server)
        return True
    except socket.error:
        return False


def show_deployment_menu() -> str:
    """Show deployment menu and return user choice"""
    print("\nHYCU Deployment Menu:")
    print("1. Configure LCM darksite")
    print("2. Deploy Object Store")
    print("3. Deploy HYCU Controller")
    print("4. Configure HYCU Target")
    print("5. Exit deployment")
    
    while True:
        choice = input("\nSelect step to execute (1-5): ")
        if choice in ['1', '2', '3', '4', '5']:
            return choice
        print("Invalid choice. Please try again.")


def deploy_step_lcm(config: Dict, deployment_state: Dict) -> None:
    """Deploy LCM darksite configuration step"""
    if deployment_state['lcm_configured']:
        logging.info("LCM darksite already configured, skipping...")
        return

    pc = config['prism_central']
    logging.info("Configuring LCM darksite...")
    current_config = get_lcm_configs(pc['pc_ip'], pc['username'], pc['password'])
    etag = current_config.get('metadata', {}).get('ETag')
    
    if not etag:
        raise ValueError("Failed to get ETag from current configuration")
        
    updated_config = update_lcm_config(
        pc['pc_ip'],
        pc['username'],
        pc['password'], 
        etag,
        pc['darksite_url']
    )
    
    if not updated_config:
        raise ValueError("Failed to update LCM configuration")
    
    deployment_state['lcm_configured'] = True
    logging.info("LCM darksite configured successfully")


def deploy_step_objectstore(config: Dict, deployment_state: Dict) -> None:
    """Deploy Object Store step"""
    if deployment_state['objectstore_deployed']:
        logging.info("Object Store already deployed, skipping...")
        return

    pc = config['prism_central']
    pe = config['prism_element']
    obj_store = config['object_store']
    
    logging.info("Deploying Object Store...")
    
    # Get cluster UUID
    clusters = get_cluster_list(pc['pc_ip'], pc['username'], pc['password'])
    cluster = next(
        (c for c in clusters['entities'] 
         if c['status']['name'] == config['prism_element']['cluster_name']),
        None
    )
    
    if not cluster:
        raise ValueError(f"Cluster {config['prism_element']['cluster_name']} not found")
        
    # Get network UUIDs
    networks = get_network_list(pe['pe_ip'], pe['username'], pe['password'])
    storage_network = next(
        (n for n in networks['entities'] 
         if n['name'] == obj_store['storage_network']['network_name']),
        None
    )
    client_network = next(
        (n for n in networks['entities'] 
         if n['name'] == obj_store['client_network']['network_name']),
        None
    )
                         
    if not storage_network or not client_network:
        raise ValueError("Required networks not found")
        
    # Deploy object store
    obj_store_payload = {
        "name": obj_store['name'],
        "domain": pc['pc_domain'],
        "cluster_uuid": cluster['metadata']['uuid'],
        "num_worker_nodes": obj_store['num_worker_nodes'],
        "storage_network_dns": obj_store['storage_network']['dns'],
        "storage_network_vip": obj_store['storage_network']['vip'],
        "storage_network_uuid": storage_network['uuid'],
        "client_network_uuid": client_network['uuid'],
        "client_network_ips": obj_store['client_network']['ips']
    }
    
    save_response = save_object_store_config(
        pc['pc_ip'],
        pc['username'], 
        pc['password'],
        **obj_store_payload
    )
    
    objectstore_uuid = save_response['metadata']['uuid']
    token = get_object_store_token(
        pc['pc_ip'],
        pc['username'], 
        pc['password'],
        objectstore_uuid
    )
    
    deploy_response = deploy_object_store(
        pc['pc_ip'],
        pc['username'], 
        pc['password'],
        objectstore_uuid,
        token
    )
    
    deployment_state['objectstore_deployed'] = True
    deployment_state['objectstore_uuid'] = objectstore_uuid
    logging.info("Object Store deployed successfully")


def deploy_step_hycu_controller(config: Dict, deployment_state: Dict, client_network: Dict) -> None:
    """Deploy HYCU Controller step"""
    if deployment_state['hycu_controller_deployed']:
        logging.info("HYCU Controller already deployed, skipping...")
        return

    pe = config['prism_element']
    hycu = config['hycu_controller']
    
    logging.info("Deploying HYCU Controller...")
    
    try:
        # Get storage container UUID
        containers = get_storage_containers(pe['pe_ip'], pe['username'], pe['password'])
        container = next((c for c in containers if c[0] == hycu['storage_container']), None)
        
        # Get image details
        images = get_images(pe['pe_ip'], pe['username'], pe['password'])
        image = next((i for i in images if i[0] == hycu['image_name']), None)
        
        if not container or not image:
            raise ValueError("Required storage container or image not found")
        
        # Deploy VM with enhanced status reporting
        deploy_status = create_hycu_vm(
            pe_ip=pe['pe_ip'],
            username=pe['username'],
            password=pe['password'],
            vm_name=hycu['vm_name'],
            image_uuid=image[2],
            storage_uuid=container[1],
            network_uuid=client_network['uuid'],
            hostname=hycu['hostname'],
            vm_ip=hycu['ip'],
            subnet_prefix=hycu['subnet_prefix'],
            gateway=hycu['gateway'],
            dns=hycu['dns_server'],
            domain=hycu['domain']
        )
        
        # Handle different stages of deployment
        if not deploy_status.vm_created:
            raise ValueError(f"VM creation failed: {deploy_status.error_message}")
        
        if not deploy_status.vm_powered_on:
            logging.error(f"VM created but power on failed: {deploy_status.error_message}")
            raise ValueError("Failed to power on HYCU Controller VM")
            
        if not deploy_status.network_reachable:
            logging.error(f"VM powered on but network unreachable: {deploy_status.error_message}")
            raise ValueError("Network connectivity to HYCU Controller VM could not be established")
            
        # Mark as deployed if VM is created, powered on, and network reachable
        if deploy_status.vm_created and deploy_status.vm_powered_on and deploy_status.network_reachable:
            deployment_state['hycu_controller_deployed'] = True
            deployment_state['hycu_vm_uuid'] = deploy_status.vm_uuid
            
            if not deploy_status.api_accessible:
                logging.warning(f"HYCU Controller VM deployed but API not yet accessible: {deploy_status.error_message}")
                print(f"\nHYCU Controller VM has been deployed but the API is not yet accessible.")
                print(f"You can proceed with deployment and check the UI manually at https://{hycu['ip']}:8443/login")
            else:
                logging.info("HYCU Controller deployed successfully with API access confirmed")
            
            return True
            
        raise ValueError("HYCU Controller deployment failed at an unknown stage")
            
    except Exception as e:
        error_info = traceback.format_exc()
        logging.error(f"Error in HYCU Controller deployment:\n{error_info}")
        raise ValueError(str(e))


def check_bucket_exists(pc_ip: str, username: str, password: str, objectstore_uuid: str, bucket_name: str) -> bool:
    """Check if bucket already exists using list_buckets function"""
    try:
        buckets = list_buckets(pc_ip, username, password, objectstore_uuid)
        if buckets is None:
            logging.warning("Could not retrieve bucket list")
            return False
            
        return bucket_name in buckets
    except Exception as e:
        logging.warning(f"Error checking bucket existence: {str(e)}")
        return False

def handle_access_keys(pc_ip: str, username: str, password: str, target_config: Dict) -> Tuple[str, str]:
    """
    Handle access key creation or retrieval based on user existence.
    For existing users: Use keys from config
    For new users: Create new user and keys
    Returns tuple of (access_key, secret_key)
    """
    # First check if user exists using username
    existing_user = get_user_ext_id(pc_ip, username, password, target_config['user_name'])
    
    if existing_user:
        logging.info("User already exists, using configured access keys")
        # For existing user, must use keys from config
        if not target_config.get('user_accesskey') or not target_config.get('user_secretkey'):
            print("\nError: User already exists but no access keys provided in configuration.")
            print("Please update the configuration file with the existing user's access keys:")
            print("hycu_target:")
            print("  user_accesskey: <existing_access_key>")
            print("  user_secretkey: <existing_secret_key>")
            sys.exit(1)
        return target_config['user_accesskey'], target_config['user_secretkey']
    else:
        # For new user, create user and new keys regardless of config values
        logging.info("User does not exist. Creating new user and access keys...")
        key_result = create_access_keys(
            pc_ip=pc_ip,
            username=username,
            password=password,
            user_email=target_config['user_email'],
            display_name=target_config['user_name']
        )
        
        if not key_result:
            raise ValueError("Failed to create new user and access keys")
            
        access_key_id, secret_key, _, _ = key_result
        
        print("\nNEW USER AND ACCESS KEYS CREATED")
        print("--------------------------------")
        print(f"Access Key: {access_key_id}")
        print(f"Secret Key: {secret_key}")
        print("\nIMPORTANT: Store these keys safely for future use!")
        print("You may want to update your configuration file with these keys for future use.")
        input("Press Enter to continue after saving the keys...")
        
        return access_key_id, secret_key

def deploy_step_hycu_target(config: Dict, deployment_state: Dict) -> None:
    """Configure HYCU Target step"""
    if deployment_state['target_configured']:
        logging.info("HYCU Target already configured, skipping...")
        return

    pc = config['prism_central']
    target = config['hycu_target']
    obj_store = config['object_store']
    hycu = config['hycu_controller']
    
    logging.info("Configuring HYCU Target...")
    
    # Get objectstore UUID if not in deployment state
    if not deployment_state.get('objectstore_uuid'):
        logging.info("Fetching Object Store information...")
        stores = list_objectstores(pc['pc_ip'], pc['username'], pc['password'])
        if not stores:
            raise ValueError("No Object Stores found. Please deploy Object Store first.")
        
        matching_store = next((store for store in stores if store['name'] == obj_store['name']), None)
        if not matching_store:
            raise ValueError(f"Object Store '{obj_store['name']}' not found")
        
        deployment_state['objectstore_uuid'] = matching_store['ext_id']

    # Check bucket existence and create if needed
    logging.info("Checking if bucket exists...")
    bucket_exists = check_bucket_exists(
        pc['pc_ip'],
        pc['username'],
        pc['password'], 
        deployment_state['objectstore_uuid'], 
        target['bucket_name']
    )
    
    if not bucket_exists:
        logging.info(f"Creating bucket '{target['bucket_name']}'...")
        if not create_bucket(pc['pc_ip'], pc['username'], pc['password'], 
                           deployment_state['objectstore_uuid'], target['bucket_name']):
            raise ValueError("Failed to create bucket")
    else:
        logging.info("Bucket already exists")

    # Handle access keys with new logic
    access_key, secret_key = handle_access_keys(pc['pc_ip'], pc['username'], pc['password'], target)
    
    # Share bucket (idempotent operation)
    if not share_bucket(pc['pc_ip'], pc['username'], pc['password'],
                       deployment_state['objectstore_uuid'], 
                       target['bucket_name'], 
                       target['user_email']):
        raise ValueError("Failed to share bucket")

    # Add HYCU target
    service_endpoint = f"http://{obj_store['client_network']['ips'][0]}"
    result = add_hycu_target(
        hycu_ip=hycu['ip'],
        username=hycu['credentials']['username'],
        password=hycu['credentials']['password'],
        target_name=target['target_name'],
        service_endpoint=service_endpoint,
        bucket_name=target['bucket_name'],
        access_key=access_key,
        secret_key=secret_key,
        backup_streams=str(target['backup_streams']),
        compression=target['compression'],
        capacity_bytes=target['capacity_bytes']
    )
    
    if not result or result['status'] != 'OK':
        raise ValueError("Failed to configure HYCU target")
        
    deployment_state['target_configured'] = True
    logging.info("HYCU Target configured successfully")


def validate_infrastructure(config: Dict, pc_username: str, pc_password: str, 
                          pe_username: str, pe_password: str) -> ValidationResult:
    """Validate all configuration values against actual infrastructure"""
    validation = ValidationResult()
    pc = config['prism_central']
    pe = config['prism_element']
    obj_store = config['object_store']
    hycu = config['hycu_controller']

    try:
        # Critical validations (ERRORS)
        logging.info(f"Validating cluster {pe['cluster_name']}...")
        clusters = get_cluster_list(pc['pc_ip'], pc_username, pc_password)
        cluster = next(
            (c for c in clusters['entities'] 
             if c['status']['name'] == pe['cluster_name']),
            None
        )
        
        if not cluster:
            validation.add_issue(
                f"Cluster '{pe['cluster_name']}' not found",
                ValidationSeverity.ERROR
            )

        # Network validation
        logging.info("Validating networks...")
        networks = get_network_list(pe['pe_ip'], pe_username, pe_password)
        storage_network = next(
            (n for n in networks['entities'] 
             if n['name'] == obj_store['storage_network']['network_name']),
            None
        )
        client_network = next(
            (n for n in networks['entities'] 
             if n['name'] == obj_store['client_network']['network_name']),
            None
        )

        if not storage_network:
            validation.add_issue(
                f"Storage network '{obj_store['storage_network']['network_name']}' not found",
                ValidationSeverity.ERROR
            )
        if not client_network:
            validation.add_issue(
                f"Client network '{obj_store['client_network']['network_name']}' not found",
                ValidationSeverity.ERROR
            )

        # Storage container validation
        logging.info("Validating storage container...")
        containers = get_storage_containers(pe['pe_ip'], pe_username, pe_password)
        container = next(
            (c for c in containers if c[0] == hycu['storage_container']),
            None
        )
        
        if not container:
            validation.add_issue(
                f"Storage container '{hycu['storage_container']}' not found",
                ValidationSeverity.ERROR
            )

        # Image validation
        logging.info("Validating HYCU image...")
        images = get_images(pe['pe_ip'], pe_username, pe_password)
        image = next(
            (i for i in images if i[0] == hycu['image_name']),
            None
        )
        
        if not image:
            validation.add_issue(
                f"HYCU image '{hycu['image_name']}' not found",
                ValidationSeverity.ERROR
            )

        # Non-critical validations (WARNINGS)
        logging.info("Checking DNS resolution...")
        if not is_dns_resolvable(obj_store['storage_network']['dns']):
            validation.add_issue(
                f"DNS server {obj_store['storage_network']['dns']} is not reachable. "
                "Deployment can continue but DNS functionality might be affected.",
                ValidationSeverity.WARNING
            )

    except Exception as e:
        validation.add_issue(f"Validation error: {str(e)}", ValidationSeverity.ERROR)

    return validation


def handle_validation_results(validation: ValidationResult, config: Dict) -> bool:
    """Handle validation results and provide user options"""
    if not validation.has_errors and not validation.has_warnings:
        return True

    print("\nConfiguration validation results:")
    
    if validation.has_errors:
        print("\nErrors (must be fixed to proceed):")
        for issue in validation.issues:
            if issue["severity"] == ValidationSeverity.ERROR:
                print(f"- {issue['message']}")

    if validation.has_warnings:
        print("\nWarnings (can proceed but review recommended):")
        for issue in validation.issues:
            if issue["severity"] == ValidationSeverity.WARNING:
                print(f"- {issue['message']}")

    if validation.has_errors:
        print("\nPlease fix the configuration errors and run the script again.")
        choice = input("Would you like to see the current configuration? (y/n): ")
        if choice.lower() == 'y':
            print("\nCurrent configuration:")
            print(yaml.dump(config, default_flow_style=False))
        return False
    
    if validation.has_warnings:
        while True:
            choice = input("\nWarnings exist. Would you like to:\n"
                         "1. Proceed with deployment\n"
                         "2. Exit to fix warnings\n"
                         "Choice (1-2): ")
            if choice == "1":
                return True
            elif choice == "2":
                return False
            print("Invalid choice. Please try again.")

    return True


def validate_credentials(pc_ip: str, pe_ip: str, max_attempts: int = 3) -> tuple:
    """Validate PC and PE credentials with retry logic"""
    pc_password = None
    pe_password = None
    
    # Validate PC credentials
    for attempt in range(max_attempts):
        try:
            pc_password = getpass(f"\nEnter password for PC ({pc_ip}) [admin]: ")
            logging.info(f"Validating PC credentials (Attempt {attempt + 1}/{max_attempts})...")
            
            response = get_cluster_list(pc_ip, "admin", pc_password)
            if response:
                logging.info("PC credentials validated successfully")
                break
            else:
                logging.error("Invalid PC credentials")
        except Exception as e:
            remaining = max_attempts - attempt - 1
            logging.error(f"PC authentication failed. {remaining} attempts remaining")
            if remaining == 0:
                raise ValueError("Maximum PC authentication attempts exceeded")
            continue

    # Validate PE credentials
    for attempt in range(max_attempts):
        try:
            pe_password = getpass(f"\nEnter password for PE ({pe_ip}) [admin]: ")
            logging.info(f"Validating PE credentials (Attempt {attempt + 1}/{max_attempts})...")
            
            response = get_cluster_details(pe_ip, "admin", pe_password)
            if response:
                logging.info("PE credentials validated successfully")
                break
            else:
                logging.error("Invalid PE credentials")
        except Exception as e:
            remaining = max_attempts - attempt - 1
            logging.error(f"PE authentication failed. {remaining} attempts remaining")
            if remaining == 0:
                raise ValueError("Maximum PE authentication attempts exceeded")
            continue
    
    if pc_password and pe_password:
        return pc_password, pe_password
    else:
        raise ValueError("Failed to validate credentials")


def get_initial_deployment_choice() -> str:
    """Get user's choice for initial deployment approach"""
    print("\nChoose deployment approach:")
    print("1. Execute all steps automatically (Zero-touch deployment)")
    print("2. Execute steps individually (Interactive deployment)")
    
    while True:
        choice = input("\nSelect approach (1-2): ")
        if choice in ['1', '2']:
            return choice
        print("Invalid choice. Please try again.")


def deploy_infrastructure(config: Dict, pc_password: str, pe_password: str) -> bool:
    """Deploy complete HYCU infrastructure"""
    try:
        pc = config['prism_central']
        pe = config['prism_element']
        
        # Update the config with the validated passwords
        pc['username'] = 'admin'
        pc['password'] = pc_password
        pe['username'] = 'admin'
        pe['password'] = pe_password

        # Validate infrastructure first
        logging.info("Validating infrastructure configuration...")
        validation_results = validate_infrastructure(
            config,
            'admin',
            pc_password,
            'admin',
            pe_password
        )

        if not handle_validation_results(validation_results, config):
            return False

        # Get client network for reuse
        networks = get_network_list(pe['pe_ip'], pe['username'], pe['password'])
        client_network = next(
            (n for n in networks['entities'] 
             if n['name'] == config['object_store']['client_network']['network_name']),
            None
        )
        
        if not client_network:
            raise ValueError("Required client network not found")

        # Track deployment state
        deployment_state = {
            'lcm_configured': False,
            'objectstore_deployed': False,
            'hycu_controller_deployed': False,
            'target_configured': False,
            'objectstore_uuid': None,
            'target_access_key': None,
            'target_secret_key': None
        }

        # Get initial deployment choice
        initial_choice = get_initial_deployment_choice()

        if initial_choice == '1':
            # Zero-touch deployment
            try:
                logging.info("Starting zero-touch deployment...")
                deploy_step_lcm(config, deployment_state)
                deploy_step_objectstore(config, deployment_state)
                deploy_step_hycu_controller(config, deployment_state, client_network)
                deploy_step_hycu_target(config, deployment_state)
                
                logging.info("Zero-touch deployment completed successfully!")
                return True

            except Exception as e:
                logging.error(f"Error during zero-touch deployment: {str(e)}")
                logging.info("Switching to interactive menu mode for error recovery...")
                
        # Either interactive mode was chosen or zero-touch failed
        # Enter menu-driven mode
        while True:
            # Check if all steps are complete
            if all([
                deployment_state['lcm_configured'],
                deployment_state['objectstore_deployed'],
                deployment_state['hycu_controller_deployed'],
                deployment_state['target_configured']
            ]):
                logging.info("All deployment steps completed successfully!")
                return True

            choice = show_deployment_menu()

            if choice == '5':
                logging.info("Deployment exited by user")
                return False

            try:
                if choice == '1':
                    deploy_step_lcm(config, deployment_state)
                elif choice == '2':
                    deploy_step_objectstore(config, deployment_state)
                elif choice == '3':
                    deploy_step_hycu_controller(config, deployment_state, client_network)
                elif choice == '4':
                    deploy_step_hycu_target(config, deployment_state)

            except Exception as e:
                logging.error(f"Error during step {choice}: {str(e)}")
                print(f"\nError during step {choice}:")
                print(f"Error details: {str(e)}")
                print("\nYou can retry this step or choose another step from the menu.")
                continue

    except Exception as e:
        logging.error(f"Deployment failed: {str(e)}")
        return False


def load_and_validate_config(config_file: str) -> dict:
    """Load and perform basic validation of config file"""
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
        
    required_sections = [
        'prism_central',
        'prism_element',
        'object_store', 
        'hycu_controller',
        'hycu_target'
    ]
    
    for section in required_sections:
        if section not in config:
            raise ValueError(f"Missing required section: {section}")
            
    # Validate new required fields
    if 'capacity_bytes' not in config['hycu_target']:
        raise ValueError("Missing capacity_bytes in hycu_target configuration")
        
    # Validate network name fields
    if 'network_name' not in config['object_store']['storage_network']:
        raise ValueError("Missing network_name in storage_network configuration")
    if 'network_name' not in config['object_store']['client_network']:
        raise ValueError("Missing network_name in client_network configuration")
            
    return config


def main():
    try:
        parser = argparse.ArgumentParser(description='HYCU Installation Script')
        parser.add_argument('--pc-ip', help='Prism Central IP address')
        parser.add_argument('--pe-ip', help='Prism Element IP address')
        args = parser.parse_args()

        # Initialize config selector
        selector = ConfigSelector()
        
        try:
            # Select configuration file
            config_file = selector.select_config(args.pc_ip, args.pe_ip)
        except Exception as e:
            error_info = traceback.format_exc()
            logging.error(f"Error selecting configuration:\n{error_info}")
            print(f"\nError selecting configuration: {str(e)}")
            print(error_info)
            sys.exit(1)
        
        try:
            # Load and validate configuration
            config = load_and_validate_config(config_file)
        except Exception as e:
            error_info = traceback.format_exc()
            logging.error(f"Error in configuration validation:\n{error_info}")
            print(f"\nConfiguration validation error: {str(e)}")
            print(error_info)
            sys.exit(1)
        
        logging.info(f"Using configuration: {os.path.basename(config_file)}")
        
        try:
            # Validate credentials
            pc_password, pe_password = validate_credentials(
                config['prism_central']['pc_ip'],
                config['prism_element']['pe_ip']
            )
        except Exception as e:
            error_info = traceback.format_exc()
            logging.error(f"Error validating credentials:\n{error_info}")
            print(f"\nCredential validation error: {str(e)}")
            print(error_info)
            sys.exit(1)
        
        # Deploy infrastructure with validated credentials
        if deploy_infrastructure(config, pc_password, pe_password):
            logging.info("Deployment completed successfully!")
        else:
            print("\nDeployment incomplete. You can:")
            print("1. Review the log file for details")
            print("2. Fix any issues and run the script again")
            print("3. Contact support if you need assistance")
            sys.exit(1)
            
    except Exception as e:
        error_info = traceback.format_exc()
        logging.error(f"Unhandled error in main:\n{error_info}")
        print(f"\nUnhandled error: {str(e)}")
        print("\nStack trace:")
        print(error_info)
        sys.exit(1)


if __name__ == "__main__":
    main()