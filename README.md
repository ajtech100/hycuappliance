# HYCU Deployment Script Documentation

## Table of Contents
- [Overview](#overview)
- [Directory Structure](#directory-structure)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Usage](#usage)
- [Deployment Steps](#deployment-steps)
- [Error Handling](#error-handling)
- [Troubleshooting](#troubleshooting)

## Overview

This script automates the deployment of HYCU backup appliance in a Nutanix environment. It handles the complete deployment process including LCM darksite configuration, Object Store deployment, HYCU Controller setup, and HYCU target configuration.

## Directory Structure

Place .py and .yaml files in the directory structure as below.

```
hycu-deployment/
├── main.py                 # Main deployment script
├── config/                     # Configuration files directory
│   └── <env>-<pc>_<pe>-hycu-config.yaml  # Environment-specific configs
└── Modules/                    # Individual functionality modules
    ├── lcm_config_get.py      # LCM configuration retrieval
    ├── lcm_config_update.py   # LCM configuration updates
    ├── save_objectstore.py    # Object store configuration
    ├── deploy_objectstore.py  # Object store deployment
    ├── create_hycuvm.py      # HYCU VM creation
    └── ... (other module files)
```

## Prerequisites

1. Python 3.6 or higher
2. Required Python packages:
   - PyYAML
   - urllib3
   - typing
   - logging

3. Network access to:
   - Prism Central
   - Prism Element
   - DNS Server
   - LCM Darksite URL

4. Required infrastructure:
   - Nutanix cluster with sufficient resources
   - Prism Central with Objects enabled 
   - Darksite webserver with LCM, Objects and MSP binaries 
   - AHV IPAM subnets for Objects storage and client networks
   - HYCU image uploaded to Prism Element
   - Storage container for HYCU VM

## Configuration

Configuration files follow the naming convention:
```
<environment>-<pc_name>_<pe_name>-hycu-config.yaml
```
Example: `Ins1-PC10_PE10-hycu-config.yaml`

### Configuration Sections

1. **Prism Central (`prism_central`)**
   ```yaml
   prism_central:
     darksite_url: http://10.10.74.161/release/
     pc_domain: prism-central.cluster.local
     pc_ip: 10.10.72.110
   ```

2. **Prism Element (`prism_element`)**
   ```yaml
   prism_element:
     pe_ip: 10.10.72.208
     cluster_name: irv-ntx-hyob
   ```

3. **Object Store (`object_store`)**
   ```yaml
   object_store:
     name: HycuDemo
     num_worker_nodes: 3
     client_network:
       network_name: 74-IPAM
       ips:
         - 10.10.74.116  # First IP for client network. Minimum two IPs for client network
         - 10.10.74.115  # Second IP for client network. Minimum two IPs for client network
     storage_network:
       network_name: 72-IPAM
       dns: 10.10.72.115  # This is first IP for storage network, not actual dns server IP
       vip: 10.10.72.116  # This is second IP for storage network 
   ```

4. **HYCU Controller (`hycu_controller`)**
   ```yaml
   hycu_controller:
     vm_name: hycudemo
     hostname: hycudemo
     image_name: hycu.qcow2
     storage_container: hycu-container
     ip: 10.10.74.118
     subnet_prefix: '24'
     gateway: 10.10.74.1
     dns_server: 8.8.8.8
     domain: techlab.com
     credentials:
       username: admin
       password: admin
   ```

5. **HYCU Target (`hycu_target`)**
   ```yaml
   hycu_target:
     target_name: nutanixbucket
     bucket_name: hycutarget
     backup_streams: 3
     compression: true
     capacity_bytes: 5497558138880
     user_name: localuser
     user_email: localuser@hycuappl.com
     user_accesskey: xxx  # Required for existing users, remove comment from config file
     user_secretkey: xxx  # Required for existing users, remove comment from config file
   ```

## Usage

1. **Basic Usage**
   ```bash
   python main.py
   ```

## Deployment Steps

The script offers two deployment approaches:

1. **Zero-touch Deployment**
   - Executes all steps automatically
   - Best for fresh deployments
   - Provides continuous feedback

2. **Interactive Deployment**
   - Executes steps individually
   - Better for troubleshooting
   - Allows selective execution

### Deployment Phases

1. **LCM Configuration**
   - Configures LCM darksite
   - Updates LCM configuration
   - Validates changes

2. **Object Store Deployment**
   - Validates network configuration
   - Configures storage and client networks
   - Deploys object store 

3. **HYCU Controller Deployment**
   - Creates HYCU VM
   - Configures networking
   - Validates VM accessibility

4. **HYCU Target Configuration**
   - Creates/validates bucket
   - Manages access keys
   - Configures backup target on HYCU

## Error Handling

The script includes comprehensive error handling:
- Validation of all prerequisites
- Credential verification with retry logic
- Network reachability checks
- Configuration validation
- Detailed error logging

### Log File
- Location: `hycu_deployment.log`
- Contains detailed deployment information
- Useful for troubleshooting

## Troubleshooting

Common issues and solutions:

1. **Network Connectivity**
   - Ensure all IPs are reachable
   - Verify DNS resolution
   - Check network configurations

2. **Authentication**
   - Verify PC/PE credentials
   - Check user permissions
   - Validate access keys

3. **Resource Issues**
   - Verify storage container space
   - Check cluster resources
   - Validate network availability

4. **Configuration Problems**
   - Verify YAML syntax
   - Check required fields
   - Validate network names

For additional support:
- Review log files
- Check network connectivity
- Verify infrastructure requirements
- Contact support if needed
