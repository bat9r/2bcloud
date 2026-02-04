import boto3
import requests
import yaml
import subprocess
import sys
import logging
import ipaddress
import argparse

# Configuration
TARGET_PUBLIC_IP = "34.254.140.195"
CLOUDFLARE_IPS_URL = "https://www.cloudflare.com/ips-v4"
YAML_FILE = "security-group.yaml"

# Logging Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

def get_public_ip():
    """Fetches the current machine's public IP."""
    try:
        response = requests.get('https://checkip.amazonaws.com', timeout=5)
        response.raise_for_status()
        ip = response.text.strip()
        logger.info(f"Detected Home IP: {ip}")
        return ip
    except requests.RequestException as e:
        logger.error(f"Failed to get public IP: {e}")
        sys.exit(1)

def get_cloudflare_ips():
    """Fetches Cloudflare IPv4 ranges."""
    try:
        response = requests.get(CLOUDFLARE_IPS_URL, timeout=5)
        response.raise_for_status()
        ips = [line.strip() for line in response.text.splitlines() if line.strip()]
        logger.info(f"Fetched {len(ips)} Cloudflare IP ranges.")
        return ips
    except requests.RequestException as e:
        logger.error(f"Failed to get Cloudflare IPs: {e}")
        sys.exit(1)

def find_instance(target_ip):
    """Finds the EC2 instance by Public IP across all enabled regions."""
    logger.info(f"Searching for instance with Public IP: {target_ip}...")
    
    # Create a session to list regions
    try:
        session = boto3.Session()
        # We need to find an available region to list all regions first
        # Usually us-east-1 is available, or use the default configured one
        ec2_client = session.client('ec2') 
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    except Exception as e:
        logger.error(f"Failed to list regions: {e}")
        sys.exit(1)

    for region in regions:
        try:
            client = session.client('ec2', region_name=region)
            response = client.describe_instances(
                Filters=[{'Name': 'ip-address', 'Values': [target_ip]}]
            )
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] not in ['terminated', 'shutting-down']:
                        sg_id = instance['SecurityGroups'][0]['GroupId'] # Assuming primary SG
                        logger.info(f"Found instance {instance['InstanceId']} in {region} with SG {sg_id}")
                        return region, sg_id
        except Exception as e:
            logger.warning(f"Error checking region {region}: {e}")
            continue

    logger.error(f"Instance with IP {target_ip} not found.")
    sys.exit(1)

def sync_security_group(region, sg_id, allowed_cidrs):
    """Syncs the Security Group rules."""
    ec2 = boto3.resource('ec2', region_name=region)
    sg = ec2.SecurityGroup(sg_id)

    logger.info(f"Syncing Security Group {sg_id}...")
    
    # Current Rules
    current_http_cidrs = set()
    current_ssh_cidrs = set()
    
    # Analyze existing rules
    # We need to revoke rules that don't match our criteria
    # Criteria:
    # - Port 22 (SSH): 0.0.0.0/0 (Keep/Ensure)
    # - Port 80 (HTTP): allowed_cidrs (Sync)
    
    # Permissions to revoke
    revoke_permissions = []
    
    for permission in sg.ip_permissions:
        from_port = permission.get('FromPort')
        to_port = permission.get('ToPort')
        ip_protocol = permission.get('IpProtocol')
        
        if ip_protocol == '-1': # All traffic
             revoke_permissions.append(permission)
             continue

        for ip_range in permission.get('IpRanges', []):
            cidr = ip_range['CidrIp']
            
            if from_port == 22 and to_port == 22 and ip_protocol == 'tcp':
                if cidr == '0.0.0.0/0':
                    current_ssh_cidrs.add(cidr)
                else:
                    pass 
            elif from_port == 80 and to_port == 80 and ip_protocol == 'tcp':
                current_http_cidrs.add(cidr)
            else:
                pass

    # Revoke stale HTTP rules
    http_to_revoke = current_http_cidrs - set(allowed_cidrs)
    if http_to_revoke:
        logger.info(f"Revoking {len(http_to_revoke)} stale HTTP rules...")
        sg.revoke_ingress(IpPermissions=[{
            'IpProtocol': 'tcp',
            'FromPort': 80,
            'ToPort': 80,
            'IpRanges': [{'CidrIp': cidr} for cidr in http_to_revoke]
        }])

    # Authorize missing HTTP rules
    http_to_add = set(allowed_cidrs) - current_http_cidrs
    if http_to_add:
        logger.info(f"Authorizing {len(http_to_add)} new HTTP rules...")
        sg.authorize_ingress(IpPermissions=[{
            'IpProtocol': 'tcp',
            'FromPort': 80,
            'ToPort': 80,
            'IpRanges': [{'CidrIp': cidr} for cidr in http_to_add]
        }])
        
    # Ensure SSH 0.0.0.0/0
    if '0.0.0.0/0' not in current_ssh_cidrs:
        logger.info("Authorizing SSH 0.0.0.0/0...")
        sg.authorize_ingress(IpPermissions=[{
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }])

    # Final Rule Count
    sg.reload()
    final_rules = len(sg.ip_permissions)
    logger.info(f"Security Group sync complete. Final rule count: {final_rules}")
    return len(allowed_cidrs)

def update_yaml(allowed_cidrs):
    """Updates the local YAML file."""
    logger.info("Updating YAML file...")
    
    with open(YAML_FILE, 'r') as f:
        data = yaml.safe_load(f)
    
    # Update rules
    # Sort and de-duplicate
    sorted_cidrs = sorted(list(set(allowed_cidrs)))
    
    # Reconstruct data to match structure
    if 'rules' not in data:
        data['rules'] = {}
    
    data['rules']['http'] = sorted_cidrs
    # Ensure SSH is correct in YAML too
    data['rules']['ssh'] = ['0.0.0.0/0']
    
    with open(YAML_FILE, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    logger.info("YAML file updated.")

def git_commit_push():
    """Commits and pushes changes to Git."""
    try:
        # Check for changes
        status = subprocess.check_output(['git', 'status', '--porcelain']).decode('utf-8')
        if not status:
            logger.info("No changes to commit.")
            return

        logger.info("Committing and pushing changes...")
        subprocess.check_call(['git', 'add', YAML_FILE])
        subprocess.check_call(['git', 'commit', '-m', 'Update Security Group rules via automation script'])
        subprocess.check_call(['git', 'push'])
        logger.info("Changes pushed to repository.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Git operation failed: {e}")
        # Don't exit, just log error as script logic finished

def main():
    parser = argparse.ArgumentParser(description='Sync EC2 Security Group with Cloudflare and Home IP.')
    parser.add_argument('--local-only', action='store_true', help='Skip AWS calls and only update local YAML')
    parser.add_argument('--target-ip', type=str, help='Override the target EC2 Public IP', default=TARGET_PUBLIC_IP)
    args = parser.parse_args()

    home_ip = get_public_ip()
    cloudflare_ips = get_cloudflare_ips()
    
    # Combine IPs for HTTP
    # Requirement: "your current home IP /32 and all Cloudflare IP ranges"
    http_cidrs = [f"{home_ip}/32"] + cloudflare_ips
    
    if args.local_only:
        logger.info("Running in LOCAL ONLY mode. Skipping AWS sync.")
    else:
        target_ip = args.target_ip
        logger.info(f"Targeting EC2 Instance with IP: {target_ip}")
        region, sg_id = find_instance(target_ip)
        sync_security_group(region, sg_id, http_cidrs)
    
    update_yaml(http_cidrs)
    
    # Only push if we are confident (maybe skipping push in local-only if not desired, but task says update repo)
    # I'll keep it enabled.
    git_commit_push()

if __name__ == "__main__":
    main()
