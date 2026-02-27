#!/bin/bash

# Azure Unused Resource Detection Script
# Author: CloudOps-SRE-Toolkit
# Description: Detects and reports unused Azure resources for cost optimization

set -euo pipefail

# Configuration
LOG_FILE="azure_unused_resources_$(date +%Y%m%d_%H%M%S).log"
OUTPUT_FILE="azure_unused_resources_$(date +%Y%m%d_%H%M%S).json"
RESOURCE_GROUPS=${RESOURCE_GROUPS:-""}
SUBSCRIPTION_ID=${SUBSCRIPTION_ID:-""}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Check if Azure CLI is installed
check_dependencies() {
    if ! command -v az &> /dev/null; then
        log "${RED}ERROR: Azure CLI is not installed. Please install it first.${NC}"
        exit 1
    fi
    
    if ! az account show &> /dev/null; then
        log "${RED}ERROR: Not logged into Azure. Please run 'az login' first.${NC}"
        exit 1
    fi
    
    log "${GREEN}Azure CLI is installed and authenticated.${NC}"
}

# Get unused VMs
get_unused_vms() {
    log "Checking for unused Virtual Machines..."
    
    local query="[?vmSize != null && powerState != 'VM running']"
    
    if [[ -n "$RESOURCE_GROUPS" ]]; then
        az vm list --resource-group "$RESOURCE_GROUPS" --query "$query" --output json 2>/dev/null || {
            log "${YELLOW}Warning: Could not retrieve VMs for resource group: $RESOURCE_GROUPS${NC}"
            return
        }
    else
        az vm list --query "$query" --output json 2>/dev/null
    fi
}

# Get unused Public IPs
get_unused_public_ips() {
    log "Checking for unused Public IP addresses..."
    
    local query="[?ipConfiguration == null]"
    
    if [[ -n "$RESOURCE_GROUPS" ]]; then
        az network public-ip list --resource-group "$RESOURCE_GROUPS" --query "$query" --output json 2>/dev/null || {
            log "${YELLOW}Warning: Could not retrieve Public IPs for resource group: $RESOURCE_GROUPS${NC}"
            return
        }
    else
        az network public-ip list --query "$query" --output json 2>/dev/null
    fi
}

# Get unused Storage Accounts
get_unused_storage_accounts() {
    log "Checking for unused Storage Accounts..."
    
    # Storage accounts with no activity in last 30 days
    local end_date=$(date -d "30 days ago" -u +"%Y-%m-%dT%H:%M:%SZ")
    
    if [[ -n "$RESOURCE_GROUPS" ]]; then
        az storage account list --resource-group "$RESOURCE_GROUPS" --output json 2>/dev/null | \
        jq '[.[] | select(.lastGeoFailoverTime < "'$end_date'" or .lastGeoFailoverTime == null)]' || {
            log "${YELLOW}Warning: Could not retrieve Storage Accounts for resource group: $RESOURCE_GROUPS${NC}"
            return
        }
    else
        az storage account list --output json 2>/dev/null | \
        jq '[.[] | select(.lastGeoFailoverTime < "'$end_date'" or .lastGeoFailoverTime == null)]'
    fi
}

# Get unused Disks
get_unused_disks() {
    log "Checking for unused Managed Disks..."
    
    local query="[?managedBy == null]"
    
    if [[ -n "$RESOURCE_GROUPS" ]]; then
        az disk list --resource-group "$RESOURCE_GROUPS" --query "$query" --output json 2>/dev/null || {
            log "${YELLOW}Warning: Could not retrieve Disks for resource group: $RESOURCE_GROUPS${NC}"
            return
        }
    else
        az disk list --query "$query" --output json 2>/dev/null
    fi
}

# Get unused NICs
get_unused_nics() {
    log "Checking for unused Network Interfaces..."
    
    local query="[?virtualMachine == null && !contains(name, 'asr')]"
    
    if [[ -n "$RESOURCE_GROUPS" ]]; then
        az network nic list --resource-group "$RESOURCE_GROUPS" --query "$query" --output json 2>/dev/null || {
            log "${YELLOW}Warning: Could not retrieve NICs for resource group: $RESOURCE_GROUPS${NC}"
            return
        }
    else
        az network nic list --query "$query" --output json 2>/dev/null
    fi
}

# Calculate potential savings
calculate_savings() {
    local unused_vms=$1
    local unused_pips=$2
    local unused_disks=$3
    
    log "${GREEN}Calculating potential cost savings...${NC}"
    
    # Approximate monthly costs (adjust based on your region and pricing)
    local vm_monthly_cost=50  # Average cost per VM
    local pip_monthly_cost=3   # Cost per Public IP
    local disk_monthly_cost=10 # Average cost per disk
    
    local vm_count=$(echo "$unused_vms" | jq '. | length' 2>/dev/null || echo 0)
    local pip_count=$(echo "$unused_pips" | jq '. | length' 2>/dev/null || echo 0)
    local disk_count=$(echo "$unused_disks" | jq '. | length' 2>/dev/null || echo 0)
    
    local total_savings=$((vm_count * vm_monthly_cost + pip_count * pip_monthly_cost + disk_count * disk_monthly_cost))
    
    log "${GREEN}Potential monthly savings: \$$total_savings${NC}"
    log "- Unused VMs: $vm_count (≈ \$$(($vm_count * vm_monthly_cost)))"
    log "- Unused Public IPs: $pip_count (≈ \$$(($pip_count * pip_monthly_cost)))"
    log "- Unused Disks: $disk_count (≈ \$$(($disk_count * disk_monthly_cost)))"
}

# Main execution
main() {
    log "${GREEN}Starting Azure Unused Resource Detection...${NC}"
    log "Log file: $LOG_FILE"
    log "Output file: $OUTPUT_FILE"
    
    check_dependencies
    
    # Collect unused resources
    local unused_vms=$(get_unused_vms)
    local unused_pips=$(get_unused_public_ips)
    local unused_storage=$(get_unused_storage_accounts)
    local unused_disks=$(get_unused_disks)
    local unused_nics=$(get_unused_nics)
    
    # Create JSON output
    jq -n \
        --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --argjson unused_vms "$(echo "$unused_vms" | jq 'if type == "string" then [] else . end')" \
        --argjson unused_pips "$(echo "$unused_pips" | jq 'if type == "string" then [] else . end')" \
        --argjson unused_storage "$(echo "$unused_storage" | jq 'if type == "string" then [] else . end')" \
        --argjson unused_disks "$(echo "$unused_disks" | jq 'if type == "string" then [] else . end')" \
        --argjson unused_nics "$(echo "$unused_nics" | jq 'if type == "string" then [] else . end')" \
        '{
            timestamp: $timestamp,
            subscription_id: env.SUBSCRIPTION_ID,
            resource_groups: env.RESOURCE_GROUPS,
            unused_resources: {
                virtual_machines: $unused_vms,
                public_ips: $unused_pips,
                storage_accounts: $unused_storage,
                managed_disks: $unused_disks,
                network_interfaces: $unused_nics
            }
        }' > "$OUTPUT_FILE"
    
    # Calculate and display savings
    calculate_savings "$unused_vms" "$unused_pips" "$unused_disks"
    
    log "${GREEN}Analysis completed successfully!${NC}"
    log "Results saved to: $OUTPUT_FILE"
    log "Logs saved to: $LOG_FILE"
}

# Execute main function
main "$@"
