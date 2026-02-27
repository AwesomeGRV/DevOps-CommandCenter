#!/bin/bash

# AWS Idle EC2 Detection Script
# Author: CloudOps-SRE-Toolkit
# Description: Detects idle EC2 instances for cost optimization

set -euo pipefail

# Configuration
LOG_FILE="aws_idle_ec2_$(date +%Y%m%d_%H%M%S).log"
OUTPUT_FILE="aws_idle_ec2_$(date +%Y%m%d_%H%M%S).json"
REGIONS=${REGIONS:-"us-east-1,us-west-2,eu-west-1"}
IDLE_DAYS=${IDLE_DAYS:-7}
CPU_THRESHOLD=${CPU_THRESHOLD:-5}  # CPU utilization percentage threshold
NETWORK_THRESHOLD=${NETWORK_THRESHOLD:-100}  # KB threshold

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Check if AWS CLI is installed and configured
check_dependencies() {
    if ! command -v aws &> /dev/null; then
        log "${RED}ERROR: AWS CLI is not installed. Please install it first.${NC}"
        exit 1
    fi
    
    if ! aws sts get-caller-identity &> /dev/null; then
        log "${RED}ERROR: AWS CLI is not configured. Please run 'aws configure' first.${NC}"
        exit 1
    fi
    
    log "${GREEN}AWS CLI is installed and configured.${NC}"
}

# Get EC2 instances with low CPU utilization
get_low_cpu_instances() {
    local region=$1
    local end_time=$(date -u +"%Y-%m-%dT%H:%M:%S")
    local start_time=$(date -d "$IDLE_DAYS days ago" -u +"%Y-%m-%dT%H:%M:%S")
    
    log "Checking instances in region: $region"
    
    # Get all running instances
    local instances=$(aws ec2 describe-instances \
        --region "$region" \
        --filters "Name=instance-state-name,Values=running" \
        --query 'Reservations[].Instances[].[InstanceId,InstanceType,Tags[?Key==`Name`].Value|[0],LaunchTime]' \
        --output json 2>/dev/null || echo "[]")
    
    if [[ "$instances" == "[]" ]]; then
        log "No running instances found in $region"
        echo "[]"
        return
    fi
    
    # Get CloudWatch metrics for each instance
    echo "$instances" | jq -c '.[]' | while read -r instance; do
        local instance_id=$(echo "$instance" | jq -r '.[0]')
        local instance_type=$(echo "$instance" | jq -r '.[1]')
        local instance_name=$(echo "$instance" | jq -r '.[2]')
        local launch_time=$(echo "$instance" | jq -r '.[3]')
        
        # Skip instances launched within the idle period
        if [[ $(date -d "$launch_time" +%s) -gt $(date -d "$IDLE_DAYS days ago" +%s) ]]; then
            continue
        fi
        
        # Get CPU utilization
        local cpu_util=$(aws cloudwatch get-metric-statistics \
            --region "$region" \
            --namespace AWS/EC2 \
            --metric-name CPUUtilization \
            --dimensions Name=InstanceId,Value="$instance_id" \
            --statistics Average \
            --start-time "$start_time" \
            --end-time "$end_time" \
            --period 3600 \
            --query 'Datapoints[0].Average' \
            --output json 2>/dev/null || echo "null")
        
        # Get network I/O
        local network_in=$(aws cloudwatch get-metric-statistics \
            --region "$region" \
            --namespace AWS/EC2 \
            --metric-name NetworkIn \
            --dimensions Name=InstanceId,Value="$instance_id" \
            --statistics Sum \
            --start-time "$start_time" \
            --end-time "$end_time" \
            --period 3600 \
            --query 'Datapoints | sort_by(@, &Timestamp) | [-1].Sum' \
            --output json 2>/dev/null || echo "null")
        
        local network_out=$(aws cloudwatch get-metric-statistics \
            --region "$region" \
            --namespace AWS/EC2 \
            --metric-name NetworkOut \
            --dimensions Name=InstanceId,Value="$instance_id" \
            --statistics Sum \
            --start-time "$start_time" \
            --end-time "$end_time" \
            --period 3600 \
            --query 'Datapoints | sort_by(@, &Timestamp) | [-1].Sum' \
            --output json 2>/dev/null || echo "null")
        
        # Check if instance is idle
        local is_idle=false
        local reason=""
        
        if [[ "$cpu_util" != "null" && $(echo "$cpu_util < $CPU_THRESHOLD" | bc -l) -eq 1 ]]; then
            is_idle=true
            reason="Low CPU utilization: ${cpu_util}%"
        fi
        
        if [[ "$network_in" != "null" && $(echo "$network_in < $NETWORK_THRESHOLD" | bc -l) -eq 1 && 
              "$network_out" != "null" && $(echo "$network_out < $NETWORK_THRESHOLD" | bc -l) -eq 1 ]]; then
            is_idle=true
            reason="Low network I/O: In=${network_in}KB, Out=${network_out}KB"
        fi
        
        if [[ "$is_idle" == "true" ]]; then
            jq -n \
                --arg instance_id "$instance_id" \
                --arg instance_type "$instance_type" \
                --arg instance_name "$instance_name" \
                --arg region "$region" \
                --arg cpu_util "${cpu_util}%" \
                --arg network_in "${network_in}KB" \
                --arg network_out "${network_out}KB" \
                --arg reason "$reason" \
                --arg launch_time "$launch_time" \
                '{
                    instance_id: $instance_id,
                    instance_type: $instance_type,
                    name: $instance_name,
                    region: $region,
                    cpu_utilization: $cpu_util,
                    network_in: $network_in,
                    network_out: $network_out,
                    idle_reason: $reason,
                    launch_time: $launch_time
                }'
        fi
    done
}

# Get stopped instances that could be terminated
get_stopped_instances() {
    local region=$1
    local days_stopped_threshold=30
    
    log "Checking stopped instances in region: $region"
    
    local stopped_instances=$(aws ec2 describe-instances \
        --region "$region" \
        --filters "Name=instance-state-name,Values=stopped" \
        --query 'Reservations[].Instances[].[InstanceId,InstanceType,Tags[?Key==`Name`].Value|[0],StateTransitionReason]' \
        --output json 2>/dev/null || echo "[]")
    
    echo "$stopped_instances" | jq -c '.[]' | while read -r instance; do
        local instance_id=$(echo "$instance" | jq -r '.[0]')
        local instance_type=$(echo "$instance" | jq -r '.[1]')
        local instance_name=$(echo "$instance" | jq -r '.[2]')
        local state_reason=$(echo "$instance" | jq -r '.[3]')
        
        # Extract stop time from state reason
        local stop_time=$(echo "$state_reason" | grep -oP '\(\K[^)]+' | head -1 || echo "")
        
        if [[ -n "$stop_time" ]]; then
            local stop_timestamp=$(date -d "$stop_time" +%s 2>/dev/null || echo 0)
            local current_timestamp=$(date +%s)
            local days_stopped=$(( (current_timestamp - stop_timestamp) / 86400 ))
            
            if [[ $days_stopped -gt $days_stopped_threshold ]]; then
                jq -n \
                    --arg instance_id "$instance_id" \
                    --arg instance_type "$instance_type" \
                    --arg instance_name "$instance_name" \
                    --arg region "$region" \
                    --arg days_stopped "$days_stopped" \
                    --arg stop_time "$stop_time" \
                    '{
                        instance_id: $instance_id,
                        instance_type: $instance_type,
                        name: $instance_name,
                        region: $region,
                        days_stopped: ($days_stopped | tonumber),
                        stop_time: $stop_time,
                        recommendation: "Consider terminating"
                    }'
            fi
        fi
    done
}

# Calculate potential savings
calculate_savings() {
    local idle_instances=$1
    local stopped_instances=$2
    
    log "${GREEN}Calculating potential cost savings...${NC}"
    
    # Approximate monthly costs (adjust based on your region and pricing)
    declare -A instance_costs=(
        ["t2.micro"]=8.5
        ["t2.small"]=17
        ["t2.medium"]=34
        ["t3.micro"]=8.5
        ["t3.small"]=17
        ["t3.medium"]=34
        ["m5.large"]=96
        ["m5.xlarge"]=192
        ["c5.large"]=85
        ["c5.xlarge"]=170
        ["r5.large"]=126
        ["r5.xlarge"]=252
    )
    
    local total_savings=0
    
    # Calculate savings from idle instances
    echo "$idle_instances" | jq -c '.[]' 2>/dev/null | while read -r instance; do
        local instance_type=$(echo "$instance" | jq -r '.instance_type')
        local cost=${instance_costs[$instance_type]:-50}  # Default cost if not found
        total_savings=$((total_savings + cost))
    done
    
    # Calculate savings from stopped instances
    echo "$stopped_instances" | jq -c '.[]' 2>/dev/null | while read -r instance; do
        local instance_type=$(echo "$instance" | jq -r '.instance_type')
        local cost=${instance_costs[$instance_type]:-50}
        total_savings=$((total_savings + cost))
    done
    
    log "${GREEN}Potential monthly savings: \$$total_savings${NC}"
}

# Main execution
main() {
    log "${GREEN}Starting AWS Idle EC2 Detection...${NC}"
    log "Log file: $LOG_FILE"
    log "Output file: $OUTPUT_FILE"
    log "Regions: $REGIONS"
    log "Idle threshold: $IDLE_DAYS days"
    
    check_dependencies
    
    # Initialize JSON arrays
    local all_idle_instances="[]"
    local all_stopped_instances="[]"
    
    # Process each region
    IFS=',' read -ra REGIONS_ARRAY <<< "$REGIONS"
    for region in "${REGIONS_ARRAY[@]}"; do
        log "Processing region: $region"
        
        local idle_instances=$(get_low_cpu_instances "$region")
        local stopped_instances=$(get_stopped_instances "$region")
        
        # Add to global arrays
        all_idle_instances=$(echo "$all_idle_instances" | jq --argjson new "$idle_instances" '. + $new')
        all_stopped_instances=$(echo "$all_stopped_instances" | jq --argjson new "$stopped_instances" '. + $new')
    done
    
    # Create final JSON output
    jq -n \
        --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --argjson idle_instances "$all_idle_instances" \
        --argjson stopped_instances "$all_stopped_instances" \
        --arg idle_days "$IDLE_DAYS" \
        --arg cpu_threshold "$CPU_THRESHOLD" \
        '{
            timestamp: $timestamp,
            scan_parameters: {
                idle_days: ($idle_days | tonumber),
                cpu_threshold: ($cpu_threshold | tonumber),
                regions: env.REGIONS | split(",")
            },
            idle_instances: $idle_instances,
            stopped_instances: $stopped_instances,
            summary: {
                total_idle_instances: ($idle_instances | length),
                total_stopped_instances: ($stopped_instances | length)
            }
        }' > "$OUTPUT_FILE"
    
    # Calculate and display savings
    calculate_savings "$all_idle_instances" "$all_stopped_instances"
    
    log "${GREEN}Analysis completed successfully!${NC}"
    log "Results saved to: $OUTPUT_FILE"
    log "Logs saved to: $LOG_FILE"
}

# Execute main function
main "$@"
