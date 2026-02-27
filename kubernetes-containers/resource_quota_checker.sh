#!/bin/bash

# Kubernetes Resource Quota Checker
# Author: CloudOps-SRE-Toolkit
# Description: Check and analyze resource quotas across namespaces

set -euo pipefail

# Configuration
LOG_FILE="resource_quota_check_$(date +%Y%m%d_%H%M%S).log"
OUTPUT_FILE="resource_quota_report_$(date +%Y%m%d_%H%M%S).json"
NAMESPACE=${NAMESPACE:-"all"}
CONTEXT=${CONTEXT:-"current"}
WARNING_THRESHOLD=${WARNING_THRESHOLD:-80}  # Percentage threshold for warnings
CRITICAL_THRESHOLD=${CRITICAL_THRESHOLD:-95}  # Percentage threshold for critical alerts

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Check if kubectl is installed and configured
check_dependencies() {
    if ! command -v kubectl &> /dev/null; then
        log "${RED}ERROR: kubectl is not installed. Please install it first.${NC}"
        exit 1
    fi
    
    if ! kubectl cluster-info &> /dev/null; then
        log "${RED}ERROR: Cannot connect to Kubernetes cluster. Please check your kubeconfig.${NC}"
        exit 1
    fi
    
    log "${GREEN}kubectl is installed and connected to cluster.${NC}"
}

# Get resource quotas for namespace
get_resource_quotas() {
    local namespace=$1
    
    log "Getting resource quotas for namespace: $namespace"
    
    local namespace_arg=""
    if [[ "$namespace" != "all" ]]; then
        namespace_arg="-n $namespace"
    fi
    
    # Get ResourceQuota objects
    local quotas=$(kubectl get resourcequota $namespace_arg -o json 2>/dev/null | \
        jq -r '.items[] | {
            name: .metadata.name,
            namespace: .metadata.namespace,
            scopes: .spec.scopes // [],
            scope_selector: .spec.scope_selector // null,
            hard: .spec.hard // {},
            used: .status.used // {},
            creation_timestamp: .metadata.creationTimestamp
        }')
    
    if [[ -z "$quotas" || "$quotas" == "null" ]]; then
        log "${YELLOW}No resource quotas found in namespace: $namespace${NC}"
        echo "[]"
        return
    fi
    
    echo "$quotas" | jq -s '.'
}

# Get LimitRange objects for namespace
get_limit_ranges() {
    local namespace=$1
    
    log "Getting limit ranges for namespace: $namespace"
    
    local namespace_arg=""
    if [[ "$namespace" != "all" ]]; then
        namespace_arg="-n $namespace"
    fi
    
    local limit_ranges=$(kubectl get limitrange $namespace_arg -o json 2>/dev/null | \
        jq -r '.items[] | {
            name: .metadata.name,
            namespace: .metadata.namespace,
            limits: .spec.limits // [],
            creation_timestamp: .metadata.creationTimestamp
        }')
    
    if [[ -z "$limit_ranges" || "$limit_ranges" == "null" ]]; then
        echo "[]"
        return
    fi
    
    echo "$limit_ranges" | jq -s '.'
}

# Calculate resource usage percentages
calculate_usage_percentages() {
    local quota=$1
    
    local hard=$(echo "$quota" | jq '.hard')
    local used=$(echo "$quota" | jq '.used')
    
    # Calculate percentages for each resource type
    echo "$hard" | jq -r 'to_entries[] | .key' | while read -r resource; do
        local hard_value=$(echo "$hard" | jq -r ".[\"$resource\"]" | sed 's/[^0-9]//g' || echo "0")
        local used_value=$(echo "$used" | jq -r ".[\"$resource\"]" | sed 's/[^0-9]//g' || echo "0")
        
        if [[ "$hard_value" != "0" ]]; then
            local percentage=$(( (used_value * 100) / hard_value ))
            
            # Determine status
            local status="normal"
            if [[ $percentage -ge $CRITICAL_THRESHOLD ]]; then
                status="critical"
            elif [[ $percentage -ge $WARNING_THRESHOLD ]]; then
                status="warning"
            fi
            
            jq -n \
                --arg resource "$resource" \
                --arg hard "$(echo "$hard" | jq -r ".[\"$resource\"]")" \
                --arg used "$(echo "$used" | jq -r ".[\"$resource\"]")" \
                --argjson percentage "$percentage" \
                --arg status "$status" \
                '{
                    resource: $resource,
                    hard: $hard,
                    used: $used,
                    percentage: $percentage,
                    status: $status
                }'
        fi
    done | jq -s '.'
}

# Get actual resource usage from pods
get_actual_usage() {
    local namespace=$1
    
    log "Getting actual resource usage for namespace: $namespace"
    
    local namespace_arg=""
    if [[ "$namespace" != "all" ]]; then
        namespace_arg="-n $namespace"
    fi
    
    # Get pod resource requests and limits
    local pod_resources=$(kubectl get pods $namespace_arg -o json 2>/dev/null | \
        jq -r '.items[] | select(.status.phase == "Running") | {
            name: .metadata.name,
            namespace: .metadata.namespace,
            containers: [.spec.containers[] | select(.resources.requests or .resources.limits) | {
                name: .name,
                requests: .resources.requests // {},
                limits: .resources.limits // {}
            }]
        }')
    
    if [[ -z "$pod_resources" || "$pod_resources" == "null" ]]; then
        echo "{}"
        return
    fi
    
    # Aggregate resource usage
    echo "$pod_resources" | jq '
    reduce .[] as $pod ({};
        reduce $pod.containers[] as $container ({};
            .cpu_requests += ($container.requests.cpu // "0" | sub("[^0-9]"; ""; "g") | tonumber),
            .cpu_limits += ($container.limits.cpu // "0" | sub("[^0-9]"; ""; "g") | tonumber),
            .memory_requests += ($container.requests.memory // "0" | sub("[^0-9]"; ""; "g") | tonumber),
            .memory_limits += ($container.limits.memory // "0" | sub("[^0-9]"; ""; "g") | tonumber),
            .storage_requests += ($container.requests["ephemeral-storage"] // "0" | sub("[^0-9]"; ""; "g") | tonumber),
            .pod_count += 1
        )
    ) | {
        cpu_requests: .cpu_requests,
        cpu_limits: .cpu_limits,
        memory_requests: .memory_requests,
        memory_limits: .memory_limits,
        storage_requests: .storage_requests,
        pod_count: .pod_count
    }'
}

# Analyze quota compliance
analyze_quota_compliance() {
    local quotas=$1
    local actual_usage=$2
    
    log "Analyzing quota compliance..."
    
    echo "$quotas" | jq -c '.[]' | while read -r quota; do
        local quota_name=$(echo "$quota" | jq -r '.name')
        local namespace=$(echo "$quota" | jq -r '.namespace')
        
        log "Analyzing quota: $quota_name in namespace: $namespace"
        
        # Calculate usage percentages
        local usage_percentages=$(calculate_usage_percentages "$quota")
        
        # Get recommendations
        local recommendations=$(get_quota_recommendations "$quota" "$usage_percentages" "$actual_usage")
        
        jq -n \
            --arg quota_name "$quota_name" \
            --arg namespace "$namespace" \
            --argjson quota "$quota" \
            --argjson usage_percentages "$usage_percentages" \
            --argjson recommendations "$recommendations" \
            '{
                quota_name: $quota_name,
                namespace: $namespace,
                quota: $quota,
                usage_percentages: $usage_percentages,
                recommendations: $recommendations,
                compliance_status: ($usage_percentages | map(select(.status == "critical")) | length > 0 ? "critical" : 
                                   ($usage_percentages | map(select(.status == "warning")) | length > 0 ? "warning" : "compliant"))
            }'
    done | jq -s '.'
}

# Get quota recommendations
get_quota_recommendations() {
    local quota=$1
    local usage_percentages=$2
    local actual_usage=$3
    
    local recommendations=()
    
    # Check for critical resources
    echo "$usage_percentages" | jq -c '.[]' | while read -r usage; do
        local resource=$(echo "$usage" | jq -r '.resource')
        local percentage=$(echo "$usage" | jq -r '.percentage')
        local status=$(echo "$usage" | jq -r '.status')
        
        if [[ "$status" == "critical" ]]; then
            recommendations+=("CRITICAL: $resource usage at ${percentage}%. Consider increasing quota or optimizing resource usage.")
        elif [[ "$status" == "warning" ]]; then
            recommendations+=("WARNING: $resource usage at ${percentage}%. Monitor closely and plan quota increase.")
        fi
    done
    
    # Check for missing quotas
    local namespace=$(echo "$quota" | jq -r '.namespace')
    local has_cpu_quota=$(echo "$quota" | jq -r '.hard | keys | contains(["requests.cpu"])')
    local has_memory_quota=$(echo "$quota" | jq -r '.hard | keys | contains(["requests.memory"])')
    local has_pod_quota=$(echo "$quota" | jq -r '.hard | keys | contains(["pods"])')
    
    if [[ "$has_cpu_quota" == "false" ]]; then
        recommendations+=("Consider adding CPU quota to prevent resource exhaustion")
    fi
    
    if [[ "$has_memory_quota" == "false" ]]; then
        recommendations+=("Consider adding memory quota to prevent resource exhaustion")
    fi
    
    if [[ "$has_pod_quota" == "false" ]]; then
        recommendations+=("Consider adding pod quota to limit pod proliferation")
    fi
    
    printf '%s\n' "${recommendations[@]}" | jq -R . | jq -s .
}

# Generate quota summary
generate_quota_summary() {
    local compliance_analysis=$1
    
    log "Generating quota summary..."
    
    local total_quotas=$(echo "$compliance_analysis" | jq '. | length')
    local compliant_quotas=$(echo "$compliance_analysis" | jq 'map(select(.compliance_status == "compliant")) | length')
    local warning_quotas=$(echo "$compliance_analysis" | jq 'map(select(.compliance_status == "warning")) | length')
    local critical_quotas=$(echo "$compliance_analysis" | jq 'map(select(.compliance_status == "critical")) | length')
    
    jq -n \
        --argjson total_quotas "$total_quotas" \
        --argjson compliant_quotas "$compliant_quotas" \
        --argjson warning_quotas "$warning_quotas" \
        --argjson critical_quotas "$critical_quotas" \
        --arg compliance_percentage "$(echo "scale=2; $compliant_quotas * 100 / $total_quotas" | bc -l 2>/dev/null || echo "0")" \
        '{
            total_quotas: $total_quotas,
            compliant_quotas: $compliant_quotas,
            warning_quotas: $warning_quotas,
            critical_quotas: $critical_quotas,
            compliance_percentage: ($compliance_percentage | tonumber),
            status: if $critical_quotas > 0 then "critical" elif $warning_quotas > 0 then "warning" else "healthy" end
        }'
}

# Create alerts for critical issues
create_alerts() {
    local compliance_analysis=$1
    
    local critical_quotas=$(echo "$compliance_analysis" | jq '.[] | select(.compliance_status == "critical")')
    
    if [[ "$critical_quotas" != "" && "$critical_quotas" != "null" ]]; then
        local critical_count=$(echo "$critical_quotas" | jq '. | length')
        log "${RED}🚨 CRITICAL: $critical_count resource quotas with critical usage detected!${NC}"
        
        echo "$critical_quotas" | jq -c '.' | while read -r quota; do
            local quota_name=$(echo "$quota" | jq -r '.quota_name')
            local namespace=$(echo "$quota" | jq -r '.namespace')
            
            log "${RED}Critical quota: $quota_name in namespace: $namespace${NC}"
            
            # Show critical resources
            echo "$quota" | jq -r '.usage_percentages[] | select(.status == "critical") | 
                "  - \(.resource): \(.percentage)% (used: \(.used), hard: \(.hard))"'
        done
        
        # Here you could integrate with your alerting system
        # send_quota_alert "$critical_quotas"
    fi
}

# Get all namespaces
get_all_namespaces() {
    kubectl get namespaces -o json | jq -r '.items[] | select(.status.phase == "Active") | .metadata.name'
}

# Main execution
main() {
    log "${GREEN}Starting Kubernetes Resource Quota Checker...${NC}"
    log "Log file: $LOG_FILE"
    log "Output file: $OUTPUT_FILE"
    log "Namespace: $NAMESPACE"
    log "Warning threshold: $WARNING_THRESHOLD%"
    log "Critical threshold: $CRITICAL_THRESHOLD%"
    
    check_dependencies
    
    # Determine namespaces to check
    local namespaces=()
    if [[ "$NAMESPACE" == "all" ]]; then
        log "Getting all active namespaces..."
        mapfile -t namespaces < <(get_all_namespaces)
    else
        namespaces=("$NAMESPACE")
    fi
    
    log "Checking namespaces: ${namespaces[*]}"
    
    # Initialize results
    local all_quotas="[]"
    local all_limit_ranges="[]"
    local all_compliance_analysis="[]"
    
    # Process each namespace
    for namespace in "${namespaces[@]}"; do
        log "Processing namespace: $namespace"
        
        # Get quotas and limit ranges
        local namespace_quotas=$(get_resource_quotas "$namespace")
        local namespace_limit_ranges=$(get_limit_ranges "$namespace")
        local namespace_usage=$(get_actual_usage "$namespace")
        
        # Analyze compliance
        local namespace_compliance=$(analyze_quota_compliance "$namespace_quotas" "$namespace_usage")
        
        # Add to global results
        all_quotas=$(echo "$all_quotas" | jq --argjson new "$namespace_quotas" '. + $new')
        all_limit_ranges=$(echo "$all_limit_ranges" | jq --argjson new "$namespace_limit_ranges" '. + $new')
        all_compliance_analysis=$(echo "$all_compliance_analysis" | jq --argjson new "$namespace_compliance" '. + $new')
    done
    
    # Generate summary
    local summary=$(generate_quota_summary "$all_compliance_analysis")
    
    # Create alerts
    create_alerts "$all_compliance_analysis"
    
    # Create final report
    local final_report=$(jq -n \
        --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --argjson summary "$summary" \
        --argjson quotas "$all_quotas" \
        --argjson limit_ranges "$all_limit_ranges" \
        --argjson compliance_analysis "$all_compliance_analysis" \
        --argjson thresholds "{\"warning\": $WARNING_THRESHOLD, \"critical\": $CRITICAL_THRESHOLD}" \
        '{
            timestamp: $timestamp,
            summary: $summary,
            quotas: $quotas,
            limit_ranges: $limit_ranges,
            compliance_analysis: $compliance_analysis,
            thresholds: $thresholds
        }')
    
    # Save results
    echo "$final_report" > "$OUTPUT_FILE"
    
    # Display summary
    echo -e "\n${BLUE}=== Resource Quota Check Summary ===${NC}"
    echo "Total quotas: $(echo "$summary" | jq -r '.total_quotas')"
    echo "Compliant: $(echo "$summary" | jq -r '.compliant_quotas')"
    echo "Warning: $(echo "$summary" | jq -r '.warning_quotas')"
    echo "Critical: $(echo "$summary" | jq -r '.critical_quotas')"
    echo "Compliance percentage: $(echo "$summary" | jq -r '.compliance_percentage')%"
    echo "Overall status: $(echo "$summary" | jq -r '.status')"
    
    log "${GREEN}Resource quota check completed successfully!${NC}"
    log "Results saved to: $OUTPUT_FILE"
    log "Logs saved to: $LOG_FILE"
}

# Execute main function
main "$@"
