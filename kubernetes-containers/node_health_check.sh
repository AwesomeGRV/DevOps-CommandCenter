#!/bin/bash

# Kubernetes Node Health Check Script
# Author: CloudOps-SRE-Toolkit
# Description: Comprehensive health check for Kubernetes nodes

set -euo pipefail

# Configuration
LOG_FILE="node_health_check_$(date +%Y%m%d_%H%M%S).log"
OUTPUT_FILE="node_health_report_$(date +%Y%m%d_%H%M%S).json"
NODE_SELECTOR=${NODE_SELECTOR:-""}  # Label selector to filter nodes
CHECK_PODS=${CHECK_PODS:-"true"}   # Whether to check pod health on nodes
CPU_THRESHOLD=${CPU_THRESHOLD:-80}  # CPU usage threshold for warnings
MEMORY_THRESHOLD=${MEMORY_THRESHOLD:-80}  # Memory usage threshold for warnings
DISK_THRESHOLD=${DISK_THRESHOLD:-85}  # Disk usage threshold for warnings

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

# Get all nodes (filtered by selector if provided)
get_nodes() {
    local selector_arg=""
    if [[ -n "$NODE_SELECTOR" ]]; then
        selector_arg="-l $NODE_SELECTOR"
    fi
    
    log "Getting nodes with selector: ${NODE_SELECTOR:-'all'}"
    
    kubectl get nodes $selector_arg -o json | \
        jq -r '.items[] | {
            name: .metadata.name,
            labels: .metadata.labels,
            annotations: .metadata.annotations,
            creation_timestamp: .metadata.creationTimestamp,
            provider_id: .spec.providerID // "",
            kubelet_version: .status.nodeInfo.kubeletVersion,
            os_image: .status.nodeInfo.osImage,
            kernel_version: .status.nodeInfo.kernelVersion,
            container_runtime_version: .status.nodeInfo.containerRuntimeVersion,
            architecture: .status.nodeInfo.architecture,
            conditions: [.status.conditions[] | {
                type: .type,
                status: .status,
                reason: .reason,
                message: .message
            }],
            addresses: [.status.addresses[] | {
                type: .type,
                address: .address
            }],
            capacity: .status.capacity,
            allocatable: .status.allocatable,
            taints: .spec.taints // [],
            unschedulable: .spec.unschedulable // false
        }'
}

# Check node conditions
check_node_conditions() {
    local node=$1
    
    local node_name=$(echo "$node" | jq -r '.name')
    log "Checking conditions for node: $node_name"
    
    local critical_conditions=()
    local warning_conditions=()
    
    echo "$node" | jq -r '.conditions[]' | while read -r condition; do
        local type=$(echo "$condition" | jq -r '.type')
        local status=$(echo "$condition" | jq -r '.status')
        local reason=$(echo "$condition" | jq -r '.reason')
        local message=$(echo "$condition" | jq -r '.message')
        
        case "$type" in
            "Ready")
                if [[ "$status" != "True" ]]; then
                    critical_conditions+=("Ready: $reason - $message")
                fi
                ;;
            "MemoryPressure")
                if [[ "$status" == "True" ]]; then
                    warning_conditions+=("MemoryPressure: $reason - $message")
                fi
                ;;
            "DiskPressure")
                if [[ "$status" == "True" ]]; then
                    critical_conditions+=("DiskPressure: $reason - $message")
                fi
                ;;
            "PIDPressure")
                if [[ "$status" == "True" ]]; then
                    warning_conditions+=("PIDPressure: $reason - $message")
                fi
                ;;
            "NetworkUnavailable")
                if [[ "$status" == "True" ]]; then
                    critical_conditions+=("NetworkUnavailable: $reason - $message")
                fi
                ;;
        esac
    done
    
    jq -n \
        --arg node_name "$node_name" \
        --argjson critical_conditions "$(printf '%s\n' "${critical_conditions[@]}" | jq -R . | jq -s .)" \
        --argjson warning_conditions "$(printf '%s\n' "${warning_conditions[@]}" | jq -R . | jq -s .)" \
        '{
            node_name: $node_name,
            critical_conditions: $critical_conditions,
            warning_conditions: $warning_conditions,
            status: if ($critical_conditions | length) > 0 then "critical" 
                   elif ($warning_conditions | length) > 0 then "warning" 
                   else "healthy" end
        }'
}

# Get node resource usage
get_node_resource_usage() {
    local node_name=$1
    
    log "Getting resource usage for node: $node_name"
    
    # Get metrics from metrics server if available
    local metrics=$(kubectl top node "$node_name" --no-headers 2>/dev/null || echo "")
    
    if [[ -n "$metrics" ]]; then
        local cpu_usage=$(echo "$metrics" | awk '{print $2}' | sed 's/%//')
        local memory_usage=$(echo "$metrics" | awk '{print $3}' | sed 's/%//')
        
        # Determine status based on thresholds
        local cpu_status="normal"
        local memory_status="normal"
        
        if [[ ${cpu_usage%?} -ge 90 ]]; then
            cpu_status="critical"
        elif [[ ${cpu_usage%?} -ge $CPU_THRESHOLD ]]; then
            cpu_status="warning"
        fi
        
        if [[ ${memory_usage%?} -ge 90 ]]; then
            memory_status="critical"
        elif [[ ${memory_usage%?} -ge $MEMORY_THRESHOLD ]]; then
            memory_status="warning"
        fi
        
        jq -n \
            --arg node_name "$node_name" \
            --arg cpu_usage "${cpu_usage}%" \
            --arg memory_usage "${memory_usage}%" \
            --arg cpu_status "$cpu_status" \
            --arg memory_status "$memory_status" \
            '{
                node_name: $node_name,
                cpu_usage: $cpu_usage,
                memory_usage: $memory_usage,
                cpu_status: $cpu_status,
                memory_status: $memory_status,
                status: if ($cpu_status == "critical" or $memory_status == "critical") then "critical"
                       elif ($cpu_status == "warning" or $memory_status == "warning") then "warning"
                       else "normal" end
            }'
    else
        jq -n \
            --arg node_name "$node_name" \
            '{
                node_name: $node_name,
                cpu_usage: "N/A",
                memory_usage: "N/A",
                cpu_status: "unknown",
                memory_status: "unknown",
                status: "unknown",
                note: "Metrics server not available"
            }'
    fi
}

# Check pods on node
check_node_pods() {
    local node_name=$1
    
    if [[ "$CHECK_PODS" != "true" ]]; then
        jq -n --arg node_name "$node_name" '{node_name: $node_name, note: "Pod checking disabled"}'
        return
    fi
    
    log "Checking pods on node: $node_name"
    
    # Get all pods on the node
    local pods=$(kubectl get pods --all-namespaces --field-selector spec.nodeName="$node_name" -o json 2>/dev/null | \
        jq -r '.items[] | {
            name: .metadata.name,
            namespace: .metadata.namespace,
            phase: .status.phase,
            pod_ip: .status.podIP // "",
            node_name: .spec.nodeName,
            containers: [.status.containerStatuses[] | {
                name: .name,
                ready: .ready,
                restart_count: .restartCount,
                state: .state,
                image: .image
            }]
        }')
    
    if [[ -z "$pods" || "$pods" == "null" ]]; then
        jq -n --arg node_name "$node_name" '{node_name: $node_name, pods: []}'
        return
    fi
    
    # Analyze pod health
    local total_pods=$(echo "$pods" | jq '. | length')
    local running_pods=$(echo "$pods" | jq 'map(select(.phase == "Running")) | length')
    local failed_pods=$(echo "$pods" | jq 'map(select(.phase == "Failed")) | length')
    local pending_pods=$(echo "$pods" | jq 'map(select(.phase == "Pending")) | length')
    local crashed_pods=$(echo "$pods" | jq 'map(.containers[] | select(.restart_count > 5)) | length')
    
    # Determine pod health status
    local pod_status="healthy"
    if [[ $failed_pods -gt 0 || $crashed_pods -gt 0 ]]; then
        pod_status="critical"
    elif [[ $pending_pods -gt 2 ]]; then
        pod_status="warning"
    fi
    
    jq -n \
        --arg node_name "$node_name" \
        --argjson total_pods "$total_pods" \
        --argjson running_pods "$running_pods" \
        --argjson failed_pods "$failed_pods" \
        --argjson pending_pods "$pending_pods" \
        --argjson crashed_pods "$crashed_pods" \
        --arg pod_status "$pod_status" \
        --argjson pods "$pods" \
        '{
            node_name: $node_name,
            total_pods: $total_pods,
            running_pods: $running_pods,
            failed_pods: $failed_pods,
            pending_pods: $pending_pods,
            crashed_pods: $crashed_pods,
            status: $pod_status,
            pods: $pods
        }'
}

# Check node connectivity and basic health
check_node_connectivity() {
    local node_name=$1
    local node_ip=$(kubectl get node "$node_name" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || echo "")
    
    log "Checking connectivity for node: $node_name (IP: $node_ip)"
    
    local connectivity_tests=()
    
    # Test basic connectivity if IP is available
    if [[ -n "$node_ip" ]]; then
        if ping -c 1 -W 5 "$node_ip" &>/dev/null; then
            connectivity_tests+=("ping: success")
        else
            connectivity_tests+=("ping: failed")
        fi
        
        # Test SSH connectivity (if possible)
        if command -v ssh &>/dev/null; then
            # This is a basic check - actual SSH would require proper keys
            if timeout 5 bash -c "</dev/tcp/$node_ip/22" 2>/dev/null; then
                connectivity_tests+=("ssh_port: open")
            else
                connectivity_tests+=("ssh_port: closed")
            fi
        fi
    else
        connectivity_tests+=("ip_address: not_available")
    fi
    
    jq -n \
        --arg node_name "$node_name" \
        --arg node_ip "$node_ip" \
        --argjson connectivity_tests "$(printf '%s\n' "${connectivity_tests[@]}" | jq -R . | jq -s .)" \
        '{
            node_name: $node_name,
            node_ip: $node_ip,
            connectivity_tests: $connectivity_tests,
            status: "checked"
        }'
}

# Get node system information
get_node_system_info() {
    local node=$1
    
    local node_name=$(echo "$node" | jq -r '.name')
    log "Getting system info for node: $node_name"
    
    # Extract system information from node object
    local kubelet_version=$(echo "$node" | jq -r '.kubelet_version')
    local os_image=$(echo "$node" | jq -r '.os_image')
    local kernel_version=$(echo "$node" | jq -r '.kernel_version')
    local container_runtime=$(echo "$node" | jq -r '.container_runtime_version')
    local architecture=$(echo "$node" | jq -r '.architecture')
    
    # Check for known issues or recommendations
    local recommendations=()
    
    # Check kubelet version
    if [[ "$kubelet_version" =~ v1\.[0-9]+\.[0-9]+ ]]; then
        local major_minor=$(echo "$kubelet_version" | sed 's/v\([0-9]\+\)\.\([0-9]\+\).*/\1.\2/')
        if [[ $(echo "$major_minor < 1.20" | bc -l 2>/dev/null || echo "0") -eq 1 ]]; then
            recommendations+=("Consider upgrading kubelet version - current version is quite old")
        fi
    fi
    
    # Check container runtime
    if [[ "$container_runtime" =~ docker ]]; then
        recommendations+=("Consider migrating to containerd for better performance and security")
    fi
    
    jq -n \
        --arg node_name "$node_name" \
        --arg kubelet_version "$kubelet_version" \
        --arg os_image "$os_image" \
        --arg kernel_version "$kernel_version" \
        --arg container_runtime "$container_runtime" \
        --arg architecture "$architecture" \
        --argjson recommendations "$(printf '%s\n' "${recommendations[@]}" | jq -R . | jq -s .)" \
        '{
            node_name: $node_name,
            kubelet_version: $kubelet_version,
            os_image: $os_image,
            kernel_version: $kernel_version,
            container_runtime: $container_runtime,
            architecture: $architecture,
            recommendations: $recommendations
        }'
}

# Analyze overall node health
analyze_node_health() {
    local node=$1
    local conditions=$2
    local resource_usage=$3
    local pod_health=$4
    local connectivity=$5
    local system_info=$6
    
    local node_name=$(echo "$node" | jq -r '.name')
    
    # Determine overall health status
    local overall_status="healthy"
    local issues=()
    
    # Check conditions
    local conditions_status=$(echo "$conditions" | jq -r '.status')
    if [[ "$conditions_status" == "critical" ]]; then
        overall_status="critical"
        issues+=("Critical node conditions detected")
    elif [[ "$conditions_status" == "warning" ]]; then
        if [[ "$overall_status" != "critical" ]]; then
            overall_status="warning"
        fi
        issues+=("Warning node conditions detected")
    fi
    
    # Check resource usage
    local usage_status=$(echo "$resource_usage" | jq -r '.status')
    if [[ "$usage_status" == "critical" ]]; then
        overall_status="critical"
        issues+=("Critical resource usage detected")
    elif [[ "$usage_status" == "warning" ]]; then
        if [[ "$overall_status" != "critical" ]]; then
            overall_status="warning"
        fi
        issues+=("High resource usage detected")
    fi
    
    # Check pod health
    local pod_status=$(echo "$pod_health" | jq -r '.status')
    if [[ "$pod_status" == "critical" ]]; then
        if [[ "$overall_status" != "critical" ]]; then
            overall_status="warning"
        fi
        issues+=("Pod health issues detected")
    fi
    
    # Check if node is schedulable
    local unschedulable=$(echo "$node" | jq -r '.unschedulable')
    if [[ "$unschedulable" == "true" ]]; then
        if [[ "$overall_status" != "critical" ]]; then
            overall_status="warning"
        fi
        issues+=("Node is marked as unschedulable")
    fi
    
    jq -n \
        --arg node_name "$node_name" \
        --arg overall_status "$overall_status" \
        --argjson issues "$(printf '%s\n' "${issues[@]}" | jq -R . | jq -s .)" \
        --argjson node "$node" \
        --argjson conditions "$conditions" \
        --argjson resource_usage "$resource_usage" \
        --argjson pod_health "$pod_health" \
        --argjson connectivity "$connectivity" \
        --argjson system_info "$system_info" \
        '{
            node_name: $node_name,
            overall_status: $overall_status,
            issues: $issues,
            node_info: $node,
            conditions: $conditions,
            resource_usage: $resource_usage,
            pod_health: $pod_health,
            connectivity: $connectivity,
            system_info: $system_info,
            check_timestamp: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
        }'
}

# Generate cluster summary
generate_cluster_summary() {
    local node_health_analysis=$1
    
    local total_nodes=$(echo "$node_health_analysis" | jq '. | length')
    local healthy_nodes=$(echo "$node_health_analysis" | jq 'map(select(.overall_status == "healthy")) | length')
    local warning_nodes=$(echo "$node_health_analysis" | jq 'map(select(.overall_status == "warning")) | length')
    local critical_nodes=$(echo "$node_health_analysis" | jq 'map(select(.overall_status == "critical")) | length')
    
    local cluster_status="healthy"
    if [[ $critical_nodes -gt 0 ]]; then
        cluster_status="critical"
    elif [[ $warning_nodes -gt 0 ]]; then
        cluster_status="warning"
    fi
    
    jq -n \
        --argjson total_nodes "$total_nodes" \
        --argjson healthy_nodes "$healthy_nodes" \
        --argjson warning_nodes "$warning_nodes" \
        --argjson critical_nodes "$critical_nodes" \
        --arg cluster_status "$cluster_status" \
        --arg health_percentage "$(echo "scale=2; $healthy_nodes * 100 / $total_nodes" | bc -l 2>/dev/null || echo "0")" \
        '{
            total_nodes: $total_nodes,
            healthy_nodes: $healthy_nodes,
            warning_nodes: $warning_nodes,
            critical_nodes: $critical_nodes,
            cluster_status: $cluster_status,
            health_percentage: ($health_percentage | tonumber),
            timestamp: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
        }'
}

# Create alerts for critical nodes
create_alerts() {
    local node_health_analysis=$1
    
    local critical_nodes=$(echo "$node_health_analysis" | jq '.[] | select(.overall_status == "critical")')
    
    if [[ "$critical_nodes" != "" && "$critical_nodes" != "null" ]]; then
        local critical_count=$(echo "$critical_nodes" | jq '. | length')
        log "${RED}🚨 CRITICAL: $critical_count nodes with critical health issues detected!${NC}"
        
        echo "$critical_nodes" | jq -c '.' | while read -r node; do
            local node_name=$(echo "$node" | jq -r '.node_name')
            local issues=$(echo "$node" | jq -r '.issues[]')
            
            log "${RED}Critical node: $node_name${NC}"
            echo "$node" | jq -r '.issues[]' | while read -r issue; do
                log "${RED}  - $issue${NC}"
            done
        done
    fi
}

# Main execution
main() {
    log "${GREEN}Starting Kubernetes Node Health Check...${NC}"
    log "Log file: $LOG_FILE"
    log "Output file: $OUTPUT_FILE"
    log "Node selector: ${NODE_SELECTOR:-'all nodes'}"
    log "CPU threshold: ${CPU_THRESHOLD}%"
    log "Memory threshold: ${MEMORY_THRESHOLD}%"
    log "Disk threshold: ${DISK_THRESHOLD}%"
    
    check_dependencies
    
    # Get all nodes
    local nodes=$(get_nodes)
    
    if [[ -z "$nodes" || "$nodes" == "null" ]]; then
        log "${RED}ERROR: No nodes found or unable to retrieve node information${NC}"
        exit 1
    fi
    
    local node_count=$(echo "$nodes" | jq '. | length')
    log "${GREEN}Found $node_count nodes to check${NC}"
    
    # Process each node
    local node_health_analysis="[]"
    
    echo "$nodes" | jq -c '.' | while read -r node; do
        local node_name=$(echo "$node" | jq -r '.name')
        log "Processing node: $node_name"
        
        # Run all checks
        local conditions=$(check_node_conditions "$node")
        local resource_usage=$(get_node_resource_usage "$node_name")
        local pod_health=$(check_node_pods "$node_name")
        local connectivity=$(check_node_connectivity "$node_name")
        local system_info=$(get_node_system_info "$node")
        
        # Analyze overall health
        local health_analysis=$(analyze_node_health "$node" "$conditions" "$resource_usage" "$pod_health" "$connectivity" "$system_info")
        
        # Add to results
        node_health_analysis=$(echo "$node_health_analysis" | jq --argjson new "$health_analysis" '. + [$new]')
    done
    
    # Generate cluster summary
    local cluster_summary=$(generate_cluster_summary "$node_health_analysis")
    
    # Create alerts for critical nodes
    create_alerts "$node_health_analysis"
    
    # Create final report
    local final_report=$(jq -n \
        --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --argjson cluster_summary "$cluster_summary" \
        --argjson node_health_analysis "$node_health_analysis" \
        --argjson thresholds "{\"cpu\": $CPU_THRESHOLD, \"memory\": $MEMORY_THRESHOLD, \"disk\": $DISK_THRESHOLD}" \
        '{
            timestamp: $timestamp,
            cluster_summary: $cluster_summary,
            node_health_analysis: $node_health_analysis,
            thresholds: $thresholds
        }')
    
    # Save results
    echo "$final_report" > "$OUTPUT_FILE"
    
    # Display summary
    echo -e "\n${BLUE}=== Node Health Check Summary ===${NC}"
    echo "Total nodes: $(echo "$cluster_summary" | jq -r '.total_nodes')"
    echo "Healthy nodes: $(echo "$cluster_summary" | jq -r '.healthy_nodes')"
    echo "Warning nodes: $(echo "$cluster_summary" | jq -r '.warning_nodes')"
    echo "Critical nodes: $(echo "$cluster_summary" | jq -r '.critical_nodes')"
    echo "Cluster health: $(echo "$cluster_summary" | jq -r '.cluster_status')"
    echo "Health percentage: $(echo "$cluster_summary" | jq -r '.health_percentage')%"
    
    log "${GREEN}Node health check completed successfully!${NC}"
    log "Results saved to: $OUTPUT_FILE"
    log "Logs saved to: $LOG_FILE"
}

# Execute main function
main "$@"
