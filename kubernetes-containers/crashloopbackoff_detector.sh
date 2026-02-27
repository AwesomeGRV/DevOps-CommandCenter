#!/bin/bash

# Kubernetes CrashLoopBackOff Detector
# Author: CloudOps-SRE-Toolkit
# Description: Detect and analyze pods in CrashLoopBackOff state

set -euo pipefail

# Configuration
LOG_FILE="crashloopbackoff_detection_$(date +%Y%m%d_%H%M%S).log"
OUTPUT_FILE="crashloopbackoff_report_$(date +%Y%m%d_%H%M%S).json"
NAMESPACE=${NAMESPACE:-"all"}
CONTEXT=${CONTEXT:-"current"}
ALERT_THRESHOLD=${ALERT_THRESHOLD:-3}  # Number of restarts before alerting
TIME_WINDOW=${TIME_WINDOW:-"10m"}  # Time window to check restarts

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

# Get pods in CrashLoopBackOff state
get_crashloop_pods() {
    local namespace=$1
    
    log "Scanning for CrashLoopBackOff pods in namespace: $namespace"
    
    local namespace_arg=""
    if [[ "$namespace" != "all" ]]; then
        namespace_arg="-n $namespace"
    fi
    
    # Get pods with CrashLoopBackOff state
    local crashloop_pods=$(kubectl get pods $namespace_arg -o json 2>/dev/null | \
        jq -r '.items[] | select(.status.containerStatuses[].state.waiting.reason == "CrashLoopBackOff") | {
            name: .metadata.name,
            namespace: .metadata.namespace,
            node: .spec.nodeName,
            labels: .metadata.labels,
            creation_timestamp: .metadata.creationTimestamp,
            containers: [.status.containerStatuses[] | select(.state.waiting.reason == "CrashLoopBackOff") | {
                name: .name,
                restart_count: .restartCount,
                state: .state,
                last_state: .lastState,
                ready: .ready,
                started: .started
            }]
        }')
    
    if [[ -z "$crashloop_pods" || "$crashloop_pods" == "null" ]]; then
        log "${GREEN}No pods in CrashLoopBackOff state found in namespace: $namespace${NC}"
        echo "[]"
        return
    fi
    
    echo "$crashloop_pods" | jq -s '.'
}

# Get detailed pod logs and events
get_pod_details() {
    local pod_name=$1
    local pod_namespace=$2
    local container_name=$3
    
    log "Getting details for pod: $pod_name in namespace: $pod_namespace"
    
    # Get recent events for the pod
    local events=$(kubectl get events -n "$pod_namespace" --field-selector involvedObject.name="$pod_name" \
        --sort-by='.lastTimestamp' -o json 2>/dev/null | \
        jq -r '.items | reverse | [.[] | {
            timestamp: .lastTimestamp,
            type: .type,
            reason: .reason,
            message: .message,
            source: .source.component
        }]')
    
    # Get recent logs (last 50 lines)
    local logs=""
    if kubectl logs -n "$pod_namespace" "$pod_name" -c "$container_name" --tail=50 &>/dev/null; then
        logs=$(kubectl logs -n "$pod_namespace" "$pod_name" -c "$container_name" --tail=50 2>/dev/null | \
            jq -R -s '.' | jq -r 'split("\n") | map(select(length > 0))')
    else
        logs="Unable to retrieve logs"
    fi
    
    # Get previous container logs if available
    local previous_logs=""
    if kubectl logs -n "$pod_namespace" "$pod_name" -c "$container_name" --previous --tail=50 &>/dev/null; then
        previous_logs=$(kubectl logs -n "$pod_namespace" "$pod_name" -c "$container_name" --previous --tail=50 2>/dev/null | \
            jq -R -s '.' | jq -r 'split("\n") | map(select(length > 0))')
    fi
    
    jq -n \
        --argjson events "$events" \
        --argjson logs "$logs" \
        --argjson previous_logs "$previous_logs" \
        '{
            events: $events,
            recent_logs: $logs,
            previous_logs: $previous_logs
        }'
}

# Analyze crash patterns
analyze_crash_patterns() {
    local pod_data=$1
    
    log "Analyzing crash patterns..."
    
    echo "$pod_data" | jq -c '.[]' | while read -r pod; do
        local pod_name=$(echo "$pod" | jq -r '.name')
        local pod_namespace=$(echo "$pod" | jq -r '.namespace')
        
        # Get details for each container in CrashLoopBackOff
        echo "$pod" | jq -r '.containers[] | .name' | while read -r container_name; do
            local restart_count=$(echo "$pod" | jq -r ".containers[] | select(.name == \"$container_name\") | .restart_count")
            
            if [[ $restart_count -gt $ALERT_THRESHOLD ]]; then
                log "${RED}ALERT: Pod $pod_name/$container_name has restarted $restart_count times${NC}"
                
                # Get detailed information
                local details=$(get_pod_details "$pod_name" "$pod_namespace" "$container_name")
                
                # Analyze common crash reasons from events
                local crash_reason=$(echo "$details" | jq -r '.events[] | select(.reason == "BackOff" or .reason == "Failed" or .reason == "Killing") | .message' | head -1)
                
                # Suggest potential fixes based on patterns
                local suggestions=$(get_suggestions "$pod_name" "$container_name" "$details")
                
                jq -n \
                    --arg pod_name "$pod_name" \
                    --arg pod_namespace "$pod_namespace" \
                    --arg container_name "$container_name" \
                    --argjson restart_count "$restart_count" \
                    --arg crash_reason "$crash_reason" \
                    --argjson suggestions "$suggestions" \
                    --argjson details "$details" \
                    '{
                        pod_name: $pod_name,
                        namespace: $pod_namespace,
                        container_name: $container_name,
                        restart_count: $restart_count,
                        crash_reason: $crash_reason,
                        suggestions: $suggestions,
                        details: $details,
                        severity: if $restart_count > 10 then "critical" elif $restart_count > 5 then "high" else "medium" end
                    }'
            fi
        done
    done
}

# Get suggestions based on common patterns
get_suggestions() {
    local pod_name=$1
    local container_name=$2
    local details=$3
    
    local suggestions=()
    
    # Check for common error patterns in logs
    local error_patterns=$(echo "$details" | jq -r '.recent_logs[]?' | grep -i -E "(error|exception|failed|denied|permission|connection|timeout)" || true)
    
    if echo "$error_patterns" | grep -qi "permission denied\|access denied"; then
        suggestions+=("Check RBAC permissions and service account")
        suggestions+=("Verify security context and file permissions")
    fi
    
    if echo "$error_patterns" | grep -qi "connection refused\|network unreachable"; then
        suggestions+=("Check network policies and service connectivity")
        suggestions+=("Verify endpoint configuration and DNS resolution")
    fi
    
    if echo "$error_patterns" | grep -qi "out of memory\|oom"; then
        suggestions+=("Increase memory limits and requests")
        suggestions+=("Check for memory leaks in the application")
    fi
    
    if echo "$error_patterns" | grep -qi "imagepull\|image pull"; then
        suggestions+=("Verify image registry access and credentials")
        suggestions+=("Check image name and tag availability")
    fi
    
    if echo "$error_patterns" | grep -qi "configmap\|secret"; then
        suggestions+=("Verify ConfigMaps and Secrets exist and are mounted correctly")
    fi
    
    # Add general suggestions if no specific patterns found
    if [[ ${#suggestions[@]} -eq 0 ]]; then
        suggestions+=("Check resource limits and requests")
        suggestions+=("Verify liveness and readiness probes")
        suggestions+=("Review application logs for startup issues")
        suggestions+=("Check environment variables and configuration")
    fi
    
    printf '%s\n' "${suggestions[@]}" | jq -R . | jq -s .
}

# Generate recommendations
generate_recommendations() {
    local analysis_results=$1
    
    log "Generating recommendations..."
    
    echo "$analysis_results" | jq -s '.' | jq '
    {
        summary: {
            total_crashloop_pods: length,
            critical_issues: map(select(.severity == "critical")) | length,
            high_issues: map(select(.severity == "high")) | length,
            medium_issues: map(select(.severity == "medium")) | length
        },
        recommendations: [
            "Review and fix pods with high restart counts",
            "Implement proper health checks (liveness/readiness probes)",
            "Set appropriate resource limits and requests",
            "Add logging and monitoring for better debugging",
            "Consider using init containers for dependency checks",
            "Implement proper error handling in applications"
        ],
        detailed_analysis: .
    }'
}

# Create alert if needed
create_alert() {
    local analysis_results=$1
    
    local critical_count=$(echo "$analysis_results" | jq 'map(select(.severity == "critical")) | length')
    local high_count=$(echo "$analysis_results" | jq 'map(select(.severity == "high")) | length')
    
    if [[ $critical_count -gt 0 ]]; then
        log "${RED}🚨 CRITICAL: $critical_count pods with critical CrashLoopBackOff issues detected!${NC}"
        # Here you could integrate with your alerting system (Slack, PagerDuty, etc.)
        # send_alert_to_slack "Critical CrashLoopBackOff detected" "$analysis_results"
    fi
    
    if [[ $high_count -gt 0 ]]; then
        log "${YELLOW}⚠️  WARNING: $high_count pods with high CrashLoopBackOff issues detected!${NC}"
    fi
}

# Main execution
main() {
    log "${GREEN}Starting Kubernetes CrashLoopBackOff Detection...${NC}"
    log "Log file: $LOG_FILE"
    log "Output file: $OUTPUT_FILE"
    log "Namespace: $NAMESPACE"
    log "Alert threshold: $ALERT_THRESHOLD restarts"
    
    check_dependencies
    
    # Get CrashLoopBackOff pods
    local crashloop_pods=$(get_crashloop_pods "$NAMESPACE")
    
    if [[ "$crashloop_pods" == "[]" ]]; then
        log "${GREEN}✅ No CrashLoopBackOff pods found. All systems healthy!${NC}"
        exit 0
    fi
    
    log "${YELLOW}Found $(echo "$crashloop_pods" | jq '. | length') pods in CrashLoopBackOff state${NC}"
    
    # Analyze crash patterns
    local analysis_results=$(analyze_crash_patterns "$crashloop_pods")
    
    # Generate recommendations
    local recommendations=$(generate_recommendations "$analysis_results")
    
    # Create alerts if needed
    create_alert "$analysis_results"
    
    # Save results to file
    echo "$recommendations" > "$OUTPUT_FILE"
    
    # Display summary
    local total_pods=$(echo "$recommendations" | jq '.summary.total_crashloop_pods')
    local critical_issues=$(echo "$recommendations" | jq '.summary.critical_issues')
    local high_issues=$(echo "$recommendations" | jq '.summary.high_issues')
    
    echo -e "\n${BLUE}=== CrashLoopBackOff Detection Summary ===${NC}"
    echo "Total pods in CrashLoopBackOff: $total_pods"
    echo "Critical issues: $critical_issues"
    echo "High priority issues: $high_issues"
    echo "Medium priority issues: $(echo "$recommendations" | jq '.summary.medium_issues')"
    
    log "${GREEN}Analysis completed successfully!${NC}"
    log "Results saved to: $OUTPUT_FILE"
    log "Logs saved to: $LOG_FILE"
}

# Execute main function
main "$@"
