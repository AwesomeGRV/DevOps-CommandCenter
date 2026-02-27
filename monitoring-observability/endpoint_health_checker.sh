#!/bin/bash

# Endpoint Health Checker Script
# Author: CloudOps-SRE-Toolkit
# Description: Comprehensive health check for HTTP/HTTPS endpoints

set -euo pipefail

# Configuration
LOG_FILE="endpoint_health_check_$(date +%Y%m%d_%H%M%S).log"
OUTPUT_FILE="endpoint_health_report_$(date +%Y%m%d_%H%M%S).json"
CONFIG_FILE=${CONFIG_FILE:-"config/endpoints.json"}
TIMEOUT=${TIMEOUT:-10}
RETRY_COUNT=${RETRY_COUNT:-3}
RETRY_DELAY=${RETRY_DELAY:-2}
USER_AGENT=${USER_AGENT:-"CloudOps-SRE-Toolkit/1.0"}
FOLLOW_REDIRECTS=${FOLLOW_REDIRECTS:-"true"}

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

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_deps+=("jq")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log "${RED}ERROR: Missing dependencies: ${missing_deps[*]}${NC}"
        log "Please install missing dependencies and try again."
        exit 1
    fi
    
    log "${GREEN}All dependencies are installed.${NC}"
}

# Load endpoint configuration
load_endpoints() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "${YELLOW}Config file $CONFIG_FILE not found. Creating sample configuration...${NC}"
        create_sample_config
        exit 1
    fi
    
    if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
        log "${RED}ERROR: Invalid JSON in config file $CONFIG_FILE${NC}"
        exit 1
    fi
    
    log "Loading endpoint configuration from: $CONFIG_FILE"
    jq -c '.endpoints[]' "$CONFIG_FILE"
}

# Create sample configuration file
create_sample_config() {
    cat > "$CONFIG_FILE" << 'EOF'
{
  "endpoints": [
    {
      "name": "Google Homepage",
      "url": "https://www.google.com",
      "method": "GET",
      "expected_status_codes": [200],
      "timeout": 10,
      "headers": {
        "User-Agent": "CloudOps-SRE-Toolkit/1.0"
      },
      "check_ssl": true,
      "check_response_time": true,
      "max_response_time_ms": 5000,
      "check_content": true,
      "expected_content": "<title>Google</title>",
      "auth": null
    },
    {
      "name": "JSONPlaceholder API",
      "url": "https://jsonplaceholder.typicode.com/posts/1",
      "method": "GET",
      "expected_status_codes": [200],
      "timeout": 10,
      "headers": {},
      "check_ssl": true,
      "check_response_time": true,
      "max_response_time_ms": 3000,
      "check_content": true,
      "expected_content": "\"userId\": 1",
      "auth": null
    },
    {
      "name": "HTTPBin Test",
      "url": "https://httpbin.org/status/200",
      "method": "GET",
      "expected_status_codes": [200],
      "timeout": 10,
      "headers": {},
      "check_ssl": true,
      "check_response_time": true,
      "max_response_time_ms": 5000,
      "check_content": false,
      "auth": null
    }
  ],
  "global_settings": {
    "parallel_checks": true,
    "max_parallel": 10,
    "alert_threshold": 0.1,
    "notification_webhook": ""
  }
}
EOF
    
    log "Sample configuration created at: $CONFIG_FILE"
    log "Please edit the configuration file with your endpoints and run again."
}

# Check single endpoint
check_endpoint() {
    local endpoint=$1
    local attempt=1
    
    local name=$(echo "$endpoint" | jq -r '.name')
    local url=$(echo "$endpoint" | jq -r '.url')
    local method=$(echo "$endpoint" | jq -r '.method // "GET"')
    local expected_codes=$(echo "$endpoint" | jq -r '.expected_status_codes[]?')
    local timeout=$(echo "$endpoint" | jq -r '.timeout // 10')
    local headers=$(echo "$endpoint" | jq -r '.headers // {}')
    local check_ssl=$(echo "$endpoint" | jq -r '.check_ssl // true')
    local check_response_time=$(echo "$endpoint" | jq -r '.check_response_time // true')
    local max_response_time=$(echo "$endpoint" | jq -r '.max_response_time_ms // 5000')
    local check_content=$(echo "$endpoint" | jq -r '.check_content // false')
    local expected_content=$(echo "$endpoint" | jq -r '.expected_content // ""')
    local auth=$(echo "$endpoint" | jq -r '.auth // null')
    
    log "Checking endpoint: $name ($url)"
    
    # Prepare curl command
    local curl_cmd="curl -s -w '%{http_code}|%{time_total}|%{size_download}|%{ssl_verify_result}|%{redirect_url}'"
    curl_cmd+=" -X $method"
    curl_cmd+=" --connect-timeout $timeout"
    curl_cmd+=" --max-time $timeout"
    curl_cmd+=" --user-agent '$USER_AGENT'"
    
    # Add headers
    if [[ "$headers" != "{}" ]]; then
        echo "$headers" | jq -r 'to_entries[] | "-H \"\(.key)=\(.value)\""' | while read -r header; do
            curl_cmd+=" $header"
        done
    fi
    
    # Add authentication
    if [[ "$auth" != "null" && "$auth" != "" ]]; then
        local auth_type=$(echo "$auth" | jq -r '.type')
        case "$auth_type" in
            "bearer")
                local token=$(echo "$auth" | jq -r '.token')
                curl_cmd+=" -H 'Authorization: Bearer $token'"
                ;;
            "basic")
                local username=$(echo "$auth" | jq -r '.username')
                local password=$(echo "$auth" | jq -r '.password')
                curl_cmd+=" -u '$username:$password'"
                ;;
            "api_key")
                local key=$(echo "$auth" | jq -r '.key')
                local value=$(echo "$auth" | jq -r '.value')
                curl_cmd+=" -H '$key: $value'"
                ;;
        esac
    fi
    
    # SSL settings
    if [[ "$check_ssl" == "false" ]]; then
        curl_cmd+=" -k"
    fi
    
    # Redirect settings
    if [[ "$FOLLOW_REDIRECTS" == "true" ]]; then
        curl_cmd+=" -L"
    fi
    
    curl_cmd+=" '$url'"
    
    # Execute with retries
    local final_result=""
    local success=false
    
    while [[ $attempt -le $RETRY_COUNT && "$success" == "false" ]]; do
        log "Attempt $attempt for $name"
        
        local start_time=$(date +%s%N)
        local result=$(eval "$curl_cmd" 2>/dev/null)
        local end_time=$(date +%s%N)
        
        if [[ -n "$result" ]]; then
            # Parse curl output
            local status_code=$(echo "$result" | cut -d'|' -f1)
            local time_total=$(echo "$result" | cut -d'|' -f2)
            local size_download=$(echo "$result" | cut -d'|' -f3)
            local ssl_verify_result=$(echo "$result" | cut -d'|' -f4)
            local redirect_url=$(echo "$result" | cut -d'|' -f5-)
            
            # Get response body
            local response_body=$(eval "$curl_cmd" 2>/dev/null | sed 's/^[^|]*|[^|]*|[^|]*|[^|]*|//')
            
            # Calculate response time in milliseconds
            local response_time_ms=$(echo "$time_total * 1000" | bc -l 2>/dev/null || echo "0")
            response_time_ms=$(printf "%.0f" "$response_time_ms")
            
            # Validate status code
            local status_ok=false
            for expected_code in $expected_codes; do
                if [[ "$status_code" == "$expected_code" ]]; then
                    status_ok=true
                    break
                fi
            done
            
            # Validate SSL
            local ssl_ok=true
            if [[ "$check_ssl" == "true" && "$ssl_verify_result" != "0" ]]; then
                ssl_ok=false
            fi
            
            # Validate response time
            local response_time_ok=true
            if [[ "$check_response_time" == "true" ]]; then
                local time_check=$(echo "$response_time_ms <= $max_response_time" | bc -l 2>/dev/null || echo "1")
                if [[ "$time_check" != "1" ]]; then
                    response_time_ok=false
                fi
            fi
            
            # Validate content
            local content_ok=true
            if [[ "$check_content" == "true" && -n "$expected_content" ]]; then
                if [[ "$response_body" != *"$expected_content"* ]]; then
                    content_ok=false
                fi
            fi
            
            # Determine overall success
            if [[ "$status_ok" == "true" && "$ssl_ok" == "true" && "$response_time_ok" == "true" && "$content_ok" == "true" ]]; then
                success=true
            fi
            
            # Create result object
            final_result=$(jq -n \
                --arg name "$name" \
                --arg url "$url" \
                --arg method "$method" \
                --arg status_code "$status_code" \
                --arg response_time_ms "$response_time_ms" \
                --arg size_download "$size_download" \
                --arg ssl_verify_result "$ssl_verify_result" \
                --arg redirect_url "$redirect_url" \
                --argjson status_ok "$status_ok" \
                --argjson ssl_ok "$ssl_ok" \
                --argjson response_time_ok "$response_time_ok" \
                --argjson content_ok "$content_ok" \
                --argjson success "$success" \
                --arg attempt "$attempt" \
                --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
                --arg expected_content "$expected_content" \
                '{
                    name: $name,
                    url: $url,
                    method: $method,
                    status_code: ($status_code | tonumber),
                    response_time_ms: ($response_time_ms | tonumber),
                    size_download: ($size_download | tonumber),
                    ssl_verify_result: ($ssl_verify_result | tonumber),
                    redirect_url: $redirect_url,
                    checks: {
                        status_code: $status_ok,
                        ssl_certificate: $ssl_ok,
                        response_time: $response_time_ok,
                        content_validation: $content_ok
                    },
                    success: $success,
                    attempt: ($attempt | tonumber),
                    timestamp: $timestamp,
                    expected_content: $expected_content,
                    max_response_time_ms: ($max_response_time | tonumber)
                }')
        else
            # Request failed completely
            final_result=$(jq -n \
                --arg name "$name" \
                --arg url "$url" \
                --arg method "$method" \
                --argjson success false \
                --arg attempt "$attempt" \
                --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
                --arg error "Request failed" \
                '{
                    name: $name,
                    url: $url,
                    method: $method,
                    success: $success,
                    attempt: ($attempt | tonumber),
                    timestamp: $timestamp,
                    error: $error
                }')
        fi
        
        if [[ "$success" == "false" && $attempt -lt $RETRY_COUNT ]]; then
            log "Endpoint $name failed, retrying in ${RETRY_DELAY}s..."
            sleep $RETRY_DELAY
        fi
        
        ((attempt++))
    done
    
    echo "$final_result"
}

# Check all endpoints
check_all_endpoints() {
    local endpoints=$(load_endpoints)
    local results="[]"
    
    if [[ "$(jq -r '.global_settings.parallel_checks // true' "$CONFIG_FILE")" == "true" ]]; then
        # Parallel execution
        local max_parallel=$(jq -r '.global_settings.max_parallel // 10' "$CONFIG_FILE")
        local pids=()
        local temp_files=()
        
        log "Running endpoint checks in parallel (max: $max_parallel)"
        
        echo "$endpoints" | while IFS= read -r endpoint; do
            # Control parallelism
            while [[ ${#pids[@]} -ge $max_parallel ]]; do
                for i in "${!pids[@]}"; do
                    if ! kill -0 "${pids[$i]}" 2>/dev/null; then
                        wait "${pids[$i]}"
                        local result=$(cat "${temp_files[$i]}")
                        results=$(echo "$results" | jq --argjson new "$result" '. + [$new]')
                        rm -f "${temp_files[$i]}"
                        unset pids[$i]
                        unset temp_files[$i]
                    fi
                done
                sleep 0.1
            done
            
            # Start new check
            local temp_file=$(mktemp)
            temp_files+=("$temp_file")
            
            check_endpoint "$endpoint" > "$temp_file" &
            pids+=($!)
        done
        
        # Wait for remaining processes
        for pid in "${pids[@]}"; do
            wait "$pid"
        done
        
        # Collect remaining results
        for temp_file in "${temp_files[@]}"; do
            if [[ -f "$temp_file" ]]; then
                local result=$(cat "$temp_file")
                results=$(echo "$results" | jq --argjson new "$result" '. + [$new]')
                rm -f "$temp_file"
            fi
        done
        
    else
        # Sequential execution
        log "Running endpoint checks sequentially"
        echo "$endpoints" | while IFS= read -r endpoint; do
            local result=$(check_endpoint "$endpoint")
            results=$(echo "$results" | jq --argjson new "$result" '. + [$new]')
        done
    fi
    
    echo "$results"
}

# Generate summary statistics
generate_summary() {
    local results=$1
    
    local total_endpoints=$(echo "$results" | jq '. | length')
    local successful_endpoints=$(echo "$results" | jq 'map(select(.success)) | length')
    local failed_endpoints=$(echo "$results" | jq 'map(select(.success == false)) | length')
    local success_rate=$(echo "scale=2; $successful_endpoints * 100 / $total_endpoints" | bc -l 2>/dev/null || echo "0")
    
    # Calculate average response time (only successful requests)
    local avg_response_time=$(echo "$results" | jq 'map(select(.success and .response_time_ms)) | .[].response_time_ms' | \
        awk '{sum+=$1; count++} END {if(count>0) print sum/count; else print 0}')
    
    # Get failed endpoints
    local failed_endpoints_list=$(echo "$results" | jq -r 'map(select(.success == false)) | .[].name')
    
    jq -n \
        --argjson total_endpoints "$total_endpoints" \
        --argjson successful_endpoints "$successful_endpoints" \
        --argjson failed_endpoints "$failed_endpoints" \
        --arg success_rate "$success_rate" \
        --argjson avg_response_time "${avg_response_time:-0}" \
        --argjson failed_endpoints_list "$(printf '%s\n' $failed_endpoints_list | jq -R . | jq -s .)" \
        '{
            total_endpoints: $total_endpoints,
            successful_endpoints: $successful_endpoints,
            failed_endpoints: $failed_endpoints,
            success_rate: ($success_rate | tonumber),
            average_response_time_ms: ($avg_response_time | tonumber),
            failed_endpoints: $failed_endpoints_list,
            status: if $failed_endpoints > 0 then "unhealthy" else "healthy" end
        }'
}

# Create alerts for failed endpoints
create_alerts() {
    local results=$1
    
    local failed_endpoints=$(echo "$results" | jq 'map(select(.success == false))')
    
    if [[ "$failed_endpoints" != "null" && "$failed_endpoints" != "[]" ]]; then
        local failed_count=$(echo "$failed_endpoints" | jq '. | length')
        log "${RED}🚨 ALERT: $failed_count endpoints failed health check!${NC}"
        
        echo "$failed_endpoints" | jq -c '.' | while read -r endpoint; do
            local name=$(echo "$endpoint" | jq -r '.name')
            local url=$(echo "$endpoint" | jq -r '.url')
            local error=$(echo "$endpoint" | jq -r '.error // "Unknown error"')
            local status_code=$(echo "$endpoint" | jq -r '.status_code // "N/A"')
            
            log "${RED}Failed endpoint: $name${NC}"
            log "${RED}  URL: $url${NC}"
            log "${RED}  Status Code: $status_code${NC}"
            log "${RED}  Error: $error${NC}"
        done
        
        # Send webhook notification if configured
        local webhook_url=$(jq -r '.global_settings.notification_webhook // ""' "$CONFIG_FILE")
        if [[ -n "$webhook_url" && "$webhook_url" != "null" ]]; then
            send_webhook_alert "$webhook_url" "$failed_endpoints"
        fi
    fi
}

# Send webhook alert
send_webhook_alert() {
    local webhook_url=$1
    local failed_endpoints=$2
    
    local alert_message=$(jq -n \
        --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --argjson failed_endpoints "$failed_endpoints" \
        '{
            timestamp: $timestamp,
            alert_type: "endpoint_health_check",
            severity: "critical",
            message: "One or more endpoints failed health check",
            failed_endpoints: $failed_endpoints
        }')
    
    if curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$alert_message" \
        "$webhook_url" &>/dev/null; then
        log "Webhook alert sent successfully"
    else
        log "Failed to send webhook alert"
    fi
}

# Generate detailed report
generate_report() {
    local results=$1
    local summary=$2
    
    local report=$(jq -n \
        --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --argjson summary "$summary" \
        --argjson results "$results" \
        --argjson config "$(jq '{endpoints: [.endpoints[].name], global_settings}' "$CONFIG_FILE")" \
        '{
            timestamp: $timestamp,
            summary: $summary,
            results: $results,
            configuration: $config,
            check_settings: {
                timeout: env.TIMEOUT,
                retry_count: env.RETRY_COUNT,
                retry_delay: env.RETRY_DELAY,
                user_agent: env.USER_AGENT,
                follow_redirects: env.FOLLOW_REDIRECTS
            }
        }')
    
    echo "$report" > "$OUTPUT_FILE"
    
    # Display summary
    echo -e "\n${BLUE}=== Endpoint Health Check Summary ===${NC}"
    echo "Total endpoints: $(echo "$summary" | jq -r '.total_endpoints')"
    echo "Successful: $(echo "$summary" | jq -r '.successful_endpoints')"
    echo "Failed: $(echo "$summary" | jq -r '.failed_endpoints')"
    echo "Success rate: $(echo "$summary" | jq -r '.success_rate')%"
    echo "Average response time: $(echo "$summary" | jq -r '.average_response_time_ms')ms"
    echo "Overall status: $(echo "$summary" | jq -r '.status')"
    
    if [[ "$(echo "$summary" | jq -r '.failed_endpoints')" != "0" ]]; then
        echo -e "\n${RED}Failed endpoints:${NC}"
        echo "$summary" | jq -r '.failed_endpoints_list[]' | while read -r name; do
            echo "  - $name"
        done
    fi
}

# Main execution
main() {
    log "${GREEN}Starting Endpoint Health Checker...${NC}"
    log "Log file: $LOG_FILE"
    log "Output file: $OUTPUT_FILE"
    log "Config file: $CONFIG_FILE"
    log "Timeout: ${TIMEOUT}s"
    log "Retry count: $RETRY_COUNT"
    
    check_dependencies
    
    # Check all endpoints
    local results=$(check_all_endpoints)
    
    # Generate summary
    local summary=$(generate_summary "$results")
    
    # Create alerts
    create_alerts "$results"
    
    # Generate report
    generate_report "$results" "$summary"
    
    log "${GREEN}Endpoint health check completed successfully!${NC}"
    log "Results saved to: $OUTPUT_FILE"
    log "Logs saved to: $LOG_FILE"
}

# Execute main function
main "$@"
