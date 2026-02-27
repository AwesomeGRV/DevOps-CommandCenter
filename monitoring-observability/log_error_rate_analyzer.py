#!/usr/bin/env python3
"""
Log Error Rate Analyzer
Author: CloudOps-SRE-Toolkit
Description: Analyze log files to calculate error rates and identify patterns
"""

import os
import json
import logging
import argparse
import re
import gzip
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Iterator
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'log_error_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class LogEntry:
    """Data class for log entry"""
    timestamp: datetime
    level: str
    message: str
    source: str
    raw_line: str
    error_type: Optional[str] = None
    service: Optional[str] = None
    request_id: Optional[str] = None
    user_id: Optional[str] = None

@dataclass
class ErrorPattern:
    """Data class for error pattern"""
    pattern: str
    count: int
    percentage: float
    samples: List[str]
    first_seen: datetime
    last_seen: datetime

@dataclass
class ErrorAnalysisReport:
    """Data class for error analysis report"""
    timestamp: str
    log_files_analyzed: List[str]
    total_entries: int
    error_entries: int
    warning_entries: int
    info_entries: int
    other_entries: int
    error_rate: float
    warning_rate: float
    time_range: Dict[str, str]
    error_patterns: List[ErrorPattern]
    hourly_error_distribution: Dict[str, int]
    service_error_distribution: Dict[str, int]
    top_error_messages: List[Dict[str, Any]]
    recommendations: List[str]

class LogErrorRateAnalyzer:
    """Analyze log files for error rates and patterns"""
    
    def __init__(self, config_file: str = "config/log_analysis_config.json"):
        self.config = self._load_config(config_file)
        self.error_patterns = self._load_error_patterns()
        self.log_entries = []
        
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {config_file} not found. Using defaults.")
            return self._get_default_config()
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in config file {config_file}")
            raise
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            "log_sources": [
                {
                    "name": "application_logs",
                    "path": "/var/log/app/*.log",
                    "format": "custom",
                    "timestamp_format": "%Y-%m-%d %H:%M:%S",
                    "log_level_regex": r"(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)"
                }
            ],
            "error_patterns": [
                {
                    "name": "Database Connection Error",
                    "regex": r"(?i)(database|db).*connection.*(error|failed|timeout)",
                    "severity": "high"
                },
                {
                    "name": "HTTP 5xx Error",
                    "regex": r"HTTP/[0-9\.]+\s+5[0-9]{2}",
                    "severity": "high"
                },
                {
                    "name": "Out of Memory",
                    "regex": r"(?i)(out of memory|oom|memory.*error)",
                    "severity": "critical"
                },
                {
                    "name": "Authentication Failed",
                    "regex": r"(?i)(auth|authentication|login).*failed",
                    "severity": "medium"
                },
                {
                    "name": "File Not Found",
                    "regex": r"(?i)(file|path).*not found|no such file",
                    "severity": "low"
                }
            ],
            "analysis": {
                "time_window_hours": 24,
                "min_error_rate_threshold": 0.01,  # 1%
                "top_error_count": 20,
                "hourly_distribution": true,
                "service_distribution": true
            },
            "output": {
                "format": ["json", "csv", "dashboard"],
                "include_samples": true,
                "max_samples_per_pattern": 5
            }
        }
    
    def _load_error_patterns(self) -> List[Dict[str, Any]]:
        """Load error patterns from configuration"""
        patterns = []
        for pattern_config in self.config.get("error_patterns", []):
            patterns.append({
                "name": pattern_config["name"],
                "regex": pattern_config["regex"],
                "severity": pattern_config.get("severity", "medium"),
                "compiled": re.compile(pattern_config["regex"])
            })
        return patterns
    
    def parse_log_file(self, file_path: str, log_config: Dict[str, Any]) -> Iterator[LogEntry]:
        """Parse a single log file"""
        logger.info(f"Parsing log file: {file_path}")
        
        # Check if file is gzipped
        opener = gzip.open if file_path.endswith('.gz') else open
        
        try:
            with opener(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        entry = self._parse_log_line(line.strip(), log_config, file_path)
                        if entry:
                            yield entry
                    except Exception as e:
                        logger.debug(f"Error parsing line {line_num} in {file_path}: {str(e)}")
                        continue
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {str(e)}")
    
    def _parse_log_line(self, line: str, log_config: Dict[str, Any], source_file: str) -> Optional[LogEntry]:
        """Parse a single log line"""
        if not line.strip():
            return None
        
        # Try different log formats
        log_format = log_config.get("format", "custom")
        
        if log_format == "apache_common":
            return self._parse_apache_common_log(line, source_file)
        elif log_format == "nginx":
            return self._parse_nginx_log(line, source_file)
        elif log_format == "json":
            return self._parse_json_log(line, source_file)
        else:
            return self._parse_custom_log(line, log_config, source_file)
    
    def _parse_custom_log(self, line: str, log_config: Dict[str, Any], source_file: str) -> Optional[LogEntry]:
        """Parse custom log format"""
        # Extract timestamp
        timestamp_format = log_config.get("timestamp_format", "%Y-%m-%d %H:%M:%S")
        log_level_regex = log_config.get("log_level_regex", r"(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)")
        
        # Try to extract timestamp
        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', line)
        if timestamp_match:
            try:
                timestamp_str = timestamp_match.group(1)
                timestamp = datetime.strptime(timestamp_str.replace('T', ' '), timestamp_format)
            except ValueError:
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()
        
        # Extract log level
        level_match = re.search(log_level_regex, line, re.IGNORECASE)
        level = level_match.group(1).upper() if level_match else "INFO"
        
        # Extract service name if available
        service_match = re.search(r'\[([a-zA-Z0-9_-]+)\]', line)
        service = service_match.group(1) if service_match else None
        
        # Extract request ID if available
        request_id_match = re.search(r'request[_-]?id[:\s=]+([a-zA-Z0-9-]+)', line, re.IGNORECASE)
        request_id = request_id_match.group(1) if request_id_match else None
        
        # Extract user ID if available
        user_id_match = re.search(r'user[_-]?id[:\s=]+([a-zA-Z0-9-]+)', line, re.IGNORECASE)
        user_id = user_id_match.group(1) if user_id_match else None
        
        # Classify error type
        error_type = self._classify_error(line)
        
        return LogEntry(
            timestamp=timestamp,
            level=level,
            message=line,
            source=source_file,
            raw_line=line,
            error_type=error_type,
            service=service,
            request_id=request_id,
            user_id=user_id
        )
    
    def _parse_apache_common_log(self, line: str, source_file: str) -> Optional[LogEntry]:
        """Parse Apache Common Log Format"""
        # Apache Common Log Format: IP - - [timestamp] "method url protocol" status size
        pattern = r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\S+)'
        match = re.match(pattern, line)
        
        if not match:
            return None
        
        ip, timestamp_str, request, status_code, size = match.groups()
        
        try:
            timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            timestamp = datetime.now()
        
        status = int(status_code)
        
        # Determine log level based on status code
        if status >= 500:
            level = "ERROR"
        elif status >= 400:
            level = "WARNING"
        else:
            level = "INFO"
        
        # Classify error type
        error_type = self._classify_error(line)
        
        return LogEntry(
            timestamp=timestamp,
            level=level,
            message=line,
            source=source_file,
            raw_line=line,
            error_type=error_type,
            service="apache"
        )
    
    def _parse_nginx_log(self, line: str, source_file: str) -> Optional[LogEntry]:
        """Parse Nginx log format"""
        # Nginx default format similar to Apache
        return self._parse_apache_common_log(line, source_file)
    
    def _parse_json_log(self, line: str, source_file: str) -> Optional[LogEntry]:
        """Parse JSON log format"""
        try:
            log_data = json.loads(line)
            
            # Extract common fields
            timestamp_str = log_data.get('timestamp', log_data.get('time', log_data.get('@timestamp')))
            level = log_data.get('level', log_data.get('severity', 'INFO')).upper()
            message = log_data.get('message', log_data.get('msg', str(log_data)))
            service = log_data.get('service', log_data.get('application'))
            request_id = log_data.get('request_id', log_data.get('trace_id'))
            user_id = log_data.get('user_id', log_data.get('user'))
            
            # Parse timestamp
            if timestamp_str:
                try:
                    # Try different timestamp formats
                    for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S']:
                        try:
                            timestamp = datetime.strptime(timestamp_str, fmt)
                            break
                        except ValueError:
                            continue
                    else:
                        timestamp = datetime.now()
                except:
                    timestamp = datetime.now()
            else:
                timestamp = datetime.now()
            
            # Classify error type
            error_type = self._classify_error(message)
            
            return LogEntry(
                timestamp=timestamp,
                level=level,
                message=message,
                source=source_file,
                raw_line=line,
                error_type=error_type,
                service=service,
                request_id=request_id,
                user_id=user_id
            )
        
        except json.JSONDecodeError:
            return None
    
    def _classify_error(self, message: str) -> Optional[str]:
        """Classify error type based on message content"""
        for pattern in self.error_patterns:
            if pattern["compiled"].search(message):
                return pattern["name"]
        return None
    
    def find_log_files(self, log_config: Dict[str, Any]) -> List[str]:
        """Find log files based on configuration"""
        path_pattern = log_config.get("path", "*.log")
        
        # Handle glob patterns
        if '*' in path_pattern:
            from glob import glob
            files = glob(path_pattern, recursive=True)
        else:
            if os.path.isfile(path_pattern):
                files = [path_pattern]
            elif os.path.isdir(path_pattern):
                files = [os.path.join(path_pattern, f) for f in os.listdir(path_pattern) 
                        if f.endswith('.log') or f.endswith('.log.gz')]
            else:
                files = []
        
        # Filter by modification time if time window is specified
        time_window_hours = self.config.get("analysis", {}).get("time_window_hours", 24)
        if time_window_hours > 0:
            cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
            filtered_files = []
            
            for file_path in files:
                try:
                    mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                    if mtime >= cutoff_time:
                        filtered_files.append(file_path)
                except OSError:
                    continue
            
            files = filtered_files
        
        logger.info(f"Found {len(files)} log files to analyze")
        return sorted(files)
    
    def analyze_logs(self) -> ErrorAnalysisReport:
        """Analyze all configured log sources"""
        logger.info("Starting log analysis...")
        
        all_entries = []
        analyzed_files = []
        
        # Process each log source
        for log_source in self.config.get("log_sources", []):
            log_files = self.find_log_files(log_source)
            analyzed_files.extend(log_files)
            
            for log_file in log_files:
                try:
                    entries = list(self.parse_log_file(log_file, log_source))
                    all_entries.extend(entries)
                    logger.info(f"Parsed {len(entries)} entries from {log_file}")
                except Exception as e:
                    logger.error(f"Error processing {log_file}: {str(e)}")
        
        logger.info(f"Total log entries parsed: {len(all_entries)}")
        
        # Perform analysis
        return self._generate_analysis_report(all_entries, analyzed_files)
    
    def _generate_analysis_report(self, entries: List[LogEntry], analyzed_files: List[str]) -> ErrorAnalysisReport:
        """Generate comprehensive analysis report"""
        if not entries:
            return ErrorAnalysisReport(
                timestamp=datetime.now().isoformat(),
                log_files_analyzed=analyzed_files,
                total_entries=0,
                error_entries=0,
                warning_entries=0,
                info_entries=0,
                other_entries=0,
                error_rate=0.0,
                warning_rate=0.0,
                time_range={},
                error_patterns=[],
                hourly_error_distribution={},
                service_error_distribution={},
                top_error_messages=[],
                recommendations=["No log entries found for analysis"]
            )
        
        # Count entries by level
        level_counts = Counter(entry.level for entry in entries)
        total_entries = len(entries)
        error_entries = level_counts.get('ERROR', 0) + level_counts.get('FATAL', 0) + level_counts.get('CRITICAL', 0)
        warning_entries = level_counts.get('WARNING', 0) + level_counts.get('WARN', 0)
        info_entries = level_counts.get('INFO', 0)
        other_entries = total_entries - error_entries - warning_entries - info_entries
        
        # Calculate rates
        error_rate = (error_entries / total_entries) * 100 if total_entries > 0 else 0
        warning_rate = (warning_entries / total_entries) * 100 if total_entries > 0 else 0
        
        # Time range
        timestamps = [entry.timestamp for entry in entries]
        time_range = {
            "start": min(timestamps).isoformat(),
            "end": max(timestamps).isoformat()
        }
        
        # Analyze error patterns
        error_patterns = self._analyze_error_patterns(entries)
        
        # Hourly distribution
        hourly_error_distribution = self._calculate_hourly_distribution(entries)
        
        # Service distribution
        service_error_distribution = self._calculate_service_distribution(entries)
        
        # Top error messages
        top_error_messages = self._get_top_error_messages(entries)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(error_rate, error_patterns, entries)
        
        return ErrorAnalysisReport(
            timestamp=datetime.now().isoformat(),
            log_files_analyzed=analyzed_files,
            total_entries=total_entries,
            error_entries=error_entries,
            warning_entries=warning_entries,
            info_entries=info_entries,
            other_entries=other_entries,
            error_rate=error_rate,
            warning_rate=warning_rate,
            time_range=time_range,
            error_patterns=error_patterns,
            hourly_error_distribution=hourly_error_distribution,
            service_error_distribution=service_error_distribution,
            top_error_messages=top_error_messages,
            recommendations=recommendations
        )
    
    def _analyze_error_patterns(self, entries: List[LogEntry]) -> List[ErrorPattern]:
        """Analyze error patterns in log entries"""
        error_entries = [entry for entry in entries if entry.level in ['ERROR', 'FATAL', 'CRITICAL']]
        
        pattern_counts = defaultdict(list)
        pattern_first_seen = {}
        pattern_last_seen = {}
        
        for entry in error_entries:
            if entry.error_type:
                pattern_counts[entry.error_type].append(entry.message)
                
                if entry.error_type not in pattern_first_seen:
                    pattern_first_seen[entry.error_type] = entry.timestamp
                pattern_last_seen[entry.error_type] = entry.timestamp
        
        error_patterns = []
        total_errors = len(error_entries)
        
        for pattern_name, messages in pattern_counts.items():
            count = len(messages)
            percentage = (count / total_errors) * 100 if total_errors > 0 else 0
            
            # Get unique samples
            unique_messages = list(set(messages[:10]))  # Limit to first 10 unique messages
            
            error_pattern = ErrorPattern(
                pattern=pattern_name,
                count=count,
                percentage=percentage,
                samples=unique_messages,
                first_seen=pattern_first_seen[pattern_name],
                last_seen=pattern_last_seen[pattern_name]
            )
            error_patterns.append(error_pattern)
        
        # Sort by count (descending)
        error_patterns.sort(key=lambda x: x.count, reverse=True)
        
        return error_patterns
    
    def _calculate_hourly_distribution(self, entries: List[LogEntry]) -> Dict[str, int]:
        """Calculate hourly distribution of errors"""
        error_entries = [entry for entry in entries if entry.level in ['ERROR', 'FATAL', 'CRITICAL']]
        
        hourly_counts = defaultdict(int)
        
        for entry in error_entries:
            hour_key = entry.timestamp.strftime('%Y-%m-%d %H:00')
            hourly_counts[hour_key] += 1
        
        return dict(hourly_counts)
    
    def _calculate_service_distribution(self, entries: List[LogEntry]) -> Dict[str, int]:
        """Calculate error distribution by service"""
        error_entries = [entry for entry in entries if entry.level in ['ERROR', 'FATAL', 'CRITICAL']]
        
        service_counts = defaultdict(int)
        
        for entry in error_entries:
            service = entry.service or "unknown"
            service_counts[service] += 1
        
        return dict(sorted(service_counts.items(), key=lambda x: x[1], reverse=True))
    
    def _get_top_error_messages(self, entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Get top error messages"""
        error_entries = [entry for entry in entries if entry.level in ['ERROR', 'FATAL', 'CRITICAL']]
        
        # Count unique error messages (normalized)
        message_counts = defaultdict(int)
        message_samples = {}
        
        for entry in error_entries:
            # Normalize message (remove timestamps, IPs, etc.)
            normalized = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', '[TIMESTAMP]', entry.message)
            normalized = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]', normalized)
            normalized = re.sub(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '[UUID]', normalized)
            
            message_counts[normalized] += 1
            if normalized not in message_samples:
                message_samples[normalized] = entry.message
        
        # Get top messages
        top_count = self.config.get("analysis", {}).get("top_error_count", 20)
        top_messages = []
        
        for message, count in sorted(message_counts.items(), key=lambda x: x[1], reverse=True)[:top_count]:
            top_messages.append({
                "normalized_message": message,
                "count": count,
                "sample": message_samples[message]
            })
        
        return top_messages
    
    def _generate_recommendations(self, error_rate: float, error_patterns: List[ErrorPattern], entries: List[LogEntry]) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        
        # Error rate recommendations
        threshold = self.config.get("analysis", {}).get("min_error_rate_threshold", 0.01) * 100
        if error_rate > threshold:
            recommendations.append(f"High error rate detected ({error_rate:.2f}%). Consider immediate investigation.")
        
        # Pattern-specific recommendations
        for pattern in error_patterns[:5]:  # Top 5 patterns
            if pattern.pattern == "Database Connection Error":
                recommendations.append("Database connection errors detected. Check database availability and connection pool settings.")
            elif pattern.pattern == "HTTP 5xx Error":
                recommendations.append("HTTP 5xx errors detected. Check application server health and upstream dependencies.")
            elif pattern.pattern == "Out of Memory":
                recommendations.append("Out of memory errors detected. Consider increasing memory allocation or optimizing memory usage.")
            elif pattern.pattern == "Authentication Failed":
                recommendations.append("Authentication failures detected. Review authentication mechanisms and user access.")
        
        # Time-based recommendations
        if error_patterns:
            recent_errors = [p for p in error_patterns if 
                           (datetime.now() - p.last_seen).total_seconds() < 3600]  # Last hour
            if recent_errors:
                recommendations.append("Recent error patterns detected. Monitor closely for potential incidents.")
        
        # General recommendations
        if len(entries) > 0:
            recommendations.append("Implement structured logging for better analysis capabilities.")
            recommendations.append("Set up automated alerting for error rate thresholds.")
            recommendations.append("Consider implementing log aggregation and centralized monitoring.")
        
        return recommendations
    
    def save_report(self, report: ErrorAnalysisReport, output_formats: List[str]):
        """Save report in specified formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if 'json' in output_formats:
            json_file = f"log_error_analysis_report_{timestamp}.json"
            with open(json_file, 'w') as f:
                json.dump(asdict(report), f, indent=2, default=str)
            logger.info(f"JSON report saved to: {json_file}")
        
        if 'csv' in output_formats:
            csv_file = f"log_error_analysis_report_{timestamp}.csv"
            self._save_csv_report(report, csv_file)
            logger.info(f"CSV report saved to: {csv_file}")
        
        if 'dashboard' in output_formats:
            dashboard_file = f"log_error_analysis_dashboard_{timestamp}.png"
            self._generate_dashboard(report, dashboard_file)
            logger.info(f"Dashboard saved to: {dashboard_file}")
    
    def _save_csv_report(self, report: ErrorAnalysisReport, filename: str):
        """Save report as CSV"""
        # Create multiple CSV files for different aspects
        
        # Error patterns CSV
        patterns_data = []
        for pattern in report.error_patterns:
            patterns_data.append({
                'Pattern': pattern.pattern,
                'Count': pattern.count,
                'Percentage': pattern.percentage,
                'First Seen': pattern.first_seen.isoformat(),
                'Last Seen': pattern.last_seen.isoformat()
            })
        
        patterns_df = pd.DataFrame(patterns_data)
        patterns_df.to_csv(filename.replace('.csv', '_patterns.csv'), index=False)
        
        # Hourly distribution CSV
        hourly_df = pd.DataFrame(list(report.hourly_error_distribution.items()), 
                                columns=['Hour', 'Error Count'])
        hourly_df.to_csv(filename.replace('.csv', '_hourly.csv'), index=False)
        
        # Service distribution CSV
        service_df = pd.DataFrame(list(report.service_error_distribution.items()), 
                                columns=['Service', 'Error Count'])
        service_df.to_csv(filename.replace('.csv', '_service.csv'), index=False)
    
    def _generate_dashboard(self, report: ErrorAnalysisReport, filename: str):
        """Generate visual dashboard"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('Log Error Analysis Dashboard', fontsize=16)
        
        # 1. Log level distribution
        levels = ['Error', 'Warning', 'Info', 'Other']
        counts = [report.error_entries, report.warning_entries, report.info_entries, report.other_entries]
        colors = ['red', 'orange', 'green', 'gray']
        
        axes[0, 0].pie(counts, labels=levels, colors=colors, autopct='%1.1f%%')
        axes[0, 0].set_title('Log Level Distribution')
        
        # 2. Top error patterns
        if report.error_patterns:
            patterns = [p.pattern for p in report.error_patterns[:10]]
            pattern_counts = [p.count for p in report.error_patterns[:10]]
            
            axes[0, 1].barh(patterns, pattern_counts, color='lightcoral')
            axes[0, 1].set_title('Top Error Patterns')
            axes[0, 1].set_xlabel('Count')
        
        # 3. Hourly error distribution
        if report.hourly_error_distribution:
            hours = list(report.hourly_error_distribution.keys())
            error_counts = list(report.hourly_error_distribution.values())
            
            axes[1, 0].plot(range(len(hours)), error_counts, marker='o')
            axes[1, 0].set_title('Hourly Error Distribution')
            axes[1, 0].set_xlabel('Hour')
            axes[1, 0].set_ylabel('Error Count')
            axes[1, 0].tick_params(axis='x', rotation=45)
        
        # 4. Service error distribution
        if report.service_error_distribution:
            services = list(report.service_error_distribution.keys())[:10]
            service_counts = list(report.service_error_distribution.values())[:10]
            
            axes[1, 1].bar(services, service_counts, color='skyblue')
            axes[1, 1].set_title('Error Distribution by Service')
            axes[1, 1].set_xlabel('Service')
            axes[1, 1].set_ylabel('Error Count')
            axes[1, 1].tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Analyze log files for error rates')
    parser.add_argument('--config', type=str, default='config/log_analysis_config.json', 
                       help='Configuration file path')
    parser.add_argument('--output-format', nargs='+', default=['json', 'dashboard'], 
                       choices=['json', 'csv', 'dashboard'], help='Output formats')
    parser.add_argument('--log-path', type=str, help='Override log path from config')
    
    args = parser.parse_args()
    
    try:
        analyzer = LogErrorRateAnalyzer(args.config)
        
        # Override log path if provided
        if args.log_path:
            analyzer.config["log_sources"][0]["path"] = args.log_path
        
        # Run analysis
        report = analyzer.analyze_logs()
        
        # Save report
        analyzer.save_report(report, args.output_format)
        
        # Print summary
        print(f"\n=== Log Error Analysis Summary ===")
        print(f"Log files analyzed: {len(report.log_files_analyzed)}")
        print(f"Total entries: {report.total_entries}")
        print(f"Error entries: {report.error_entries}")
        print(f"Warning entries: {report.warning_entries}")
        print(f"Error rate: {report.error_rate:.2f}%")
        print(f"Warning rate: {report.warning_rate:.2f}%")
        
        if report.error_patterns:
            print(f"\nTop error patterns:")
            for i, pattern in enumerate(report.error_patterns[:5], 1):
                print(f"{i}. {pattern.pattern}: {pattern.count} occurrences ({pattern.percentage:.1f}%)")
        
        if report.recommendations:
            print(f"\nRecommendations:")
            for i, rec in enumerate(report.recommendations, 1):
                print(f"{i}. {rec}")
        
        logger.info("Log error analysis completed successfully!")
        
    except Exception as e:
        logger.error(f"Error during log analysis: {str(e)}")
        raise

if __name__ == "__main__":
    main()
