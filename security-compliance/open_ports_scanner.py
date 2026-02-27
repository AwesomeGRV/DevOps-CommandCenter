#!/usr/bin/env python3
"""
Open Ports Scanner
Author: CloudOps-SRE-Toolkit
Description: Scan networks and hosts for open ports and security vulnerabilities
"""

import os
import json
import logging
import argparse
import asyncio
import socket
import ssl
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import ipaddress
import concurrent.futures
import pandas as pd
import matplotlib.pyplot as plt

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'open_ports_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class PortScanResult:
    """Data class for port scan result"""
    host: str
    port: int
    protocol: str
    state: str  # open, closed, filtered
    service: Optional[str]
    version: Optional[str]
    banner: Optional[str]
    ssl_info: Optional[Dict[str, Any]]
    timestamp: datetime
    scan_duration_ms: float

@dataclass
class VulnerabilityFinding:
    """Data class for vulnerability finding"""
    host: str
    port: int
    severity: str  # critical, high, medium, low, info
    category: str
    description: str
    recommendation: str
    cve_id: Optional[str]
    cvss_score: Optional[float]

@dataclass
class ScanReport:
    """Data class for scan report"""
    timestamp: str
    scan_targets: List[str]
    total_hosts: int
    total_ports_scanned: int
    open_ports_count: int
    scan_duration_seconds: float
    port_results: List[PortScanResult]
    vulnerabilities: List[VulnerabilityFinding]
    summary_statistics: Dict[str, Any]
    recommendations: List[str]

class OpenPortsScanner:
    """Scan for open ports and security vulnerabilities"""
    
    def __init__(self, config_file: str = "config/port_scan_config.json"):
        self.config = self._load_config(config_file)
        self.common_ports = self._get_common_ports()
        self.service_banners = self._get_service_banners()
        
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
            "scan_targets": [
                "127.0.0.1",
                "192.168.1.1"
            ],
            "port_ranges": [
                {"start": 1, "end": 1024},  # Well-known ports
                {"start": 8080, "end": 8090}  # Common application ports
            ],
            "scan_options": {
                "timeout_seconds": 3,
                "max_concurrent_scans": 100,
                "enable_banner_grabbing": True,
                "enable_ssl_check": True,
                "enable_service_detection": True,
                "scan_type": "tcp"  # tcp, udp, both
            },
            "vulnerability_checks": {
                "enabled": True,
                "check_default_credentials": True,
                "check_weak_ssl": True,
                "check_outdated_services": True,
                "check_anonymous_access": True
            },
            "output": {
                "format": ["json", "csv", "dashboard"],
                "include_banners": True,
                "max_banner_length": 200
            }
        }
    
    def _get_common_ports(self) -> List[int]:
        """Get list of common ports to scan"""
        return [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017
        ]
    
    def _get_service_banners(self) -> Dict[int, str]:
        """Get common service banners"""
        return {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            9200: "Elasticsearch",
            27017: "MongoDB"
        }
    
    def resolve_targets(self, targets: List[str]) -> List[str]:
        """Resolve target hostnames to IP addresses"""
        resolved_targets = []
        
        for target in targets:
            try:
                # Check if it's an IP address
                ipaddress.ip_address(target)
                resolved_targets.append(target)
                logger.info(f"Added IP target: {target}")
            except ValueError:
                # Try to resolve hostname
                try:
                    ip = socket.gethostbyname(target)
                    resolved_targets.append(ip)
                    logger.info(f"Resolved {target} to {ip}")
                except socket.gaierror:
                    logger.error(f"Could not resolve target: {target}")
        
        return list(set(resolved_targets))  # Remove duplicates
    
    def scan_port(self, host: str, port: int, timeout: int = 3) -> PortScanResult:
        """Scan a single port on a host"""
        start_time = datetime.now()
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Try to connect
            result = sock.connect_ex((host, port))
            scan_duration = (datetime.now() - start_time).total_seconds() * 1000
            
            if result == 0:
                # Port is open
                service = self.service_banners.get(port, "unknown")
                banner = None
                version = None
                ssl_info = None
                
                # Grab banner if enabled
                if self.config.get("scan_options", {}).get("enable_banner_grabbing", True):
                    try:
                        banner = self._grab_banner(sock, port)
                        version = self._extract_version_from_banner(banner)
                    except:
                        pass
                
                # Check SSL if enabled and port is commonly SSL
                if (self.config.get("scan_options", {}).get("enable_ssl_check", True) and 
                    port in [443, 8443, 993, 995, 636, 989, 990]):
                    try:
                        ssl_info = self._check_ssl(host, port)
                    except:
                        pass
                
                sock.close()
                
                return PortScanResult(
                    host=host,
                    port=port,
                    protocol="TCP",
                    state="open",
                    service=service,
                    version=version,
                    banner=banner,
                    ssl_info=ssl_info,
                    timestamp=start_time,
                    scan_duration_ms=scan_duration
                )
            else:
                sock.close()
                return PortScanResult(
                    host=host,
                    port=port,
                    protocol="TCP",
                    state="closed",
                    service=None,
                    version=None,
                    banner=None,
                    ssl_info=None,
                    timestamp=start_time,
                    scan_duration_ms=scan_duration
                )
        
        except Exception as e:
            scan_duration = (datetime.now() - start_time).total_seconds() * 1000
            return PortScanResult(
                host=host,
                port=port,
                protocol="TCP",
                state="filtered",
                service=None,
                version=None,
                banner=None,
                ssl_info=None,
                timestamp=start_time,
                scan_duration_ms=scan_duration
            )
    
    def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        """Grab service banner from open port"""
        try:
            # Send a simple HTTP request for web ports
            if port in [80, 8080, 8000, 8081]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            # Send SSH version request for SSH
            elif port == 22:
                pass  # SSH server sends banner automatically
            # Send FTP request for FTP
            elif port == 21:
                pass  # FTP server sends banner automatically
            else:
                # Generic probe
                sock.send(b"\r\n")
            
            # Receive response
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            return response.strip()[:200]  # Limit banner length
        
        except:
            return None
    
    def _extract_version_from_banner(self, banner: str) -> Optional[str]:
        """Extract version information from service banner"""
        if not banner:
            return None
        
        # Common version patterns
        import re
        
        # SSH version pattern
        ssh_match = re.search(r'SSH-[\d.]+-(.+)', banner)
        if ssh_match:
            return ssh_match.group(1)
        
        # HTTP server pattern
        http_match = re.search(r'Server:\s*(.+)', banner, re.IGNORECASE)
        if http_match:
            return http_match.group(1)
        
        # FTP version pattern
        ftp_match = re.search(r'(\d+\.\d+\.\d+)', banner)
        if ftp_match:
            return ftp_match.group(1)
        
        return None
    
    def _check_ssl(self, host: str, port: int) -> Dict[str, Any]:
        """Check SSL/TLS configuration"""
        ssl_info = {
            "ssl_enabled": True,
            "certificate_info": {},
            "protocol_version": None,
            "cipher_suite": None,
            "vulnerabilities": []
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate info
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info["protocol_version"] = ssock.version()
                    ssl_info["cipher_suite"] = ssock.cipher()
                    
                    if cert:
                        ssl_info["certificate_info"] = {
                            "subject": dict(x[0] for x in cert["subject"]),
                            "issuer": dict(x[0] for x in cert["issuer"]),
                            "version": cert["version"],
                            "serial_number": cert["serialNumber"],
                            "not_before": cert["notBefore"],
                            "not_after": cert["notAfter"],
                            "subject_alt_names": cert.get("subjectAltName", [])
                        }
                        
                        # Check certificate expiry
                        from datetime import datetime
                        expiry_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        if expiry_date < datetime.now():
                            ssl_info["vulnerabilities"].append("Certificate expired")
                        elif (expiry_date - datetime.now()).days < 30:
                            ssl_info["vulnerabilities"].append("Certificate expires soon")
        
        except Exception as e:
            ssl_info["ssl_enabled"] = False
            ssl_info["error"] = str(e)
        
        return ssl_info
    
    def scan_host(self, host: str, ports: List[int]) -> List[PortScanResult]:
        """Scan all specified ports on a host"""
        logger.info(f"Scanning host {host} on {len(ports)} ports")
        
        results = []
        timeout = self.config.get("scan_options", {}).get("timeout_seconds", 3)
        
        # Use thread pool for concurrent scanning
        max_concurrent = self.config.get("scan_options", {}).get("max_concurrent_scans", 100)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            # Submit all scan tasks
            future_to_port = {executor.submit(self.scan_port, host, port, timeout): port for port in ports}
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.state == "open":
                        logger.info(f"Found open port: {host}:{port} ({result.service})")
                
                except Exception as e:
                    logger.error(f"Error scanning {host}:{port} - {str(e)}")
        
        return results
    
    def check_vulnerabilities(self, scan_results: List[PortScanResult]) -> List[VulnerabilityFinding]:
        """Check for security vulnerabilities in scan results"""
        vulnerabilities = []
        
        if not self.config.get("vulnerability_checks", {}).get("enabled", True):
            return vulnerabilities
        
        for result in scan_results:
            if result.state != "open":
                continue
            
            # Check for default credentials
            if self.config.get("vulnerability_checks", {}).get("check_default_credentials", True):
                vulns = self._check_default_credentials(result)
                vulnerabilities.extend(vulns)
            
            # Check for weak SSL
            if self.config.get("vulnerability_checks", {}).get("check_weak_ssl", True):
                vulns = self._check_weak_ssl(result)
                vulnerabilities.extend(vulns)
            
            # Check for outdated services
            if self.config.get("vulnerability_checks", {}).get("check_outdated_services", True):
                vulns = self._check_outdated_services(result)
                vulnerabilities.extend(vulns)
            
            # Check for anonymous access
            if self.config.get("vulnerability_checks", {}).get("check_anonymous_access", True):
                vulns = self._check_anonymous_access(result)
                vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _check_default_credentials(self, result: PortScanResult) -> List[VulnerabilityFinding]:
        """Check for services with default credentials"""
        vulnerabilities = []
        
        # Common services with default credentials
        default_creds_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            3389: "RDP",
            5900: "VNC",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB"
        }
        
        if result.port in default_creds_services:
            vulnerabilities.append(VulnerabilityFinding(
                host=result.host,
                port=result.port,
                severity="high",
                category="default_credentials",
                description=f"{default_creds_services[result.port]} service may be using default credentials",
                recommendation="Change default credentials and implement strong authentication",
                cve_id=None,
                cvss_score=7.5
            ))
        
        return vulnerabilities
    
    def _check_weak_ssl(self, result: PortScanResult) -> List[VulnerabilityFinding]:
        """Check for weak SSL/TLS configurations"""
        vulnerabilities = []
        
        if result.ssl_info and result.ssl_info.get("ssl_enabled"):
            # Check for SSL vulnerabilities
            ssl_vulns = result.ssl_info.get("vulnerabilities", [])
            for vuln in ssl_vulns:
                severity = "high" if "expired" in vuln else "medium"
                vulnerabilities.append(VulnerabilityFinding(
                    host=result.host,
                    port=result.port,
                    severity=severity,
                    category="ssl_configuration",
                    description=f"SSL issue: {vuln}",
                    recommendation="Update SSL certificate and configuration",
                    cve_id=None,
                    cvss_score=6.5
                ))
        
        return vulnerabilities
    
    def _check_outdated_services(self, result: PortScanResult) -> List[VulnerabilityFinding]:
        """Check for outdated service versions"""
        vulnerabilities = []
        
        if result.version:
            # Check for known outdated versions
            # This is a simplified version - in practice, you'd use a vulnerability database
            outdated_patterns = {
                "Apache/2.2": "Apache 2.2.x is outdated",
                "nginx/1.14": "nginx 1.14.x may have vulnerabilities",
                "OpenSSH_7.4": "OpenSSH 7.4 has known vulnerabilities"
            }
            
            for pattern, description in outdated_patterns.items():
                if pattern.lower() in result.version.lower():
                    vulnerabilities.append(VulnerabilityFinding(
                        host=result.host,
                        port=result.port,
                        severity="medium",
                        category="outdated_service",
                        description=f"{description}: {result.version}",
                        recommendation="Update service to latest stable version",
                        cve_id=None,
                        cvss_score=5.5
                    ))
        
        return vulnerabilities
    
    def _check_anonymous_access(self, result: PortScanResult) -> List[VulnerabilityFinding]:
        """Check for anonymous access vulnerabilities"""
        vulnerabilities = []
        
        # Check for services that commonly allow anonymous access
        anonymous_services = {
            21: "FTP anonymous access",
            80: "Anonymous HTTP access",
            443: "Anonymous HTTPS access"
        }
        
        if result.port in anonymous_services:
            # This is a simplified check - in practice, you'd test actual anonymous access
            vulnerabilities.append(VulnerabilityFinding(
                host=result.host,
                port=result.port,
                severity="medium",
                category="anonymous_access",
                description=f"Potential {anonymous_services[result.port]}",
                recommendation="Review and restrict anonymous access if not required",
                cve_id=None,
                cvss_score=4.0
            ))
        
        return vulnerabilities
    
    def generate_recommendations(self, scan_results: List[PortScanResult], 
                               vulnerabilities: List[VulnerabilityFinding]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if not scan_results:
            return ["No scan results available for recommendations"]
        
        # Count open ports by service
        open_ports = [r for r in scan_results if r.state == "open"]
        service_counts = defaultdict(int)
        for result in open_ports:
            service_counts[result.service] += 1
        
        # General recommendations
        if len(open_ports) > 20:
            recommendations.append("High number of open ports detected. Review and close unnecessary services.")
        
        # Service-specific recommendations
        if service_counts.get("Telnet", 0) > 0:
            recommendations.append("Telnet service detected. Consider using SSH instead for secure remote access.")
        
        if service_counts.get("FTP", 0) > 0:
            recommendations.append("FTP service detected. Consider using SFTP or FTPS for secure file transfer.")
        
        if service_counts.get("HTTP", 0) > 0:
            recommendations.append("HTTP service detected. Consider redirecting to HTTPS for secure communication.")
        
        # SSL recommendations
        ssl_ports = [r for r in open_ports if r.port in [443, 8443, 993, 995]]
        if ssl_ports:
            https_ports = [r for r in ssl_ports if r.port in [443, 8443]]
            if https_ports:
                recommendations.append("HTTPS services detected. Ensure proper SSL/TLS configuration.")
        
        # Vulnerability-based recommendations
        if vulnerabilities:
            high_vulns = [v for v in vulnerabilities if v.severity == "critical" or v.severity == "high"]
            if high_vulns:
                recommendations.append(f"Address {len(high_vulns)} high/critical vulnerabilities immediately.")
        
        # General security recommendations
        recommendations.extend([
            "Implement network segmentation to limit exposure of critical services.",
            "Use firewalls to restrict access to necessary ports only.",
            "Regularly update services and apply security patches.",
            "Implement intrusion detection systems for monitoring.",
            "Conduct regular security assessments and penetration testing."
        ])
        
        return recommendations
    
    def generate_statistics(self, scan_results: List[PortScanResult]) -> Dict[str, Any]:
        """Generate scan statistics"""
        if not scan_results:
            return {}
        
        total_ports = len(scan_results)
        open_ports = [r for r in scan_results if r.state == "open"]
        closed_ports = [r for r in scan_results if r.state == "closed"]
        filtered_ports = [r for r in scan_results if r.state == "filtered"]
        
        # Service distribution
        service_counts = defaultdict(int)
        for result in open_ports:
            service_counts[result.service] += 1
        
        # Port distribution by range
        well_known_ports = len([r for r in open_ports if 1 <= r.port <= 1023])
        registered_ports = len([r for r in open_ports if 1024 <= r.port <= 49151])
        dynamic_ports = len([r for r in open_ports if 49152 <= r.port <= 65535])
        
        return {
            "total_ports_scanned": total_ports,
            "open_ports_count": len(open_ports),
            "closed_ports_count": len(closed_ports),
            "filtered_ports_count": len(filtered_ports),
            "open_ports_percentage": (len(open_ports) / total_ports) * 100 if total_ports > 0 else 0,
            "service_distribution": dict(service_counts),
            "port_range_distribution": {
                "well_known": well_known_ports,
                "registered": registered_ports,
                "dynamic": dynamic_ports
            },
            "most_common_services": sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        }
    
    def run_scan(self, targets: List[str] = None, port_ranges: List[Dict[str, int]] = None) -> ScanReport:
        """Run complete port scan"""
        start_time = datetime.now()
        
        # Use provided targets or config defaults
        scan_targets = targets or self.config.get("scan_targets", [])
        scan_port_ranges = port_ranges or self.config.get("port_ranges", [])
        
        # Resolve targets
        resolved_targets = self.resolve_targets(scan_targets)
        logger.info(f"Resolved {len(resolved_targets)} targets for scanning")
        
        # Build port list
        ports_to_scan = []
        for port_range in scan_port_ranges:
            start_port = port_range.get("start", 1)
            end_port = port_range.get("end", 1024)
            ports_to_scan.extend(range(start_port, end_port + 1))
        
        # Add common ports if not already included
        for port in self.common_ports:
            if port not in ports_to_scan:
                ports_to_scan.append(port)
        
        ports_to_scan = sorted(list(set(ports_to_scan)))  # Remove duplicates and sort
        logger.info(f"Scanning {len(ports_to_scan)} ports on {len(resolved_targets)} hosts")
        
        # Scan all hosts
        all_results = []
        for host in resolved_targets:
            host_results = self.scan_host(host, ports_to_scan)
            all_results.extend(host_results)
        
        # Check for vulnerabilities
        vulnerabilities = self.check_vulnerabilities(all_results)
        
        # Generate statistics and recommendations
        statistics = self.generate_statistics(all_results)
        recommendations = self.generate_recommendations(all_results, vulnerabilities)
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        
        return ScanReport(
            timestamp=datetime.now().isoformat(),
            scan_targets=resolved_targets,
            total_hosts=len(resolved_targets),
            total_ports_scanned=len(ports_to_scan),
            open_ports_count=len([r for r in all_results if r.state == "open"]),
            scan_duration_seconds=scan_duration,
            port_results=all_results,
            vulnerabilities=vulnerabilities,
            summary_statistics=statistics,
            recommendations=recommendations
        )
    
    def save_report(self, report: ScanReport, output_formats: List[str]):
        """Save scan report in specified formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if 'json' in output_formats:
            json_file = f"open_ports_scan_report_{timestamp}.json"
            with open(json_file, 'w') as f:
                json.dump(asdict(report), f, indent=2, default=str)
            logger.info(f"JSON report saved to: {json_file}")
        
        if 'csv' in output_formats:
            csv_file = f"open_ports_scan_report_{timestamp}.csv"
            self._save_csv_report(report, csv_file)
            logger.info(f"CSV report saved to: {csv_file}")
        
        if 'dashboard' in output_formats:
            dashboard_file = f"open_ports_scan_dashboard_{timestamp}.png"
            self._generate_dashboard(report, dashboard_file)
            logger.info(f"Dashboard saved to: {dashboard_file}")
    
    def _save_csv_report(self, report: ScanReport, filename: str):
        """Save report as CSV"""
        # Port results CSV
        port_data = []
        for result in report.port_results:
            port_data.append({
                'Host': result.host,
                'Port': result.port,
                'Protocol': result.protocol,
                'State': result.state,
                'Service': result.service,
                'Version': result.version,
                'Banner': result.banner[:100] if result.banner else '',
                'Timestamp': result.timestamp.isoformat()
            })
        
        df = pd.DataFrame(port_data)
        df.to_csv(filename.replace('.csv', '_ports.csv'), index=False)
        
        # Vulnerabilities CSV
        if report.vulnerabilities:
            vuln_data = []
            for vuln in report.vulnerabilities:
                vuln_data.append({
                    'Host': vuln.host,
                    'Port': vuln.port,
                    'Severity': vuln.severity,
                    'Category': vuln.category,
                    'Description': vuln.description,
                    'Recommendation': vuln.recommendation,
                    'CVE_ID': vuln.cve_id or '',
                    'CVSS_Score': vuln.cvss_score or 0
                })
            
            vuln_df = pd.DataFrame(vuln_data)
            vuln_df.to_csv(filename.replace('.csv', '_vulnerabilities.csv'), index=False)
    
    def _generate_dashboard(self, report: ScanReport, filename: str):
        """Generate visual dashboard"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('Open Ports Scan Dashboard', fontsize=16)
        
        # 1. Port state distribution
        states = ['Open', 'Closed', 'Filtered']
        counts = [
            len([r for r in report.port_results if r.state == 'open']),
            len([r for r in report.port_results if r.state == 'closed']),
            len([r for r in report.port_results if r.state == 'filtered'])
        ]
        colors = ['red', 'green', 'orange']
        
        axes[0, 0].pie(counts, labels=states, colors=colors, autopct='%1.1f%%')
        axes[0, 0].set_title('Port State Distribution')
        
        # 2. Service distribution
        open_ports = [r for r in report.port_results if r.state == 'open']
        if open_ports:
            service_counts = {}
            for result in open_ports:
                service_counts[result.service] = service_counts.get(result.service, 0) + 1
            
            services = list(service_counts.keys())[:10]  # Top 10
            service_counts_list = [service_counts[service] for service in services]
            
            axes[0, 1].barh(services, service_counts_list, color='skyblue')
            axes[0, 1].set_title('Top Services (Open Ports)')
            axes[0, 1].set_xlabel('Count')
        
        # 3. Vulnerability severity distribution
        if report.vulnerabilities:
            severity_counts = {}
            for vuln in report.vulnerabilities:
                severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
            
            severities = list(severity_counts.keys())
            severity_counts_list = list(severity_counts.values())
            severity_colors = ['red', 'orange', 'yellow', 'blue', 'gray']
            
            axes[1, 0].bar(severities, severity_counts_list, color=severity_colors[:len(severities)])
            axes[1, 0].set_title('Vulnerability Severity Distribution')
            axes[1, 0].set_ylabel('Count')
        
        # 4. Port range distribution
        if report.summary_statistics:
            port_ranges = report.summary_statistics.get("port_range_distribution", {})
            range_names = list(port_ranges.keys())
            range_counts = list(port_ranges.values())
            
            axes[1, 1].pie(range_counts, labels=range_names, autopct='%1.1f%%')
            axes[1, 1].set_title('Port Range Distribution')
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Scan for open ports and vulnerabilities')
    parser.add_argument('--config', type=str, default='config/port_scan_config.json', 
                       help='Configuration file path')
    parser.add_argument('--targets', nargs='+', help='Target hosts to scan')
    parser.add_argument('--ports', type=str, help='Port ranges (e.g., "80-443,8080-8090")')
    parser.add_argument('--output-format', nargs='+', default=['json', 'dashboard'], 
                       choices=['json', 'csv', 'dashboard'], help='Output formats')
    
    args = parser.parse_args()
    
    try:
        scanner = OpenPortsScanner(args.config)
        
        # Parse port ranges if provided
        port_ranges = None
        if args.ports:
            port_ranges = []
            for port_range in args.ports.split(','):
                if '-' in port_range:
                    start, end = map(int, port_range.split('-'))
                    port_ranges.append({"start": start, "end": end})
                else:
                    port = int(port_range)
                    port_ranges.append({"start": port, "end": port})
        
        # Run scan
        report = scanner.run_scan(args.targets, port_ranges)
        
        # Save report
        scanner.save_report(report, args.output_format)
        
        # Print summary
        print(f"\n=== Open Ports Scan Summary ===")
        print(f"Targets scanned: {len(report.scan_targets)}")
        print(f"Ports scanned: {report.total_ports_scanned}")
        print(f"Open ports: {report.open_ports_count}")
        print(f"Scan duration: {report.scan_duration_seconds:.2f} seconds")
        print(f"Vulnerabilities found: {len(report.vulnerabilities)}")
        
        if report.vulnerabilities:
            severity_counts = {}
            for vuln in report.vulnerabilities:
                severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
            
            print(f"\nVulnerability Summary:")
            for severity, count in severity_counts.items():
                print(f"  {severity.capitalize()}: {count}")
        
        if report.recommendations:
            print(f"\n📋 Key Recommendations:")
            for i, rec in enumerate(report.recommendations[:5], 1):
                print(f"{i}. {rec}")
        
        logger.info("Open ports scan completed successfully!")
        
    except Exception as e:
        logger.error(f"Error during port scanning: {str(e)}")
        raise

if __name__ == "__main__":
    main()
