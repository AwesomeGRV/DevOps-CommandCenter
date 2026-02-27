#!/usr/bin/env python3
"""
SSL Certificate Expiry Checker
Author: CloudOps-SRE-Toolkit
Description: Check SSL certificate expiry dates for domains and services
"""

import ssl
import socket
import OpenSSL
import argparse
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class CertificateInfo:
    domain: str
    ip_address: str
    issuer: str
    subject: str
    valid_from: str
    expires_on: str
    days_until_expiry: int
    is_expired: bool
    is_expiring_soon: bool
    signature_algorithm: str
    key_size: int

class SSLCertChecker:
    def __init__(self, warning_days: int = 30, critical_days: int = 7):
        self.warning_days = warning_days
        self.critical_days = critical_days
    
    def check_certificate(self, domain: str, port: int = 443, timeout: int = 10) -> CertificateInfo:
        try:
            # Get IP address
            ip_address = socket.gethostbyname(domain)
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
                    
                    # Extract certificate information
                    subject = cert.get_subject()
                    issuer = cert.get_issuer()
                    
                    # Convert to readable format
                    subject_str = ', '.join([f'{name.decode()}={value}' for name, value in subject.get_components()])
                    issuer_str = ', '.join([f'{name.decode()}={value}' for name, value in issuer.get_components()])
                    
                    # Parse dates
                    valid_from = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
                    expires_on = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                    
                    # Calculate days until expiry
                    days_until_expiry = (expires_on - datetime.now()).days
                    is_expired = days_until_expiry < 0
                    is_expiring_soon = 0 < days_until_expiry <= self.warning_days
                    
                    # Get certificate details
                    signature_algorithm = cert.get_signature_algorithm().decode('ascii')
                    key_size = cert.get_pubkey().bits()
                    
                    return CertificateInfo(
                        domain=domain,
                        ip_address=ip_address,
                        issuer=issuer_str,
                        subject=subject_str,
                        valid_from=valid_from.isoformat(),
                        expires_on=expires_on.isoformat(),
                        days_until_expiry=days_until_expiry,
                        is_expired=is_expired,
                        is_expiring_soon=is_expiring_soon,
                        signature_algorithm=signature_algorithm,
                        key_size=key_size
                    )
        
        except Exception as e:
            logger.error(f"Error checking certificate for {domain}: {str(e)}")
            raise
    
    def check_domains(self, domains: List[str]) -> List[CertificateInfo]:
        certificates = []
        
        for domain in domains:
            try:
                cert_info = self.check_certificate(domain)
                certificates.append(cert_info)
                
                if cert_info.is_expired:
                    logger.error(f"CRITICAL: Certificate for {domain} has EXPIRED!")
                elif cert_info.is_expiring_soon:
                    if cert_info.days_until_expiry <= self.critical_days:
                        logger.error(f"CRITICAL: Certificate for {domain} expires in {cert_info.days_until_expiry} days")
                    else:
                        logger.warning(f"WARNING: Certificate for {domain} expires in {cert_info.days_until_expiry} days")
                else:
                    logger.info(f"OK: Certificate for {domain} is valid for {cert_info.days_until_expiry} days")
            
            except Exception as e:
                logger.error(f"Failed to check {domain}: {str(e)}")
        
        return certificates
    
    def generate_report(self, certificates: List[CertificateInfo]) -> Dict[str, Any]:
        expired_count = len([c for c in certificates if c.is_expired])
        expiring_soon_count = len([c for c in certificates if c.is_expiring_soon])
        valid_count = len(certificates) - expired_count - expiring_soon_count
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_domains": len(certificates),
            "expired_certificates": expired_count,
            "expiring_soon": expiring_soon_count,
            "valid_certificates": valid_count,
            "warning_threshold_days": self.warning_days,
            "critical_threshold_days": self.critical_days,
            "certificates": [asdict(cert) for cert in certificates]
        }

def main():
    parser = argparse.ArgumentParser(description='Check SSL certificate expiry')
    parser.add_argument('domains', nargs='+', help='Domains to check')
    parser.add_argument('--output', default='ssl_cert_report.json')
    parser.add_argument('--warning-days', type=int, default=30)
    parser.add_argument('--critical-days', type=int, default=7)
    
    args = parser.parse_args()
    
    try:
        checker = SSLCertChecker(args.warning_days, args.critical_days)
        certificates = checker.check_domains(args.domains)
        report = checker.generate_report(certificates)
        
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"SSL Certificate Check Summary:")
        print(f"Total domains: {report['total_domains']}")
        print(f"Expired: {report['expired_certificates']}")
        print(f"Expiring soon: {report['expiring_soon']}")
        print(f"Valid: {report['valid_certificates']}")
        print(f"Report saved to {args.output}")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
