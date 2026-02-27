# CloudOps-SRE-Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Bash](https://img.shields.io/badge/Bash-4.0+-green.svg)](https://www.gnu.org/software/bash/)
[![Docker](https://img.shields.io/badge/Docker-20.10+-blue.svg)](https://www.docker.com/)

> Production-ready scripts and tools for Cloud Engineers, DevOps Engineers, Platform Engineers, and SREs

## Project Vision

The CloudOps-SRE-Toolkit provides practical, real-world scripts used by cloud operations and site reliability engineering teams to manage, monitor, and optimize cloud infrastructure. This toolkit focuses on automation, observability, security, and reliability across multiple cloud providers.

## Who This Is For

- **Cloud Engineers** managing multi-cloud environments
- **DevOps Engineers** automating infrastructure and deployment pipelines
- **Platform Engineers** building and maintaining platform services
- **Site Reliability Engineers (SREs)** ensuring service reliability and performance
- **System Administrators** transitioning to cloud operations

## Repository Structure

```
CloudOps-SRE-Toolkit/
├── cloud-cost-optimization/     # Cost management and optimization
├── kubernetes-containers/       # Kubernetes and container management
├── monitoring-observability/     # Monitoring and observability tools
├── security-compliance/          # Security scanning and compliance
├── cicd-utilities/              # CI/CD pipeline utilities
├── incident-reliability/        # Incident management and reliability
├── docs/                        # Documentation and guides
├── config/                      # Configuration files
├── scripts/                     # Helper and utility scripts
└── tests/                       # Test files
```

## Quick Start

### Prerequisites

- Python 3.8+ (for Python scripts)
- Bash 4.0+ (for shell scripts)
- Docker (for container-related scripts)
- AWS CLI/Azure CLI/GCP CLI (for cloud-specific scripts)
- kubectl (for Kubernetes scripts)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/CloudOps-SRE-Toolkit.git
   cd CloudOps-SRE-Toolkit
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your credentials and configurations
   ```

4. **Make scripts executable:**
   ```bash
   chmod +x cloud-cost-optimization/*.sh
   chmod +x kubernetes-containers/*.sh
   chmod +x monitoring-observability/*.sh
   chmod +x security-compliance/*.sh
   ```

### Usage Examples

#### Cloud Cost Optimization
```bash
# Detect unused Azure resources
./cloud-cost-optimization/azure_unused_resources.sh

# Find idle EC2 instances
python cloud-cost-optimization/aws_idle_ec2_detection.py

# Compare monthly costs
python cloud-cost-optimization/monthly_cost_comparison.py
```

#### Kubernetes Management
```bash
# Detect CrashLoopBackOff pods
./kubernetes-containers/crashloopbackoff_detector.sh

# Monitor restart counts
python kubernetes-containers/restart_count_monitor.py

# Check resource quotas
./kubernetes-containers/resource_quota_checker.sh
```

#### Security Scanning
```bash
# Scan for open ports
python security-compliance/open_ports_scanner.py --targets 192.168.1.1

# Detect public S3 buckets
python security-compliance/aws_public_s3_detector.py

# Scan for exposed secrets
python security-compliance/secrets_exposure_scanner.py ./src
```

##  Categories and Scripts

### 1. Cloud Cost Optimization

| Script | Description | Language |
|--------|-------------|----------|
| `azure_unused_resources.sh` | Detect unused Azure resources | Bash |
| `aws_idle_ec2_detection.sh` | Find idle EC2 instances | Bash |
| `monthly_cost_comparison.py` | Compare monthly costs across providers | Python |
| `resource_tagging_compliance.py` | Check resource tagging compliance | Python |

### 2. Kubernetes & Containers

| Script | Description | Language |
|--------|-------------|----------|
| `crashloopbackoff_detector.sh` | Detect CrashLoopBackOff pods | Bash |
| `restart_count_monitor.py` | Monitor pod restart counts | Python |
| `resource_quota_checker.sh` | Check resource quotas | Bash |
| `unused_images_detector.py` | Find unused container images | Python |
| `node_health_check.sh` | Comprehensive node health check | Bash |

### 3. Monitoring & Observability

| Script | Description | Language |
|--------|-------------|----------|
| `api_latency_checker.py` | Monitor API endpoint latency | Python |
| `endpoint_health_checker.sh` | Check endpoint health | Bash |
| `log_error_rate_analyzer.py` | Analyze log error rates | Python |
| `synthetic_monitoring.py` | Synthetic monitoring for services | Python |
| `sla_slo_calculator.py` | Calculate SLA/SLO compliance | Python |

### 4. Security & Compliance

| Script | Description | Language |
|--------|-------------|----------|
| `open_ports_scanner.py` | Scan for open ports | Python |
| `aws_public_s3_detector.py` | Detect public S3 buckets | Python |
| `secrets_exposure_scanner.py` | Scan for exposed secrets | Python |
| `ssl_cert_expiry_checker.py` | Check SSL certificate expiry | Python |
| `iam_risky_policy_detector.py` | Detect risky IAM policies | Python |

### 5. CI/CD Utilities

| Script | Description | Language |
|--------|-------------|----------|
| `pipeline_failure_notifier.py` | Notify on pipeline failures | Python |
| `branch_naming_validator.py` | Validate branch naming conventions | Python |
| `docker_image_cleanup.py` | Clean up unused Docker images | Python |
| `artifact_retention_cleaner.py` | Clean old build artifacts | Bash |

### 6. Incident & Reliability

| Script | Description | Language |
|--------|-------------|----------|
| `mttr_calculator.py` | Calculate Mean Time To Resolve | Python |
| `error_budget_calculator.py` | Calculate error budgets | Python |
| `deployment_frequency_tracker.py` | Track deployment frequency | Python |
| `incident_summary_generator.py` | Generate incident summaries | Python |

## Configuration

### Environment Variables

Create a `.env` file with the following variables:

```bash
# AWS Configuration
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-east-1

# Azure Configuration
AZURE_SUBSCRIPTION_ID=your_subscription_id
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret
AZURE_TENANT_ID=your_tenant_id

# GCP Configuration
GCP_PROJECT_ID=your_project_id
GCP_BILLING_ACCOUNT_ID=your_billing_account_id

# Notification Configuration
SLACK_WEBHOOK_URL=your_slack_webhook_url
ALERT_WEBHOOK_URL=your_alert_webhook_url
EMAIL_ENABLED=true
EMAIL_SMTP_HOST=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=your_email@gmail.com
EMAIL_PASSWORD=your_app_password

# Monitoring Configuration
PROMETHEUS_GATEWAY=http://prometheus-pushgateway:9091
```

### Configuration Files

Each category has its own configuration files in the `config/` directory:

- `config/cost_config.json` - Cost optimization settings
- `config/k8s_config.json` - Kubernetes monitoring settings
- `config/api_config.json` - API monitoring configuration
- `config/sla_slo_config.json` - SLA/SLO definitions
- `config/security_config.json` - Security scanning rules

## Security Notes

### Credential Management

- **Never** commit credentials to version control
- Use environment variables or secure credential stores
- Rotate credentials regularly
- Use least privilege access principles

### Script Security

- All scripts validate inputs and handle errors gracefully
- No hardcoded credentials in scripts
- Secure by default configurations
- Audit logging for security-sensitive operations

### Data Protection

- Logs may contain sensitive data - review before sharing
- Use data masking in reports when necessary
- Follow GDPR/CCPA compliance for personal data
- Encrypt sensitive configuration files

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Add tests if applicable
5. Ensure all tests pass: `make test`
6. Submit a pull request

### Code Standards

- Follow PEP 8 for Python code
- Use shellcheck for Bash scripts
- Add comprehensive logging
- Include error handling
- Document functions and classes
- Use type hints where appropriate

## Roadmap

### v1.0.0 (Current)
-  Core functionality for all categories
-  Basic configuration and documentation
-  Multi-cloud support (AWS, Azure, GCP)
-  Kubernetes integration

### v1.1.0 (Planned)
- Web dashboard for monitoring
- Integration with popular monitoring tools
- Advanced alerting capabilities
- Automated remediation scripts

### v1.2.0 (Future)
- Machine learning for anomaly detection
- Predictive analytics for capacity planning
- Multi-tenant support
- API server for remote execution

## Testing

Run the test suite:

```bash
# Run all tests
make test

# Run specific category tests
make test-cost-optimization
make test-kubernetes
make test-security

# Run with coverage
make test-coverage
```

## Monitoring and Metrics

Scripts generate comprehensive reports including:

- JSON reports for programmatic consumption
- CSV exports for spreadsheet analysis
- HTML dashboards for visualization
- Metrics for Prometheus/Grafana integration

## Support

- Check the [Documentation](docs/)
- Search [Issues](https://github.com/your-org/CloudOps-SRE-Toolkit/issues)
- Join our [Discord Community](https://discord.gg/cloudops-sre)
- Email: cloudops-sre-toolkit@example.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built by the cloud operations community
- Inspired by real-world SRE practices
- Thanks to all contributors and users
- Special thanks to the open-source projects that make this toolkit possible

## Badges

![GitHub stars](https://img.shields.io/github/stars/your-org/CloudOps-SRE-Toolkit?style=social)
![GitHub forks](https://img.shields.io/github/forks/your-org/CloudOps-SRE-Toolkit?style=social)
![GitHub issues](https://img.shields.io/github/issues/your-org/CloudOps-SRE-Toolkit)
![GitHub pull requests](https://img.shields.io/github/issues-pr/your-org/CloudOps-SRE-Toolkit)

---

**Built for CloudOps Engineers, by CloudOps Engineers**

*If you find this toolkit helpful, please give us a ⭐ on GitHub!*
