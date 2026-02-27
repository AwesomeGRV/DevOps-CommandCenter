# DevOps-CommandCenter Makefile
# Provides convenient commands for development, testing, and deployment

.PHONY: help install test lint format clean docs docker build run

# Default target
help:
	@echo "DevOps-CommandCenter - Available Commands:"
	@echo ""
	@echo "Setup and Installation:"
	@echo "  install     Install Python dependencies"
	@echo "  setup       Set up development environment"
	@echo ""
	@echo "Development:"
	@echo "  test        Run all tests"
	@echo "  test-coverage Run tests with coverage report"
	@echo "  lint        Run code linting"
	@echo "  format      Format code with black"
	@echo "  type-check  Run type checking with mypy"
	@echo ""
	@echo "Scripts:"
	@echo "  run-cost    Run cost optimization scripts"
	@echo "  run-k8s     Run Kubernetes scripts"
	@echo "  run-security Run security scanning scripts"
	@echo "  run-monitoring Run monitoring scripts"
	@echo ""
	@echo "Documentation:"
	@echo "  docs        Generate documentation"
	@echo "  readme      Update README with latest stats"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build Build Docker image"
	@echo "  docker-run  Run toolkit in Docker"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean       Clean temporary files"
	@echo "  update      Update dependencies"

# Installation and setup
install:
	pip install -r requirements.txt
	pip install -e .

setup:
	python -m venv venv
	. venv/bin/activate && pip install -r requirements.txt
	cp .env.example .env
	chmod +x cloud-cost-optimization/*.sh
	chmod +x kubernetes-containers/*.sh
	chmod +x monitoring-observability/*.sh
	chmod +x security-compliance/*.sh
	@echo "Setup complete! Activate venv with: source venv/bin/activate"

# Testing
test:
	python -m pytest tests/ -v

test-coverage:
	python -m pytest tests/ --cov=. --cov-report=html --cov-report=term

test-cost-optimization:
	python -m pytest tests/test_cost_optimization.py -v

test-kubernetes:
	python -m pytest tests/test_kubernetes.py -v

test-security:
	python -m pytest tests/test_security.py -v

test-monitoring:
	python -m pytest tests/test_monitoring.py -v

# Code quality
lint:
	flake8 cloud-cost-optimization/ kubernetes-containers/ monitoring-observability/ security-compliance/ cicd-utilities/ incident-reliability/
	shellcheck cloud-cost-optimization/*.sh kubernetes-containers/*.sh monitoring-observability/*.sh security-compliance/*.sh

format:
	black cloud-cost-optimization/ kubernetes-containers/ monitoring-observability/ security-compliance/ cicd-utilities/ incident-reliability/
	isort cloud-cost-optimization/ kubernetes-containers/ monitoring-observability/ security-compliance/ cicd-utilities/ incident-reliability/

type-check:
	mypy cloud-cost-optimization/ kubernetes-containers/ monitoring-observability/ security-compliance/ cicd-utilities/ incident-reliability/

# Script execution
run-cost:
	@echo "Running cost optimization scripts..."
	python cloud-cost-optimization/monthly_cost_comparison.py --sample
	@echo "Cost optimization scripts completed!"

run-k8s:
	@echo "Running Kubernetes scripts..."
	python kubernetes-containers/restart_count_monitor.py --mode single
	@echo "Kubernetes scripts completed!"

run-security:
	@echo "Running security scanning scripts..."
	python security-compliance/ssl_cert_expiry_checker.py --example.com --output security_report.json
	@echo "Security scripts completed!"

run-monitoring:
	@echo "Running monitoring scripts..."
	python monitoring-observability/api_latency_checker.py --mode single
	@echo "Monitoring scripts completed!"

run-all: run-cost run-k8s run-security run-monitoring

# Documentation
docs:
	@echo "Generating documentation..."
	@mkdir -p docs/generated
	python -c "
import json
import os
from datetime import datetime

# Generate script documentation
categories = {
    'cloud-cost-optimization': 'Cost Management',
    'kubernetes-containers': 'Kubernetes & Containers',
    'monitoring-observability': 'Monitoring & Observability',
    'security-compliance': 'Security & Compliance',
    'cicd-utilities': 'CI/CD Utilities',
    'incident-reliability': 'Incident & Reliability'
}

docs_content = '# CloudOps-SRE-Toolkit Documentation\n\n'
docs_content += f'Generated on: {datetime.now().isoformat()}\n\n'

for category, description in categories.items():
    docs_content += f'## {description}\n\n'
    docs_content += f'Location: `{category}/`\n'
    docs_content += f'Scripts:\n'
    
    for file in os.listdir(category):
        if file.endswith(('.py', '.sh')):
            docs_content += f'- `{file}`\n'
    
    docs_content += '\n'

with open('docs/generated/overview.md', 'w') as f:
    f.write(docs_content)
"
	@echo "Documentation generated in docs/generated/"

readme-stats:
	@echo "Updating README with latest statistics..."
	@python -c "
import os
from datetime import datetime

# Count scripts by category
categories = {
    'cloud-cost-optimization': [],
    'kubernetes-containers': [],
    'monitoring-observability': [],
    'security-compliance': [],
    'cicd-utilities': [],
    'incident-reliability': []
}

total_scripts = 0
for category in categories:
    for file in os.listdir(category):
        if file.endswith(('.py', '.sh')):
            categories[category].append(file)
            total_scripts += 1

print(f'Total scripts: {total_scripts}')
for category, scripts in categories.items():
    print(f'{category}: {len(scripts)} scripts')
"

# Docker
docker-build:
	docker build -t cloudops-sre-toolkit:latest .

docker-run:
	docker run --rm -it \
		-v $(PWD)/config:/app/config \
		-v $(PWD)/reports:/app/reports \
		--env-file .env \
		cloudops-sre-toolkit:latest

# Maintenance
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/
	rm -rf dist/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf reports/*.json
	rm -rf reports/*.csv
	rm -rf reports/*.html
	rm -rf logs/*.log

update:
	pip install --upgrade pip
	pip install --upgrade -r requirements.txt
	@echo "Dependencies updated!"

# Security checks
security-scan:
	@echo "Running security scans..."
	bandit -r cloud-cost-optimization/ kubernetes-containers/ monitoring-observability/ security-compliance/ cicd-utilities/ incident-reliability/
	safety check
	@echo "Security scans completed!"

# Performance tests
perf-test:
	@echo "Running performance tests..."
	python -m pytest tests/performance/ -v
	@echo "Performance tests completed!"

# Integration tests
integration-test:
	@echo "Running integration tests..."
	python -m pytest tests/integration/ -v
	@echo "Integration tests completed!"

# Release preparation
release-check:
	@echo "Preparing for release..."
	make test
	make lint
	make security-scan
	make docs
	@echo "Release preparation completed!"

# Quick development commands
dev-setup: setup install
dev-test: test lint
dev-run: run-all
dev-clean: clean

# CI/CD pipeline commands
ci-test: test-coverage lint type-check
ci-build: docker-build
ci-security: security-scan
ci-all: ci-test ci-build ci-security

# Help for specific categories
help-cost:
	@echo "Cost Optimization Scripts:"
	@ls -la cloud-cost-optimization/

help-k8s:
	@echo "Kubernetes Scripts:"
	@ls -la kubernetes-containers/

help-security:
	@echo "Security Scripts:"
	@ls -la security-compliance/

help-monitoring:
	@echo "Monitoring Scripts:"
	@ls -la monitoring-observability/
