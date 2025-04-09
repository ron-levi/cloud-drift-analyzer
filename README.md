# Cloud Drift Analyzer

A tool for analyzing infrastructure drift between Infrastructure as Code (IaC) definitions and actual cloud resources.

## Features

- **Multi-Cloud Support**
  - AWS integration with OIDC authentication
  - GCP support (planned)
  - Extensible provider architecture

- **IaC Tool Integration**
  - Terraform state analysis
  - Pulumi state support
  - Real-time drift detection

- **Advanced Reporting**
  - HTML reports with detailed drift visualization
  - JSON output for programmatic analysis
  - Critical changes highlighting
  - Resource state comparison

- **Notification System**
  - Slack integration with customizable alerts
  - Support for multiple notification channels
  - Configurable notification rules

- **REST API**
  - Health monitoring endpoints
  - Drift analysis triggers
  - Results retrieval
  - Structured logging

- **Scheduling & Automation**
  - Cron-based scheduled scans
  - Environment-specific configurations
  - Automated drift detection

- **Database Integration**
  - SQLite storage (default)
  - Drift history tracking
  - Resource state persistence
  - Notification configurations

## Installation

```bash
# Install using Poetry (recommended)
poetry install

# Or using pip
pip install -r requirements.txt
```

## Configuration

### Environment Variables

Create a `.env` file based on `.env.example`:

```env
DATABASE_URL=sqlite:///./drift.db
AWS_REGION=us-west-2
SLACK_TOKEN=your-slack-token
SLACK_CHANNEL=#infrastructure
LOG_LEVEL=INFO
```

### Authentication

AWS authentication supports OIDC tokens for secure cloud access:

```bash
# Configure AWS credentials
export AWS_ROLE_ARN=arn:aws:iam::123456789012:role/DriftAnalyzer
export AWS_WEB_IDENTITY_TOKEN_FILE=/path/to/token
```

## Usage

### CLI Commands

```bash
# Initialize the tool
poetry run cloud-drift init

# Analyze drift in terraform state
poetry run cloud-drift get-terraform-state /path/to/terraform

# Run drift analysis
poetry run cloud-drift analyze-drift /path/to/state --provider aws --env production

# Enable notifications
poetry run cloud-drift analyze-drift /path/to/state --notify
```

### API Endpoints

The service exposes a REST API on port 8000:

- `GET /health` - Service health check
- `GET /api/v1/drift` - Get drift analysis results
- `POST /api/v1/drift/scan` - Trigger new drift analysis

### Scheduling Scans

Configure automated scans using the built-in scheduler:

```python
from cloud_drift_analyzer.scheduler import DriftScheduler

scheduler = DriftScheduler()
scheduler.schedule_drift_analysis(
    schedule="0 * * * *",  # Run hourly
    environment="production"
)
```

## Development

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=cloud_drift_analyzer
```

### Docker Support

Build and run using Docker:

```bash
docker build -t cloud-drift-analyzer .
docker run -p 8000:8000 cloud-drift-analyzer
```

## Logging

The application uses structured logging with different configurations for development, production, and testing environments. Logs can be output in both JSON and human-readable formats.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License - See LICENSE file for details