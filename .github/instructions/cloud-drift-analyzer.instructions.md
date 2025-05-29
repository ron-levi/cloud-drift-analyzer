# Cloud Drift Analyzer - Project Instructions

## Project Overview
Cloud Drift Analyzer is a tool designed to analyze and detect drift in cloud infrastructure configurations across multiple providers. It integrates with AI agents via Model Context Protocol (MCP) to provide intelligent analysis and recommendations.

## Key Components

### 1. Provider Modules
- **AWS Module** (`providers/aws/`): 
  - Authentication utilities for OIDC-based access
  - Resource scanning and drift detection
  - IAM policy management and analysis

- **Other Cloud Providers**:
  - Similar modules for other cloud providers (Azure, GCP, etc.)
  - Each provider module should maintain consistent interfaces

### 2. MCP Layer (`mcp/`)
- **Base Tool Infrastructure** (`base.py`): Core classes for tools and registry
- **Tool Implementations** (`tools.py`): Specialized cloud analysis tools
- **Server Implementation** (`server.py`): Management of tool registry
- **API Layer** (`api.py`): FastAPI endpoints for tool execution
- **Agent Integration** (`agent_integration.py`): LangGraph integration

### 3. Core Features
- Drift detection between actual and expected configurations
- Security posture analysis
- Cost optimization recommendations
- Compliance checking against best practices
- Resource inventory and relationship mapping

## Coding Standards

### Style Guide
- Follow PEP 8 for Python code
- Use type hints for all function parameters and return types
- Comprehensive docstrings in Google style format
- Maximum line length of 100 characters

### Error Handling
- Use custom exception classes for different error types
- Provide meaningful error messages
- Handle errors at appropriate levels of abstraction
- Log errors with sufficient context for debugging

### Testing
- Unit tests for all modules with high coverage
- Integration tests for provider-specific functionality
- Mock external services in tests to avoid dependencies

## Implementation Requirements

### Authentication
- Implement secure OIDC token validation with proper key fetching
- Support multiple identity providers (GitHub, GitLab, etc.)
- Provide secure credential management and handling
- Implement least-privilege access patterns

### Resource Analysis
- Ensure efficient scanning of large resource sets
- Implement pagination for large result sets
- Provide mechanisms for filtering and focusing analysis
- Add support for custom analyzers and rules

### AI Integration
- Provide clear interfaces for AI agents to consume
- Ensure all tools have well-defined schemas
- Return structured data that's easy for agents to process
- Support conversational context and state management

## Best Practices
- Never log sensitive information (tokens, credentials)
- Cache results where appropriate to improve performance
- Implement retry mechanisms for cloud API calls
- Follow cloud provider best practices for API usage
- Use dependency injection for better testability
- Implement feature flags for experimental functionality

## Project Structure
- `/cloud_drift_analyzer/` - Main package
  - `/providers/` - Cloud provider-specific modules
  - `/mcp/` - Model Context Protocol implementation
  - `/core/` - Core functionality shared across the project
  - `/api/` - API endpoints for external access
  - `/utils/` - Utility functions and shared helpers
  - `/tests/` - Test cases and fixtures

## Development Workflow
- Create feature branches from main
- Write tests before implementing features
- Document all public APIs and user-facing functionality
- Run linters and type checkers before committing code
- Keep dependencies up to date and minimal
