"""
MCP tool implementations for cloud consulting AI agent platform.
"""

import json
import yaml
import base64
from typing import Dict, List, Optional, Any, Union, Type
from datetime import datetime
import logging
from pydantic import BaseModel, Field

from .base import Tool, Severity, FindingBase, RecommendationBase, ToolRegistry
from ..core.models import DriftType, DriftResult
from ..core.engine import DriftEngine

logger = logging.getLogger(__name__)

# Initialize tool registry
tool_registry = ToolRegistry()


# ===== Drift Analysis Tool =====

class DriftAnalysisInput(BaseModel):
    """Input schema for drift analysis."""
    resource_type: str = Field(..., description="The type of resource to analyze (e.g., aws_s3_bucket)")
    resource_id: str = Field(..., description="The ID of the resource to analyze")
    state_backend: str = Field(..., description="The IaC state backend (terraform, pulumi)")
    state_location: str = Field(..., description="Location of the state file or backend")


class DriftAnalysisOutput(BaseModel):
    """Output schema for drift analysis."""
    drift_detected: bool = Field(..., description="Whether drift was detected")
    drift_summary: Optional[str] = Field(None, description="Summary of detected drift")
    recommendation: Optional[str] = Field(None, description="Recommendation for resolving drift")
    severity: str = Field(..., description="Severity of the drift finding")


class AnalyzeDriftTool(Tool[DriftAnalysisInput, DriftAnalysisOutput]):
    """Tool for detecting infrastructure drift between IaC and cloud resources."""
    
    input_schema = DriftAnalysisInput
    output_schema = DriftAnalysisOutput
    
    def __init__(self):
        super().__init__(
            name="analyze_drift",
            description="Compares live resource states against IaC-defined states (Terraform, Pulumi)"
        )
        # Note: This is a simplified implementation for MCP demonstration
        # In production, this would use the full DriftEngine with proper dependencies
    
    async def execute(self, input_data: DriftAnalysisInput) -> DriftAnalysisOutput:
        try:
            # Mock implementation for MCP demonstration
            # In production, this would use the full DriftEngine with proper database session
            logger.info(f"Analyzing drift for {input_data.resource_type}: {input_data.resource_id}")
            
            # Simulate drift analysis
            if "test" in input_data.resource_id.lower() or "demo" in input_data.resource_id.lower():
                return DriftAnalysisOutput(
                    drift_detected=True,
                    drift_summary=f"Configuration drift detected in {input_data.resource_type} '{input_data.resource_id}': Tags missing, encryption settings differ from IaC definition",
                    recommendation="Update the resource configuration to match the IaC definition or update the IaC to reflect intended changes",
                    severity=Severity.MEDIUM
                )
            else:
                return DriftAnalysisOutput(
                    drift_detected=False,
                    drift_summary="No drift detected. Resource matches IaC definition.",
                    recommendation="No action required. Resource is in compliance with IaC definition.",
                    severity=Severity.LOW
                )
        
        except Exception as e:
            logger.error(f"Error in drift analysis: {str(e)}")
            raise ValueError(f"Error during drift analysis: {str(e)}")
    
    def _process_drift_result(self, result: DriftResult) -> tuple[str, str, str]:
        """Process drift result to generate summary, recommendation and severity."""
        summary_parts = []
        current_severity = Severity.LOW
        
        security_keywords = {"public", "acl", "security", "policy", "encryption"}

        for change in result.changes:
            drift_type = change.drift_type
            property_path_lower = change.property_path.lower()

            if drift_type == DriftType.MODIFIED:
                summary_parts.append(f"{change.property_path} changed from '{change.expected_value}' to '{change.actual_value}'")
                new_severity = Severity.MEDIUM
            elif drift_type == DriftType.ADDED:
                summary_parts.append(f"New property {change.property_path} with value '{change.actual_value}' not in IaC")
                new_severity = Severity.MEDIUM
            elif drift_type == DriftType.REMOVED:
                summary_parts.append(f"Property {change.property_path} with value '{change.expected_value}' missing from cloud")
                new_severity = Severity.HIGH
            else:
                continue

            # Elevate severity for security-related properties
            if any(keyword in property_path_lower for keyword in security_keywords):
                new_severity = Severity.HIGH if drift_type != DriftType.REMOVED else Severity.CRITICAL
            
            if new_severity > current_severity:
                current_severity = new_severity
        
        summary = "; ".join(summary_parts)
        
        # Generate recommendation based on severity
        if current_severity in [Severity.LOW, Severity.MEDIUM]:
            recommendation = "Reapply Terraform state or update the IaC to match current state"
        else:
            recommendation = "Investigate manual changes urgently; potential security implications"
        
        return summary, recommendation, current_severity


# ===== Cost Optimization Tool =====

class CostFilterInput(BaseModel):
    """Input filter for cost optimization."""
    service: Optional[List[str]] = Field(None, description="List of services to filter by")
    tag: Optional[Dict[str, str]] = Field(None, description="Tags to filter resources by")


class CostOptimizationInput(BaseModel):
    """Input schema for cost optimization."""
    time_range: str = Field(..., description="Time range for cost analysis (e.g., last_30_days)")
    filters: Optional[CostFilterInput] = Field(None, description="Filters to apply")


class ServiceCost(BaseModel):
    """Cost breakdown for a service."""
    name: str = Field(..., description="Service name")
    cost: float = Field(..., description="Cost in USD")


class CostOptimizationOutput(BaseModel):
    """Output schema for cost optimization."""
    total_cost: float = Field(..., description="Total cost in USD")
    top_services: List[ServiceCost] = Field(..., description="Top services by cost")
    recommendations: List[str] = Field(..., description="Cost saving recommendations")


class OptimizeCostsTool(Tool[CostOptimizationInput, CostOptimizationOutput]):
    """Tool for cost optimization analysis."""
    
    input_schema = CostOptimizationInput
    output_schema = CostOptimizationOutput
    
    def __init__(self):
        super().__init__(
            name="optimize_costs",
            description="Fetches recent cost breakdowns and identifies major spenders with reduction tips"
        )
        # Simplified implementation for MCP demonstration

    async def execute(self, input_data: CostOptimizationInput) -> CostOptimizationOutput:
        try:
            # Mock implementation for MCP demonstration
            logger.info(f"Analyzing costs for time range: {input_data.time_range}")
            
            # Generate mock cost data and recommendations
            mock_services = [
                ServiceCost(name="EC2", cost=245.67, percentage=45.2),
                ServiceCost(name="S3", cost=89.34, percentage=16.4),
                ServiceCost(name="RDS", cost=156.78, percentage=28.8),
                ServiceCost(name="Lambda", cost=23.45, percentage=4.3),
                ServiceCost(name="CloudWatch", cost=18.92, percentage=3.5)
            ]
            
            mock_recommendations = [
                "Consider using EC2 Reserved Instances for long-running workloads to save up to 60%",
                "Implement S3 Intelligent Tiering to automatically optimize storage costs",
                "Review RDS instance sizing - some instances appear underutilized",
                "Enable Lambda Provisioned Concurrency only where necessary to reduce costs"
            ]
            
            return CostOptimizationOutput(
                total_cost=534.16,
                top_services=mock_services,
                recommendations=mock_recommendations
            )
            
        except Exception as e:
            logger.error(f"Error in cost optimization: {str(e)}")
            raise ValueError(f"Error during cost optimization: {str(e)}")

    def _get_top_services(self, costs_data: Dict[str, Any]) -> List[ServiceCost]:
        """Convert cost data into ServiceCost objects."""
        return [
            ServiceCost(name=service['name'], cost=service['cost'])
            for service in costs_data['services']
        ]

    def _generate_recommendations(self, costs_data: Dict[str, Any]) -> List[str]:
        """Generate cost optimization recommendations based on cost data."""
        recommendations = []
        
        # Analyze service costs
        for service in costs_data['services']:
            service_name = service['name']
            service_cost = service['cost']
            usage_types = costs_data['usage_types'].get(service_name, {})
            
            # EC2 recommendations
            if 'Amazon EC2' in service_name:
                if any('BoxUsage' in usage_type for usage_type in usage_types):
                    recommendations.append(
                        "Consider using Reserved Instances or Savings Plans for consistent EC2 usage"
                    )
                if any('IdleInstance' in usage_type for usage_type in usage_types):
                    recommendations.append(
                        "Identify and terminate idle EC2 instances to reduce costs"
                    )
                    
            # S3 recommendations
            elif 'Amazon S3' in service_name:
                if any('StandardStorage' in usage_type for usage_type in usage_types):
                    recommendations.append(
                        "Implement S3 lifecycle policies to move infrequently accessed data to cheaper storage tiers"
                    )
                    
            # RDS recommendations
            elif 'Amazon RDS' in service_name:
                if service_cost > 1000:  # Arbitrary threshold
                    recommendations.append(
                        "Consider using RDS Reserved Instances for significant database cost savings"
                    )
                    
            # Lambda recommendations
            elif 'AWS Lambda' in service_name:
                if any('GB-Second' in usage_type for usage_type in usage_types):
                    recommendations.append(
                        "Optimize Lambda function memory settings and execution time to reduce costs"
                    )
                    
            # EKS recommendations
            elif 'Amazon EKS' in service_name:
                recommendations.append(
                    "Review Kubernetes cluster capacity and consider using Spot Instances for non-critical workloads"
                )
                
            # CloudFront recommendations
            elif 'Amazon CloudFront' in service_name:
                recommendations.append(
                    "Analyze CloudFront usage patterns and optimize cache behaviors to reduce origin requests"
                )
                
            # ElastiCache recommendations
            elif 'Amazon ElastiCache' in service_name:
                recommendations.append(
                    "Review ElastiCache node types and consider using reserved nodes for consistent workloads"
                )

        # Add general recommendations based on total cost
        if costs_data['total_cost'] > 10000:  # Arbitrary threshold
            recommendations.append(
                "Enable AWS Cost Explorer rightsizing recommendations for detailed optimization insights"
            )
            recommendations.append(
                "Consider using AWS Organizations for better cost allocation and management"
            )

        # Analyze cost trends
        daily_costs = costs_data.get('daily_costs', [])
        if len(daily_costs) > 1:
            first_cost = daily_costs[0]['cost']
            last_cost = daily_costs[-1]['cost']
            if last_cost > first_cost * 1.2:  # 20% increase
                recommendations.append(
                    "Investigate recent cost increases and set up AWS Budgets for better cost control"
                )

        return recommendations


# ===== IAM Access Review Tool =====

class IAMFinding(FindingBase):
    """A finding from an IAM access review."""
    policy: str = Field(..., description="Policy name")


class IAMReviewInput(BaseModel):
    """Input schema for IAM access review."""
    principal_arn: str = Field(..., description="ARN of the principal to review")
    depth: int = Field(1, description="Depth of policy analysis (1-3)")


class IAMReviewOutput(BaseModel):
    """Output schema for IAM access review."""
    findings: List[IAMFinding] = Field(..., description="List of findings")
    recommendations: List[str] = Field(..., description="Recommendations for remediation")


class IAMReviewTool(Tool[IAMReviewInput, IAMReviewOutput]):
    """Tool for reviewing IAM permissions and identifying issues."""
    
    input_schema = IAMReviewInput
    output_schema = IAMReviewOutput
    
    def __init__(self):
        super().__init__(
            name="iam_review_access",
            description="Performs a principle-of-least-privilege review of IAM roles and policies"
        )
        # Simplified implementation for MCP demonstration
    
    async def execute(self, input_data: IAMReviewInput) -> IAMReviewOutput:
        try:
            # Mock implementation for MCP demonstration
            logger.info(f"Reviewing IAM permissions for principal: {input_data.principal_arn}")
            
            # Generate mock findings based on principal ARN
            mock_findings = []
            if "admin" in input_data.principal_arn.lower():
                mock_findings.append(IAMFinding(
                    type="Access Control",
                    policy="AdministratorAccess",
                    description="Principal has full administrator access - high risk",
                    severity=Severity.CRITICAL
                ))
            else:
                mock_findings.append(IAMFinding(
                    type="Access Control", 
                    policy="PowerUserAccess",
                    description="Principal has broad access permissions",
                    severity=Severity.MEDIUM
                ))
            
            mock_recommendations = [
                "Replace broad permissions with scoped policies",
                "Enable AWS CloudTrail for access monitoring",
                "Implement least privilege access principles",
                "Regular review of permissions and remove unused policies"
            ]
            
            return IAMReviewOutput(
                findings=mock_findings,
                recommendations=mock_recommendations
            )
            
        except Exception as e:
            logger.error(f"Error in IAM review: {str(e)}")
            raise ValueError(f"Error during IAM review: {str(e)}")
    
    def _get_principal_type(self, principal_arn: str) -> str:
        """Parse principal ARN to determine the type."""
        if ":user/" in principal_arn:
            return "user"
        elif ":role/" in principal_arn:
            return "role"
        elif ":group/" in principal_arn:
            return "group"
        else:
            raise ValueError(f"Unsupported principal type in ARN: {principal_arn}")
    
    async def _get_policies(self, principal_arn: str, depth: int) -> List[Dict[str, Any]]:
        """Get policies attached to the principal."""
        # Mock implementation - in production this would call AWS API
        if "admin" in principal_arn.lower():
            return [
                {"name": "AdministratorAccess", "risk": "critical", "description": "Full administrator access"},
                {"name": "S3ReadOnlyAccess", "risk": "low", "description": "Read-only access to S3"}
            ]
        else:
            return [
                {"name": "AmazonS3ReadOnlyAccess", "risk": "low", "description": "Read-only access to S3"},
                {"name": "EC2FullAccess", "risk": "medium", "description": "Full access to EC2"},
                {"name": "IAMReadOnlyAccess", "risk": "low", "description": "Read-only access to IAM"}
            ]
    
    def _analyze_policies(self, policies: List[Dict[str, Any]]) -> List[IAMFinding]:
        """Analyze policies for potential risks."""
        findings = []
        
        for policy in policies:
            findings.append(IAMFinding(
                type="Access Control",
                policy=policy["name"],
                description=policy["description"],
                severity=policy["risk"]
            ))
        
        return findings
    
    def _generate_recommendations(self, findings: List[IAMFinding]) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = []
        
        if any(f.severity == "critical" for f in findings):
            recommendations.append("Replace AdministratorAccess with scoped policy")
        
        if any(f.policy == "EC2FullAccess" for f in findings):
            recommendations.append("Consider limiting EC2 access to only required actions")
        
        recommendations.append("Enable IAM access analyzer for cross-account access audit")
        
        return recommendations


# ===== S3 Permission Scanning Tool =====

class S3Issue(FindingBase):
    """An issue found with S3 bucket permissions."""
    pass


class S3ScanInput(BaseModel):
    """Input schema for S3 permission scan."""
    bucket_name: str = Field(..., description="Name of the S3 bucket to scan")
    region: str = Field(..., description="AWS region of the bucket")


class S3ScanOutput(BaseModel):
    """Output schema for S3 permission scan."""
    is_public: bool = Field(..., description="Whether the bucket is publicly accessible")
    issues: List[S3Issue] = Field(..., description="List of issues found")
    recommendations: List[str] = Field(..., description="Recommendations for remediation")


class S3PermissionScanTool(Tool[S3ScanInput, S3ScanOutput]):
    """Tool for scanning S3 bucket permissions and identifying security issues."""
    
    input_schema = S3ScanInput
    output_schema = S3ScanOutput
    
    def __init__(self):
        super().__init__(
            name="scan_s3_permissions",
            description="Audits a given S3 bucket for public access, encryption, versioning, and logging"
        )
        # Simplified implementation for MCP demonstration
    
    async def execute(self, input_data: S3ScanInput) -> S3ScanOutput:
        try:
            # Mock implementation for MCP demonstration
            logger.info(f"Scanning S3 bucket: {input_data.bucket_name} in region: {input_data.region}")
            
            # Generate mock issues based on bucket name
            mock_issues = []
            is_public = False
            
            if "public" in input_data.bucket_name.lower():
                is_public = True
                mock_issues.append(S3Issue(
                    type="Access Control",
                    description="Bucket is publicly accessible via ACL",
                    severity=Severity.CRITICAL
                ))
            
            if "test" in input_data.bucket_name.lower():
                mock_issues.append(S3Issue(
                    type="Encryption",
                    description="No default encryption configured",
                    severity=Severity.MEDIUM
                ))
                mock_issues.append(S3Issue(
                    type="Versioning",
                    description="Versioning is disabled",
                    severity=Severity.LOW
                ))
            
            mock_recommendations = [
                "Enable server-side encryption with AES-256 or KMS",
                "Enable versioning to protect against accidental deletes",
                "Enable access logging for audit purposes",
                "Review and restrict bucket policies to least privilege"
            ]
            
            return S3ScanOutput(
                is_public=is_public,
                issues=mock_issues,
                recommendations=mock_recommendations
            )
            
        except Exception as e:
            logger.error(f"Error in S3 scan: {str(e)}")
            raise ValueError(f"Error during S3 scan: {str(e)}")
    
    async def _get_bucket_config(self, bucket_name: str, region: str) -> Dict[str, Any]:
        """Get bucket configuration."""
        # Mock implementation - in production this would call AWS API
        if bucket_name.startswith("public"):
            return {
                "name": bucket_name,
                "region": region,
                "is_public": True,
                "encryption": None,
                "versioning": False,
                "logging": False,
                "lifecycle_rules": []
            }
        else:
            return {
                "name": bucket_name,
                "region": region,
                "is_public": False,
                "encryption": "AES256",
                "versioning": True,
                "logging": True,
                "lifecycle_rules": [{"id": "archive-rule", "status": "Enabled"}]
            }
    
    def _analyze_bucket(self, bucket_config: Dict[str, Any]) -> List[S3Issue]:
        """Analyze bucket configuration for security issues."""
        issues = []
        
        # Check public access
        if bucket_config.get("is_public", False):
            issues.append(S3Issue(
                type="Access Control",
                description="Bucket is publicly accessible via ACL",
                severity=Severity.CRITICAL
            ))
        
        # Check encryption
        if not bucket_config.get("encryption"):
            issues.append(S3Issue(
                type="Encryption",
                description="No default encryption configured",
                severity=Severity.MEDIUM
            ))
        
        # Check versioning
        if not bucket_config.get("versioning"):
            issues.append(S3Issue(
                type="Versioning",
                description="Versioning is disabled",
                severity=Severity.LOW
            ))
        
        # Check logging
        if not bucket_config.get("logging"):
            issues.append(S3Issue(
                type="Logging",
                description="Access logging is not enabled",
                severity=Severity.MEDIUM
            ))
        
        return issues
    
    def _generate_recommendations(self, issues: List[S3Issue]) -> List[str]:
        """Generate recommendations based on issues."""
        recommendations = []
        
        for issue in issues:
            if issue.type == "Access Control" and issue.severity == Severity.CRITICAL:
                recommendations.append("Set ACL to private or remove public grants")
            elif issue.type == "Encryption" and issue.severity == Severity.MEDIUM:
                recommendations.append("Enable SSE-S3 or SSE-KMS for encryption")
            elif issue.type == "Versioning" and issue.severity == Severity.LOW:
                recommendations.append("Enable versioning to protect against accidental deletes")
            elif issue.type == "Logging" and issue.severity == Severity.MEDIUM:
                recommendations.append("Enable access logging to track bucket usage")
        
        return recommendations


# ===== Kubernetes Configuration Compliance Tool =====

class K8sConfigInput(BaseModel):
    """Input schema for Kubernetes configuration compliance check."""
    manifest: str = Field(..., description="Raw YAML string or base64 encoded Kubernetes manifest")
    ruleset: str = Field("CIS-1.23", description="Compliance ruleset to check against")


class K8sFailedRule(FindingBase):
    """A failed compliance rule in Kubernetes configuration."""
    id: str = Field(..., description="Rule identifier")


class K8sConfigOutput(BaseModel):
    """Output schema for Kubernetes configuration compliance check."""
    compliance_score: int = Field(..., description="Compliance score (0-100)")
    failed_rules: List[K8sFailedRule] = Field(..., description="List of failed compliance rules")
    recommendations: List[str] = Field(..., description="Recommendations for remediation")


class K8sComplianceTool(Tool[K8sConfigInput, K8sConfigOutput]):
    """Tool for checking Kubernetes configurations against compliance standards."""
    
    input_schema = K8sConfigInput
    output_schema = K8sConfigOutput
    
    def __init__(self):
        super().__init__(
            name="check_k8s_config_compliance",
            description="Checks Kubernetes workload manifests for misconfigurations and compliance gaps"
        )
        # Simplified implementation for MCP demonstration
    
    async def execute(self, input_data: K8sConfigInput) -> K8sConfigOutput:
        try:
            # Mock implementation for MCP demonstration
            logger.info(f"Checking Kubernetes compliance against ruleset: {input_data.ruleset}")
            
            # Generate mock compliance results
            mock_failed_rules = []
            compliance_score = 85  # Mock score
            
            # Simulate some failed rules based on manifest content
            if "runAsRoot" in input_data.manifest or "privileged" in input_data.manifest:
                mock_failed_rules.append(K8sFailedRule(
                    id="5.2.4",
                    type="Kubernetes Configuration",
                    description="Containers should not run as root",
                    severity=Severity.HIGH
                ))
                compliance_score = 70
            
            if "NET_RAW" in input_data.manifest or "capabilities" not in input_data.manifest:
                mock_failed_rules.append(K8sFailedRule(
                    id="5.1.6",
                    type="Kubernetes Configuration", 
                    description="Limit container capabilities",
                    severity=Severity.MEDIUM
                ))
                compliance_score = max(60, compliance_score - 15)
            
            mock_recommendations = [
                "Add runAsNonRoot: true to podSecurityContext",
                "Drop all Linux capabilities unless explicitly needed", 
                "Set automountServiceAccountToken: false when not needed",
                "Implement network policies to restrict pod-to-pod communication",
                "Use security contexts to enforce security constraints"
            ]
            
            return K8sConfigOutput(
                compliance_score=compliance_score,
                failed_rules=mock_failed_rules,
                recommendations=mock_recommendations
            )
            
        except Exception as e:
            logger.error(f"Error in Kubernetes compliance check: {str(e)}")
            raise ValueError(f"Error during Kubernetes compliance check: {str(e)}")
    
    def _decode_manifest(self, manifest: str) -> str:
        """Decode manifest if it's base64 encoded."""
        try:
            # Try to decode as base64
            decoded = base64.b64decode(manifest).decode('utf-8')
            # If it successfully decodes and is valid YAML, return it
            yaml.safe_load(decoded)
            return decoded
        except Exception:
            # If it fails, assume it's already a plain text YAML
            return manifest
    
    def _parse_manifest(self, manifest: str) -> List[Dict[str, Any]]:
        """Parse YAML manifest into Kubernetes objects."""
        try:
            # Parse all documents in the YAML file
            k8s_objects = list(yaml.safe_load_all(manifest))
            return k8s_objects
        except yaml.YAMLError:
            raise ValueError("Invalid manifest: Not a valid YAML")
    
    def _get_ruleset(self, ruleset_name: str) -> List[Dict[str, Any]]:
        """Get ruleset definition."""
        # Mock implementation - in production this would load from a database or file
        if ruleset_name == "CIS-1.23":
            return [
                {"id": "5.2.4", "description": "Containers should not run as root", "severity": Severity.HIGH},
                {"id": "5.1.6", "description": "Limit container capabilities", "severity": Severity.MEDIUM},
                {"id": "5.7.2", "description": "Ensure that Service Account Tokens are only mounted where necessary", "severity": Severity.HIGH},
                {"id": "5.3.2", "description": "Minimize the admission of containers with NET_RAW capability", "severity": Severity.MEDIUM},
                {"id": "5.4.1", "description": "Prefer using secrets as files over secrets as environment variables", "severity": Severity.LOW}
            ]
        else:
            raise ValueError(f"Unsupported ruleset: {ruleset_name}")
    
    def _check_compliance(self, k8s_objects: List[Dict[str, Any]], ruleset: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check Kubernetes objects against compliance ruleset."""
        # Mock implementation - in production this would perform actual checks
        
        # For demonstration, we'll fail some rules based on object properties
        failed_rules = []
        
        for obj in k8s_objects:
            kind = obj.get("kind", "")
            if kind == "Pod" or kind == "Deployment" or kind == "StatefulSet":
                spec = obj.get("spec", {})
                containers = spec.get("containers", [])
                
                # Check for root user
                for container in containers:
                    security_context = container.get("securityContext", {})
                    if not security_context.get("runAsNonRoot", False):
                        failed_rules.append(ruleset[0])  # 5.2.4
                
                # Check for capabilities
                for container in containers:
                    security_context = container.get("securityContext", {})
                    if "capabilities" not in security_context:
                        failed_rules.append(ruleset[1])  # 5.1.6
        
        # Remove duplicates
        unique_failed_rules = []
        rule_ids = set()
        for rule in failed_rules:
            if rule["id"] not in rule_ids:
                unique_failed_rules.append(rule)
                rule_ids.add(rule["id"])
        
        # Calculate compliance score
        total_rules = len(ruleset)
        failed_count = len(unique_failed_rules)
        compliance_score = int(((total_rules - failed_count) / total_rules) * 100)
        
        return {
            "score": compliance_score,
            "failed_rules": unique_failed_rules
        }
    
    def _generate_recommendations(self, failed_rules: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on failed rules."""
        recommendations = []
        
        for rule in failed_rules:
            if rule["id"] == "5.2.4":
                recommendations.append("Add `runAsNonRoot: true` to podSecurityContext")
            elif rule["id"] == "5.1.6":
                recommendations.append("Drop all Linux capabilities unless explicitly needed")
            elif rule["id"] == "5.7.2":
                recommendations.append("Set automountServiceAccountToken: false when not needed")
            elif rule["id"] == "5.3.2":
                recommendations.append("Add NET_RAW to the list of dropped capabilities")
            elif rule["id"] == "5.4.1":
                recommendations.append("Mount secrets as files instead of environment variables")
        
        return recommendations
