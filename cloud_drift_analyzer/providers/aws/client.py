import aioboto3
from botocore.exceptions import ClientError
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone

from cloud_drift_analyzer.core.models import ResourceState
from ..base import CloudProvider
from .auth_utils import validate_oidc_token, assume_role_with_web_identity, TokenValidationError, AssumeRoleError
from ...core.logging import get_logger, log_duration, LogContext

logger = get_logger(__name__)

class AWSAuthenticationError(Exception):
    """Base exception for AWS authentication errors."""
    pass

class AWSCloudProvider(CloudProvider):
    """AWS implementation of the CloudProvider interface using OIDC-based authentication."""

    # Mapping of our generic resource types to AWS service names
    SERVICE_MAPPING = {
        'vm': 'ec2',
        'storage': 's3',
        'database': 'rds',
        'network': 'vpc',
        'lambda': 'lambda',
        'iam': 'iam',
        'eks': 'eks',
        'elb': 'elbv2',
        'cloudfront': 'cloudfront',
        'elasticache': 'elasticache'
    }

    def __init__(self, credentials: Dict[str, Any]):
        """
        Initialize AWS Cloud Provider with OIDC credentials.

        Args:
            credentials: Dict containing OIDC authentication details:
                - role_arn: ARN of the IAM role to assume
                - web_identity_token: OIDC JWT token
                - session_name: Optional name for the assumed role session
                - region: AWS region (defaults to us-east-1)
                - oidc_issuer: OIDC provider URL (required for token validation)
        """
        super().__init__(credentials)
        self.session: Optional[aioboto3.Session] = None
        self.clients: Dict[str, Any] = {}
        self.temporary_credentials: Optional[Dict[str, Any]] = None
        self.credentials_expiry: Optional[datetime] = None

        # Validate required credentials
        required_fields = ['role_arn', 'web_identity_token', 'oidc_issuer']
        missing_fields = [field for field in required_fields if field not in credentials]
        if missing_fields:
            logger.error("missing_required_credentials", fields=missing_fields)
            raise ValueError(f"Missing required credentials: {', '.join(missing_fields)}")

        logger.info("aws_provider_initialized",
                    role_arn=credentials['role_arn'],
                    region=credentials.get('region', 'us-east-1'))

    async def authenticate(self) -> bool:
        """
        Authenticate with AWS using OIDC token to assume role.

        Returns:
            bool: True if authentication successful, False otherwise

        Raises:
            AWSAuthenticationError: If authentication fails
        """
        try:
            with log_duration(logger, "aws_authentication") as log:
                # Validate the OIDC token
                logger.debug("validating_oidc_token")
                validate_oidc_token(
                    self.credentials['web_identity_token'],
                    self.credentials['oidc_issuer']
                )

                # Assume role with web identity
                logger.debug("assuming_role", role_arn=self.credentials['role_arn'])
                # Note: assume_role_with_web_identity is likely synchronous,
                # consider making it async or running in thread if it blocks
                self.temporary_credentials = assume_role_with_web_identity(
                    role_arn=self.credentials['role_arn'],
                    web_identity_token=self.credentials['web_identity_token'],
                    session_name=self.credentials.get('session_name', 'cloud-drift-session'),
                    region=self.credentials.get('region', 'us-east-1')
                )

                self.credentials_expiry = self.temporary_credentials['Expiration']
                # Create session with temporary credentials
                logger.debug("creating_aws_session")
                self.session = aioboto3.Session(
                    aws_access_key_id=self.temporary_credentials['AccessKeyId'],
                    aws_secret_access_key=self.temporary_credentials['SecretAccessKey'],
                    aws_session_token=self.temporary_credentials['SessionToken'],
                    region_name=self.credentials.get('region', 'us-east-1')
                )

                # Test authentication
                logger.debug("testing_authentication")
                async with self.session.client('s3') as s3_client:
                    await s3_client.list_buckets()
                logger.info("authentication_successful")
                return True

        except TokenValidationError as e:
            logger.error("token_validation_failed", error=str(e))
            raise AWSAuthenticationError(f"OIDC token validation failed: {str(e)}")
        except AssumeRoleError as e:
            logger.error("role_assumption_failed", error=str(e))
            raise AWSAuthenticationError(f"Failed to assume role: {str(e)}")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error("aws_api_error",
                        error_code=error_code,
                        error_message=error_message)
            raise AWSAuthenticationError(f"AWS API error ({error_code}): {error_message}")
        except Exception as e:
            logger.error("authentication_failed", error=str(e))
            raise AWSAuthenticationError(f"Authentication failed: {str(e)}")
        finally:
            if not self.session:
                self.temporary_credentials = None
                self.credentials_expiry = None

    async def _refresh_credentials_if_needed(self) -> None:
        """Check if credentials need refresh and re-authenticate if necessary."""
        if (
            not self.credentials_expiry or
            not self.temporary_credentials or
            isinstance(self.credentials_expiry, datetime) and  # Check if it's a real datetime
            datetime.now(timezone.utc) + timedelta(minutes=5) >= self.credentials_expiry.replace(tzinfo=timezone.utc)
        ):
            logger.info("refreshing_credentials")
            if not await self.authenticate(): # Made authenticate call async
                logger.error("credentials_refresh_failed")
                raise RuntimeError("Failed to refresh AWS credentials")

    async def get_resources(self) -> List[ResourceState]:
        """Retrieve all supported resources from AWS."""
        if not self.session:
            logger.error("not_authenticated")
            raise RuntimeError("Not authenticated. Call authenticate() first.")

        await self._refresh_credentials_if_needed()
        resources: List[ResourceState] = []

        with log_duration(logger, "get_aws_resources"):
            try:
                # Fetch EC2 instances
                resources.extend(await self._get_ec2_resources())
                
                # Fetch S3 buckets
                resources.extend(await self._get_s3_resources())
                
                # Fetch RDS instances
                resources.extend(await self._get_rds_resources())
                
                # Fetch Lambda functions
                resources.extend(await self._get_lambda_resources())
                
                # Fetch EKS clusters
                resources.extend(await self._get_eks_resources())
                
                # Fetch Load Balancers
                resources.extend(await self._get_elb_resources())
                
                # Fetch CloudFront distributions
                resources.extend(await self._get_cloudfront_resources())
                
                # Fetch ElastiCache clusters
                resources.extend(await self._get_elasticache_resources())

                logger.info("aws_resources_fetched", total_count=len(resources))
                return resources

            except Exception as e:
                logger.error("resource_fetch_failed", error=str(e))
                raise

    async def _get_ec2_resources(self) -> List[ResourceState]:
        """Fetch EC2 instances and related resources."""
        resources = []
        async with self.session.client('ec2') as ec2:
            # Get instances
            response = await ec2.describe_instances()
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    resources.append(ResourceState(
                        resource_id=instance['InstanceId'],
                        resource_type='vm',
                        provider='aws',
                        properties={
                            'InstanceType': instance['InstanceType'],
                            'State': instance['State']['Name'],
                            'LaunchTime': instance['LaunchTime'].isoformat(),
                            'PublicIpAddress': instance.get('PublicIpAddress'),
                            'PrivateIpAddress': instance.get('PrivateIpAddress'),
                            'Tags': {t['Key']: t['Value'] for t in instance.get('Tags', [])}
                        }
                    ))
        return resources

    async def _get_s3_resources(self) -> List[ResourceState]:
        """Fetch S3 buckets and their properties."""
        resources = []
        async with self.session.client('s3') as s3:
            response = await s3.list_buckets()
            for bucket in response['Buckets']:
                # Get bucket location
                location = await s3.get_bucket_location(Bucket=bucket['Name'])
                
                resources.append(ResourceState(
                    resource_id=bucket['Name'],
                    resource_type='storage',
                    provider='aws',
                    properties={
                        'CreationDate': bucket['CreationDate'].isoformat(),
                        'Region': location.get('LocationConstraint', 'us-east-1'),
                        'VersioningEnabled': await self._get_bucket_versioning(s3, bucket['Name'])
                    }
                ))
        return resources

    async def _get_rds_resources(self) -> List[ResourceState]:
        """Fetch RDS database instances."""
        resources = []
        async with self.session.client('rds') as rds:
            response = await rds.describe_db_instances()
            for instance in response['DBInstances']:
                resources.append(ResourceState(
                    resource_id=instance['DBInstanceIdentifier'],
                    resource_type='database',
                    provider='aws',
                    properties={
                        'Engine': instance['Engine'],
                        'EngineVersion': instance['EngineVersion'],
                        'DBInstanceClass': instance['DBInstanceClass'],
                        'MultiAZ': instance['MultiAZ'],
                        'StorageType': instance['StorageType'],
                        'AllocatedStorage': instance['AllocatedStorage']
                    }
                ))
        return resources

    async def _get_lambda_resources(self) -> List[ResourceState]:
        """Fetch Lambda functions."""
        resources = []
        async with self.session.client('lambda') as lambda_client:
            paginator = lambda_client.get_paginator('list_functions')
            async for page in paginator.paginate():
                for function in page['Functions']:
                    resources.append(ResourceState(
                        resource_id=function['FunctionName'],
                        resource_type='lambda',
                        provider='aws',
                        properties={
                            'Runtime': function['Runtime'],
                            'Memory': function['MemorySize'],
                            'Timeout': function['Timeout'],
                            'LastModified': function['LastModified'],
                            'Handler': function['Handler']
                        }
                    ))
        return resources

    async def _get_eks_resources(self) -> List[ResourceState]:
        """Fetch EKS clusters."""
        resources = []
        async with self.session.client('eks') as eks:
            paginator = eks.get_paginator('list_clusters')
            async for page in paginator.paginate():
                for cluster_name in page['clusters']:
                    cluster = await eks.describe_cluster(name=cluster_name)
                    resources.append(ResourceState(
                        resource_id=cluster_name,
                        resource_type='eks',
                        provider='aws',
                        properties={
                            'Status': cluster['cluster']['status'],
                            'Version': cluster['cluster']['version'],
                            'PlatformVersion': cluster['cluster']['platformVersion'],
                            'VpcId': cluster['cluster']['resourcesVpcConfig']['vpcId']
                        }
                    ))
        return resources

    async def _get_elb_resources(self) -> List[ResourceState]:
        """Fetch Elastic Load Balancers."""
        resources = []
        async with self.session.client('elbv2') as elb:
            response = await elb.describe_load_balancers()
            for lb in response['LoadBalancers']:
                resources.append(ResourceState(
                    resource_id=lb['LoadBalancerArn'],
                    resource_type='elb',
                    provider='aws',
                    properties={
                        'Type': lb['Type'],
                        'Scheme': lb['Scheme'],
                        'State': lb['State']['Code'],
                        'DNSName': lb['DNSName'],
                        'CreatedTime': lb['CreatedTime'].isoformat()
                    }
                ))
        return resources

    async def _get_cloudfront_resources(self) -> List[ResourceState]:
        """Fetch CloudFront distributions."""
        resources = []
        async with self.session.client('cloudfront') as cloudfront:
            response = await cloudfront.list_distributions()
            for distribution in response.get('DistributionList', {}).get('Items', []):
                resources.append(ResourceState(
                    resource_id=distribution['Id'],
                    resource_type='cloudfront',
                    provider='aws',
                    properties={
                        'Status': distribution['Status'],
                        'DomainName': distribution['DomainName'],
                        'Enabled': distribution['Enabled'],
                        'LastModified': distribution['LastModifiedTime'].isoformat()
                    }
                ))
        return resources

    async def _get_elasticache_resources(self) -> List[ResourceState]:
        """Fetch ElastiCache clusters."""
        resources = []
        async with self.session.client('elasticache') as elasticache:
            response = await elasticache.describe_cache_clusters()
            for cluster in response['CacheClusters']:
                resources.append(ResourceState(
                    resource_id=cluster['CacheClusterId'],
                    resource_type='elasticache',
                    provider='aws',
                    properties={
                        'Engine': cluster['Engine'],
                        'EngineVersion': cluster['EngineVersion'],
                        'CacheNodeType': cluster['CacheNodeType'],
                        'NumCacheNodes': cluster['NumCacheNodes'],
                        'Status': cluster['CacheClusterStatus']
                    }
                ))
        return resources

    async def get_resource_costs(self, start_date: str, end_date: str, filters: Optional[Dict] = None) -> Dict[str, Any]:
        """Get cost and usage data for resources."""
        if not self.session:
            raise RuntimeError("Not authenticated. Call authenticate() first.")

        await self._refresh_credentials_if_needed()

        try:
            async with self.session.client('ce') as ce:
                params = {
                    'TimePeriod': {
                        'Start': start_date,
                        'End': end_date
                    },
                    'Granularity': 'DAILY',
                    'Metrics': ['UnblendedCost'],
                    'GroupBy': [
                        {'Type': 'DIMENSION', 'Key': 'SERVICE'},
                        {'Type': 'DIMENSION', 'Key': 'USAGE_TYPE'}
                    ]
                }

                if filters:
                    params['Filter'] = filters

                response = await ce.get_cost_and_usage(**params)
                
                return self._process_cost_data(response)

        except Exception as e:
            logger.error("cost_data_fetch_failed", error=str(e))
            raise

    def _process_cost_data(self, cost_response: Dict[str, Any]) -> Dict[str, Any]:
        """Process and structure the cost data response."""
        processed_data = {
            'total_cost': 0.0,
            'services': [],
            'daily_costs': [],
            'usage_types': {}
        }

        for result in cost_response['ResultsByTime']:
            daily_cost = 0.0
            for group in result['Groups']:
                service = group['Keys'][0]
                usage_type = group['Keys'][1]
                cost = float(group['Metrics']['UnblendedCost']['Amount'])
                
                daily_cost += cost
                processed_data['total_cost'] += cost

                # Update service costs
                service_entry = next(
                    (s for s in processed_data['services'] if s['name'] == service),
                    None
                )
                if service_entry:
                    service_entry['cost'] += cost
                else:
                    processed_data['services'].append({
                        'name': service,
                        'cost': cost
                    })

                # Update usage type costs
                if service not in processed_data['usage_types']:
                    processed_data['usage_types'][service] = {}
                if usage_type not in processed_data['usage_types'][service]:
                    processed_data['usage_types'][service][usage_type] = 0.0
                processed_data['usage_types'][service][usage_type] += cost

            processed_data['daily_costs'].append({
                'date': result['TimePeriod']['Start'],
                'cost': daily_cost
            })

        # Sort services by cost
        processed_data['services'].sort(key=lambda x: x['cost'], reverse=True)
        
        return processed_data

    async def _get_bucket_versioning(self, s3_client: Any, bucket_name: str) -> bool:
        """Helper method to get bucket versioning status."""
        try:
            versioning = await s3_client.get_bucket_versioning(Bucket=bucket_name)
            return versioning.get('Status') == 'Enabled'
        except Exception:
            return False

    async def get_resource_by_id(self, resource_type: str, resource_id: str) -> Dict[str, Any]:
        """Retrieve a specific AWS resource by its ID."""
        if not self.session:
            raise RuntimeError("Not authenticated. Call authenticate() first.")

        await self._refresh_credentials_if_needed() # Ensure credentials are fresh

        service = self.SERVICE_MAPPING.get(resource_type)
        if not service:
            raise ValueError(f"Unsupported resource type: {resource_type}")

        async with self.session.client(service) as client:
            try:
                if resource_type == 'vm':
                    response = await client.describe_instances(InstanceIds=[resource_id])
                    if response['Reservations']:
                        return response['Reservations'][0]['Instances'][0]
                elif resource_type == 'storage':
                     # get_bucket_location is synchronous in boto3, might need adjustment or separate handling
                     # For now, assuming it might work or needs a different approach with aioboto3
                    return await client.get_bucket_location(Bucket=resource_id)
                elif resource_type == 'database':
                    response = await client.describe_db_instances(DBInstanceIdentifier=resource_id)
                    return response['DBInstances'][0]
                # Add more resource type handlers as needed
            except ClientError as e:
                raise KeyError(f"Resource not found: {resource_id}") from e

        raise KeyError(f"Resource not found: {resource_id}")

    def get_resource_types(self) -> List[str]:
        """Get list of supported AWS resource types."""
        return list(self.SERVICE_MAPPING.keys())

    async def _get_client(self, service_name: str) -> Any:
        """Get or create a boto3 client for the specified service."""
        # Refresh credentials if needed before getting/creating client
        await self._refresh_credentials_if_needed()

        if service_name not in self.clients:
            if not self.session:
                raise RuntimeError("Not authenticated. Call authenticate() first.")
            self.clients[service_name] = self.session.client(service_name)

        return self.clients[service_name]
