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
        'iam': 'iam'
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

        await self._refresh_credentials_if_needed() # Ensure credentials are fresh

        resources: List[ResourceState] = []

        with log_duration(logger, "get_aws_resources"):
            # Fetch EC2 instances
            if 'vm' in self.get_resource_types():
                with LogContext(resource_type="ec2"):
                    try:
                        logger.debug("fetching_ec2_instances")
                        async with self.session.client('ec2') as ec2_client:
                            response = await ec2_client.describe_instances()
                            for reservation in response['Reservations']:
                                for instance in reservation['Instances']:
                                    resource_id = instance['InstanceId']
                                    properties = {
                                        'InstanceType': instance['InstanceType'],
                                        'State': instance['State']['Name'],
                                        'PublicIpAddress': instance.get('PublicIpAddress', None)
                                    }
                                    resources.append(ResourceState(
                                        resource_id=resource_id,
                                        resource_type='vm',
                                        provider='aws',
                                        properties=properties
                                    ))
                            logger.info("ec2_instances_fetched", count=len(resources)) # Adjusted count logic
                    except Exception as e:
                        logger.error("ec2_fetch_failed", error=str(e))

            # Fetch S3 buckets
            if 'storage' in self.get_resource_types():
                with LogContext(resource_type="s3"):
                    try:
                        logger.debug("fetching_s3_buckets")
                        async with self.session.client('s3') as s3_client:
                            response = await s3_client.list_buckets()
                            s3_count = 0
                            for bucket in response['Buckets']:
                                resource_id = bucket['Name']
                                properties = {
                                    'CreationDate': bucket['CreationDate'].isoformat()
                                }
                                resources.append(ResourceState(
                                    resource_id=resource_id,
                                    resource_type='storage',
                                    provider='aws',
                                    properties=properties
                                ))
                                s3_count += 1
                            logger.info("s3_buckets_fetched", count=s3_count)
                    except Exception as e:
                        logger.error("s3_fetch_failed", error=str(e))

            # Fetch RDS instances
            if 'database' in self.get_resource_types():
                with LogContext(resource_type="rds"):
                    try:
                        logger.debug("fetching_rds_instances")
                        async with self.session.client('rds') as rds_client:
                            response = await rds_client.describe_db_instances()
                            rds_count = 0
                            for instance in response['DBInstances']:
                                resource_id = instance['DBInstanceIdentifier']
                                properties = {
                                    'Engine': instance['Engine'],
                                    'DBInstanceClass': instance['DBInstanceClass'],
                                    'DBInstanceStatus': instance['DBInstanceStatus']
                                }
                                resources.append(ResourceState(
                                    resource_id=resource_id,
                                    resource_type='database',
                                    provider='aws',
                                    properties=properties
                                ))
                                rds_count += 1
                            logger.info("rds_instances_fetched", count=rds_count)
                    except Exception as e:
                        logger.error("rds_fetch_failed", error=str(e))

        return resources

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
