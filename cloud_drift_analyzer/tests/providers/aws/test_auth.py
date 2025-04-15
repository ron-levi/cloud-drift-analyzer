import pytest
from datetime import datetime, timedelta, timezone
import jwt
from botocore.exceptions import ClientError
from unittest.mock import patch, MagicMock

from cloud_drift_analyzer.providers.aws.auth_utils import (
    validate_oidc_token,
    assume_role_with_web_identity,
    TokenValidationError,
    AssumeRoleError
)
from cloud_drift_analyzer.providers.aws.client import AWSCloudProvider, AWSAuthenticationError

# Test secret key for JWT signing
TEST_KEY = "test-secret-key"

@pytest.fixture
def mock_valid_token():
    """Generate a valid OIDC token for testing."""
    now = datetime.now(timezone.utc)
    claims = {
        "iss": "https://test-issuer.com",
        "sub": "test-subject",
        "aud": "test-audience",
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
    }
    return jwt.encode(claims, TEST_KEY, algorithm="HS256")

@pytest.fixture
def mock_expired_token():
    """Generate an expired OIDC token for testing."""
    now = datetime.now(timezone.utc)
    claims = {
        "iss": "https://test-issuer.com",
        "sub": "test-subject",
        "aud": "test-audience",
        "exp": int((now - timedelta(hours=1)).timestamp()),
        "iat": int((now - timedelta(hours=2)).timestamp()),
    }
    return jwt.encode(claims, TEST_KEY, algorithm="HS256")

@pytest.fixture
def mock_aws_credentials(mock_valid_token):
    """Mock AWS credentials for testing."""
    return {
        "role_arn": "arn:aws:iam::123456789012:role/TestRole",
        "web_identity_token": mock_valid_token,  # Use the actual mock token
        "session_name": "test-session",
        "oidc_issuer": "https://test-issuer.com",
        "region": "us-east-1"
    }

class TestOIDCTokenValidation:
    def test_validate_valid_token(self, mock_valid_token):
        """Test validation of a valid OIDC token."""
        decoded = validate_oidc_token(mock_valid_token, "https://test-issuer.com")
        assert decoded["iss"] == "https://test-issuer.com"
        assert decoded["sub"] == "test-subject"

    def test_validate_expired_token(self, mock_expired_token):
        """Test validation fails with expired token."""
        with pytest.raises(TokenValidationError, match="Token has expired"):
            validate_oidc_token(mock_expired_token, "https://test-issuer.com")

    def test_validate_invalid_issuer(self, mock_valid_token):
        """Test validation fails with wrong issuer."""
        with pytest.raises(TokenValidationError, match="Invalid token issuer"):
            validate_oidc_token(mock_valid_token, "https://wrong-issuer.com")

    def test_validate_malformed_token(self):
        """Test validation fails with malformed token."""
        with pytest.raises(TokenValidationError):
            validate_oidc_token("invalid-token", "https://test-issuer.com")

class TestAWSRoleAssumption:
    @patch('boto3.client')
    def test_successful_role_assumption(self, mock_boto3_client):
        """Test successful role assumption with valid token."""
        mock_sts = MagicMock()
        mock_sts.assume_role_with_web_identity.return_value = {
            'Credentials': {
                'AccessKeyId': 'test-key',
                'SecretAccessKey': 'test-secret',
                'SessionToken': 'test-session',
                'Expiration': datetime.now(timezone.utc)
            }
        }
        mock_boto3_client.return_value = mock_sts

        credentials = assume_role_with_web_identity(
            "arn:aws:iam::123456789012:role/TestRole",
            "valid-token",
            "test-session"
        )

        assert credentials['AccessKeyId'] == 'test-key'
        assert credentials['SecretAccessKey'] == 'test-secret'
        mock_sts.assume_role_with_web_identity.assert_called_once()

    @patch('boto3.client')
    def test_invalid_token_role_assumption(self, mock_boto3_client):
        """Test role assumption fails with invalid token."""
        mock_sts = MagicMock()
        mock_error = ClientError(
            error_response={
                "Error": {
                    "Code": "InvalidIdentityToken",
                    "Message": "Invalid token"
                }
            },
            operation_name="AssumeRoleWithWebIdentity"
        )
        mock_sts.assume_role_with_web_identity.side_effect = mock_error
        mock_boto3_client.return_value = mock_sts

        with pytest.raises(AssumeRoleError, match="Invalid OIDC token provided"):
            assume_role_with_web_identity(
                "arn:aws:iam::123456789012:role/TestRole",
                "invalid-token",
                "test-session"
            )

class TestAWSCloudProvider:
    @patch('cloud_drift_analyzer.providers.aws.client.validate_oidc_token')
    @patch('cloud_drift_analyzer.providers.aws.client.assume_role_with_web_identity')
    @patch('boto3.Session')
    def test_provider_authentication(
        self,
        mock_session,
        mock_assume_role,
        mock_validate_token,
        mock_aws_credentials
    ):
        """Test full authentication flow in AWS Cloud Provider."""
        # Mock successful token validation
        mock_validate_token.return_value = {
            "iss": "https://test-issuer.com",
            "sub": "test-subject"
        }

        # Mock successful role assumption with timezone-aware expiration
        expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        mock_assume_role.return_value = {
            'AccessKeyId': 'test-key',
            'SecretAccessKey': 'test-secret',
            'SessionToken': 'test-session',
            'Expiration': expiry
        }

        # Mock boto3 session and S3 client
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {'Buckets': []}
        mock_session_instance = MagicMock()
        mock_session_instance.client.return_value = mock_s3
        mock_session.return_value = mock_session_instance

        # Configure credentials with proper string values
        mock_session_instance.get_credentials.return_value = MagicMock(
            access_key='test-key',
            secret_key='test-secret',
            token='test-session'
        )

        provider = AWSCloudProvider(mock_aws_credentials)
        result = provider.authenticate()
        assert result is True

        mock_validate_token.assert_called_once_with(
            mock_aws_credentials['web_identity_token'],
            mock_aws_credentials['oidc_issuer']
        )
        mock_assume_role.assert_called_once()
        mock_s3.list_buckets.assert_called_once()

    @patch('cloud_drift_analyzer.providers.aws.client.validate_oidc_token')
    def test_provider_authentication_token_validation_failure(
        self,
        mock_validate_token,
        mock_aws_credentials
    ):
        """Test authentication fails when token validation fails."""
        mock_validate_token.side_effect = TokenValidationError("Invalid token")

        provider = AWSCloudProvider(mock_aws_credentials)
        with pytest.raises(AWSAuthenticationError, match="OIDC token validation failed: Invalid token"):
            provider.authenticate()

    def test_provider_missing_credentials(self):
        """Test provider initialization fails with missing credentials."""
        with pytest.raises(ValueError, match="Missing required credentials"):
            AWSCloudProvider({})

    @patch('cloud_drift_analyzer.providers.aws.client.validate_oidc_token')
    @patch('cloud_drift_analyzer.providers.aws.client.assume_role_with_web_identity')
    @patch('boto3.Session')
    def test_provider_credential_refresh(
        self,
        mock_session,
        mock_assume_role,
        mock_validate_token,
        mock_aws_credentials
    ):
        """Test credentials are refreshed when expired."""
        # Mock successful token validation
        mock_validate_token.return_value = {"iss": "https://test-issuer.com"}

        # Mock successful role assumption with timezone-aware expiration
        expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
        initial_credentials = {
            'AccessKeyId': 'test-key-1',
            'SecretAccessKey': 'test-secret-1',
            'SessionToken': 'test-session-1',
            'Expiration': expiry
        }
        refresh_credentials = {
            'AccessKeyId': 'test-key-2',
            'SecretAccessKey': 'test-secret-2',
            'SessionToken': 'test-session-2',
            'Expiration': expiry + timedelta(hours=1)
        }
        mock_assume_role.side_effect = [initial_credentials, refresh_credentials]

        # Mock boto3 session and S3 client
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {'Buckets': []}
        mock_session_instance = MagicMock()
        mock_session_instance.client.return_value = mock_s3
        mock_session.return_value = mock_session_instance

        # Configure credentials with proper string values for each session
        session_credentials_1 = MagicMock(
            access_key='test-key-1',
            secret_key='test-secret-1',
            token='test-session-1'
        )
        session_credentials_2 = MagicMock(
            access_key='test-key-2',
            secret_key='test-secret-2',
            token='test-session-2'
        )
        mock_session_instance.get_credentials.side_effect = [
            session_credentials_1,
            session_credentials_2
        ]

        provider = AWSCloudProvider(mock_aws_credentials)
        assert provider.authenticate() is True

        # Force credential refresh by setting expiry to past
        provider.credentials_expiry = datetime.now(timezone.utc) - timedelta(minutes=5)
        
        # Make a request that should trigger refresh
        provider._refresh_credentials_if_needed()
        
        # Validate that assume_role was called twice (initial + refresh)
        assert mock_assume_role.call_count == 2
        assert provider.temporary_credentials['AccessKeyId'] == 'test-key-2'