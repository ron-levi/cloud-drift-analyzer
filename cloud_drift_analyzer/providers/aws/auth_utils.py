"""
AWS Authentication Utilities for Cloud Drift Analyzer

This module handles OIDC-based authentication for AWS services.
"""

from typing import Dict, Any, Optional, List
import jwt
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError
from .jwks_client import JWKSClient
from ...core.logging import get_logger

logger = get_logger(__name__)

# Initialize the JWKS client as a singleton
jwks_client = JWKSClient()

class OIDCAuthError(Exception):
    """Base exception for OIDC authentication errors."""
    pass

class TokenValidationError(OIDCAuthError):
    """Exception raised when token validation fails."""
    pass

class AssumeRoleError(OIDCAuthError):
    """Exception raised when role assumption fails."""
    pass

def validate_oidc_token(token: str, issuer_url: str, audience: Optional[str] = None) -> Dict[str, Any]:
    """
    Validate an OIDC token.
    
    Args:
        token: The OIDC JWT token to validate
        issuer_url: The expected issuer URL
        audience: The expected audience (optional)
        
    Returns:
        Dict containing the decoded token claims
        
    Raises:
        TokenValidationError: If token validation fails
    """
    try:
        # Decode without verification first to get the headers
        unverified_headers = jwt.get_unverified_header(token)
        kid = unverified_headers.get('kid')
        
        if not kid:
            raise TokenValidationError("Token missing key ID (kid) in header")
        
        # Get the public key from the OIDC provider using our JWKS client
        jwks_url = f"{issuer_url.rstrip('/')}/.well-known/jwks.json"
        signing_key = jwks_client.get_signing_key(jwks_url, kid)
        
        if not signing_key:
            raise TokenValidationError(f"Unable to find signing key with ID: {kid}")
        
        # Prepare the key for PyJWT
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(signing_key)
        
        # Verify the token
        decode_options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_aud": audience is not None,
            "verify_iss": True,
        }
        
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=[unverified_headers.get("alg", "RS256")],
            options=decode_options,
            audience=audience,
            issuer=issuer_url
        )
        
        logger.debug("token_validated", sub=decoded.get('sub', 'unknown'))
        return decoded
        
    except jwt.InvalidTokenError as e:
        logger.warning("invalid_token_error", error=str(e))
        raise TokenValidationError(f"Invalid token format: {str(e)}")
    except Exception as e:
        logger.error("token_validation_failed", error=str(e))
        raise TokenValidationError(f"Token validation failed: {str(e)}")

def assume_role_with_web_identity(
    role_arn: str,
    web_identity_token: str,
    session_name: str,
    region: str = "us-east-1",
    duration_seconds: int = 3600,
    tags: Optional[List[Dict[str, str]]] = None
) -> Dict[str, Any]:
    """
    Assume an IAM role using a web identity token.
    
    Args:
        role_arn: ARN of the IAM role to assume
        web_identity_token: OIDC JWT token
        session_name: Name for the assumed role session
        region: AWS region
        duration_seconds: Duration of the session in seconds
        tags: Session tags to pass to the assumed role
        
    Returns:
        Dict containing temporary credentials
        
    Raises:
        AssumeRoleError: If role assumption fails
    """
    try:
        logger.info("assuming_role", role_arn=role_arn, session_name=session_name)
        sts_client = boto3.client('sts', region_name=region)
        
        kwargs = {
            'RoleArn': role_arn,
            'RoleSessionName': session_name,
            'WebIdentityToken': web_identity_token,
            'DurationSeconds': duration_seconds
        }
        
        # Add tags if provided
        if tags:
            kwargs['Tags'] = tags
        
        response = sts_client.assume_role_with_web_identity(**kwargs)
        
        logger.info("role_assumed", 
                   role_arn=role_arn, 
                   session_name=session_name,
                   expiration=response['Credentials'].get('Expiration', 'unknown'))
        
        return response['Credentials']
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        logger.error("assume_role_failed", 
                    error_code=error_code, 
                    error_message=error_message,
                    role_arn=role_arn)
        
        if error_code == 'InvalidIdentityToken':
            raise AssumeRoleError("Invalid OIDC token provided")
        elif error_code == 'ExpiredTokenException':
            raise AssumeRoleError("OIDC token has expired")
        elif error_code == 'IDPRejectedClaim':
            raise AssumeRoleError(f"Identity provider rejected claim: {error_message}")
        else:
            raise AssumeRoleError(f"Failed to assume role: {error_message}")
            
def get_sample_trust_policy(
    oidc_provider_url: str,
    allowed_subjects: List[str],
    account_id: str = "YOUR_ACCOUNT_ID"
) -> Dict[str, Any]:
    """
    Generate a sample IAM role trust policy for OIDC authentication.
    
    Args:
        oidc_provider_url: URL of your OIDC provider
        allowed_subjects: List of allowed subject claims (e.g., ["user:123", "tenant:456"])
        account_id: AWS account ID where the policy will be applied
        
    Returns:
        Dict containing the trust policy
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": f"arn:aws:iam::{account_id}:oidc-provider/{oidc_provider_url}"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        f"{oidc_provider_url}:sub": allowed_subjects
                    }
                }
            }
        ]
    }