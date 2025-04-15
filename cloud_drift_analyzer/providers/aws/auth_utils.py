from typing import Dict, Any, Optional
import jwt  # Changed from python_jwt to PyJWT
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

class OIDCAuthError(Exception):
    """Base exception for OIDC authentication errors."""
    pass

class TokenValidationError(OIDCAuthError):
    """Exception raised when token validation fails."""
    pass

class AssumeRoleError(OIDCAuthError):
    """Exception raised when role assumption fails."""
    pass

def validate_oidc_token(token: str, issuer_url: str) -> Dict[str, Any]:
    """
    Validate an OIDC token.
    
    Args:
        token: The OIDC JWT token to validate
        issuer_url: The expected issuer URL
        
    Returns:
        Dict containing the decoded token claims
        
    Raises:
        TokenValidationError: If token validation fails
    """
    try:
        # Decode without verification first to get the headers
        unverified_headers = jwt.get_unverified_header(token)
        
        # Get the public key from the OIDC provider
        # In production, you should cache these keys
        jwks_url = f"{issuer_url.rstrip('/')}/.well-known/jwks.json"
        
        # TODO: Implement JWKS client to fetch and cache keys
        # For now, we just decode and validate basic claims
        
        decoded = jwt.decode(
            token,
            options={"verify_signature": False},  # In production, this should be True
            algorithms=[unverified_headers.get("alg", "RS256")]
        )
        
        # Validate basic claims
        if decoded.get("iss") != issuer_url:
            raise TokenValidationError("Invalid token issuer")
            
        exp = decoded.get("exp")
        if not exp or datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            raise TokenValidationError("Token has expired")
            
        return decoded
        
    except jwt.InvalidTokenError as e:
        raise TokenValidationError(f"Invalid token format: {str(e)}")
    except Exception as e:
        raise TokenValidationError(f"Token validation failed: {str(e)}")

def assume_role_with_web_identity(
    role_arn: str,
    web_identity_token: str,
    session_name: str,
    region: str = "us-east-1"
) -> Dict[str, Any]:
    """
    Assume an IAM role using a web identity token.
    
    Args:
        role_arn: ARN of the IAM role to assume
        web_identity_token: OIDC JWT token
        session_name: Name for the assumed role session
        region: AWS region
        
    Returns:
        Dict containing temporary credentials
        
    Raises:
        AssumeRoleError: If role assumption fails
    """
    try:
        sts_client = boto3.client('sts', region_name=region)
        response = sts_client.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            WebIdentityToken=web_identity_token
        )
        return response['Credentials']
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
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
    allowed_subjects: list[str]
) -> Dict[str, Any]:
    """
    Generate a sample IAM role trust policy for OIDC authentication.
    
    Args:
        oidc_provider_url: URL of your OIDC provider
        allowed_subjects: List of allowed subject claims (e.g., ["user:123", "tenant:456"])
        
    Returns:
        Dict containing the trust policy
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": f"arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/{oidc_provider_url}"
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