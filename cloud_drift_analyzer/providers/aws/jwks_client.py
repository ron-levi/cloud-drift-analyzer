"""JWKS Client for fetching and caching JSON Web Keys for OIDC token validation."""

from typing import Dict, Any, Optional, List
import time
import requests
import jwt
from cloud_drift_analyzer.core.logging import get_logger

logger = get_logger(__name__)

class JWKSClient:
    """
    Client for fetching and caching JSON Web Key Sets (JWKS) from OIDC providers.
    
    This client handles retrieving public keys from OIDC providers and maintains
    a local cache to avoid excessive network calls.
    """
    
    def __init__(self, cache_ttl: int = 3600):
        """
        Initialize the JWKS client.
        
        Args:
            cache_ttl: Time-to-live for cached keys in seconds (default: 1 hour)
        """
        self._keys_cache: Dict[str, Dict[str, Any]] = {}  # URL -> {keys, timestamp}
        self._cache_ttl = cache_ttl
    
    def get_signing_key(self, jwks_url: str, kid: str) -> Optional[Dict[str, Any]]:
        """
        Get a signing key by key ID from a JWKS URL.
        
        Args:
            jwks_url: URL of the JWKS endpoint
            kid: Key ID to retrieve
            
        Returns:
            The signing key if found, None otherwise
        """
        jwks = self._get_jwks(jwks_url)
        if not jwks:
            return None
        
        # Find the key with the matching kid
        for key in jwks.get('keys', []):
            if key.get('kid') == kid:
                logger.debug("jwks_key_found", kid=kid)
                return key
        
        logger.warning("jwks_key_not_found", kid=kid, url=jwks_url)
        return None
    
    def _get_jwks(self, jwks_url: str) -> Dict[str, Any]:
        """
        Get the JWKS from the provided URL, using cache when available.
        
        Args:
            jwks_url: URL of the JWKS endpoint
            
        Returns:
            The JWKS dictionary
        """
        # Check if we have a cached version that's still valid
        cache_entry = self._keys_cache.get(jwks_url)
        current_time = time.time()
        
        if cache_entry and (current_time - cache_entry['timestamp'] < self._cache_ttl):
            logger.debug("using_cached_jwks", url=jwks_url)
            return cache_entry['keys']
        
        # Fetch new keys
        try:
            logger.info("fetching_jwks", url=jwks_url)
            response = requests.get(jwks_url, timeout=10)
            response.raise_for_status()
            jwks = response.json()
            
            # Cache the keys
            self._keys_cache[jwks_url] = {
                'keys': jwks,
                'timestamp': current_time
            }
            
            return jwks
        except requests.RequestException as e:
            logger.error("jwks_fetch_failed", url=jwks_url, error=str(e))
            # If we have stale cache, use it rather than failing completely
            if cache_entry:
                logger.warning("using_stale_jwks_cache", url=jwks_url)
                return cache_entry['keys']
            return {'keys': []}
