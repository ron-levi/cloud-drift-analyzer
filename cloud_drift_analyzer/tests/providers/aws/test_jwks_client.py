"""Tests for the JWKS client implementation."""

import time
import json
import pytest
import responses
from unittest.mock import patch
from cloud_drift_analyzer.providers.aws.jwks_client import JWKSClient

# Sample JWKS response
SAMPLE_JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "test-key-1",
            "use": "sig",
            "alg": "RS256",
            "n": "sample-modulus",
            "e": "AQAB"
        },
        {
            "kty": "RSA",
            "kid": "test-key-2",
            "use": "sig",
            "alg": "RS256",
            "n": "another-sample-modulus",
            "e": "AQAB"
        }
    ]
}

TEST_URL = "https://example.com/.well-known/jwks.json"

@pytest.fixture
def jwks_client():
    """Create a JWKS client for testing."""
    return JWKSClient(cache_ttl=300)  # 5 minutes TTL for testing

@responses.activate
def test_fetch_jwks(jwks_client):
    """Test fetching JWKS from a URL."""
    # Mock the JWKS endpoint
    responses.add(
        responses.GET,
        TEST_URL,
        json=SAMPLE_JWKS,
        status=200
    )
    
    # Get a key from the mocked endpoint
    key = jwks_client.get_signing_key(TEST_URL, "test-key-1")
    
    # Verify we got the correct key
    assert key is not None
    assert key["kid"] == "test-key-1"
    assert key["kty"] == "RSA"
    
    # Verify we made exactly one request
    assert len(responses.calls) == 1

@responses.activate
def test_key_caching(jwks_client):
    """Test that keys are properly cached."""
    # Mock the JWKS endpoint
    responses.add(
        responses.GET,
        TEST_URL,
        json=SAMPLE_JWKS,
        status=200
    )
    
    # First request should fetch from URL
    key1 = jwks_client.get_signing_key(TEST_URL, "test-key-1")
    assert key1 is not None
    assert len(responses.calls) == 1
    
    # Second request should use cache
    key2 = jwks_client.get_signing_key(TEST_URL, "test-key-1")
    assert key2 is not None
    assert len(responses.calls) == 1  # Still 1, meaning no new request
    
    # Request for different key should still use cache
    key3 = jwks_client.get_signing_key(TEST_URL, "test-key-2")
    assert key3 is not None
    assert key3["kid"] == "test-key-2"
    assert len(responses.calls) == 1  # Still 1, using cached JWKS

@responses.activate
def test_cache_expiration(jwks_client):
    """Test that cache expires after TTL."""
    # Mock the JWKS endpoint
    responses.add(
        responses.GET,
        TEST_URL,
        json=SAMPLE_JWKS,
        status=200
    )
    
    # First request should fetch from URL
    key1 = jwks_client.get_signing_key(TEST_URL, "test-key-1")
    assert key1 is not None
    assert len(responses.calls) == 1
    
    # Manually expire the cache
    with patch.dict(jwks_client._keys_cache, {
        TEST_URL: {
            'keys': SAMPLE_JWKS,
            'timestamp': time.time() - 600  # 10 minutes ago, exceeding TTL
        }
    }):
        # Next request should fetch again
        key2 = jwks_client.get_signing_key(TEST_URL, "test-key-1")
        assert key2 is not None
        assert len(responses.calls) == 2  # New request made

@responses.activate
def test_key_not_found(jwks_client):
    """Test behavior when requested key is not found."""
    # Mock the JWKS endpoint
    responses.add(
        responses.GET,
        TEST_URL,
        json=SAMPLE_JWKS,
        status=200
    )
    
    # Request a key that doesn't exist
    key = jwks_client.get_signing_key(TEST_URL, "non-existent-key")
    assert key is None

@responses.activate
def test_request_failure_with_cache(jwks_client):
    """Test falling back to stale cache when request fails."""
    # Mock successful request to populate cache
    responses.add(
        responses.GET,
        TEST_URL,
        json=SAMPLE_JWKS,
        status=200
    )
    
    # First request succeeds and populates cache
    key1 = jwks_client.get_signing_key(TEST_URL, "test-key-1")
    assert key1 is not None
    
    # Replace with failing response
    responses.reset()
    responses.add(
        responses.GET,
        TEST_URL,
        status=500
    )
    
    # Should fall back to cache even if expired
    with patch.dict(jwks_client._keys_cache, {
        TEST_URL: {
            'keys': SAMPLE_JWKS,
            'timestamp': time.time() - 600  # 10 minutes ago, exceeding TTL
        }
    }):
        key2 = jwks_client.get_signing_key(TEST_URL, "test-key-1")
        assert key2 is not None  # Still works using stale cache
