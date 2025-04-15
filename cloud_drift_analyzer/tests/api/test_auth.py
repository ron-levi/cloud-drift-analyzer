import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import jwt
from datetime import datetime, timedelta, timezone

from cloud_drift_analyzer.api.main import app
from cloud_drift_analyzer.api.security.auth import (
    create_access_token,
    create_refresh_token,
    JWT_SECRET_KEY,
    get_password_hash
)
from cloud_drift_analyzer.db.models import User, RefreshToken
from cloud_drift_analyzer.tests.conftest import async_session_maker

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
async def test_user(async_session):
    """Create a test user"""
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password=get_password_hash("testpass123")
    )
    async_session.add(user)
    await async_session.commit()
    await async_session.refresh(user)
    return user

@pytest.mark.asyncio
async def test_register_user(client, async_session):
    """Test user registration endpoint"""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": "newuser",
            "email": "new@example.com",
            "password": "password123"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "newuser"
    assert data["email"] == "new@example.com"
    assert "password" not in data

@pytest.mark.asyncio
async def test_register_duplicate_user(client, test_user):
    """Test registration with existing username/email"""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": "testuser",  # Same as test_user
            "email": "another@example.com",
            "password": "password123"
        }
    )
    assert response.status_code == 400
    assert "already registered" in response.json()["detail"]

@pytest.mark.asyncio
async def test_login_success(client, test_user):
    """Test successful login"""
    response = client.post(
        "/api/v1/auth/token",
        data={
            "username": "testuser",
            "password": "testpass123"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert "expires_in" in data

    # Verify the tokens
    access_token = data["access_token"]
    payload = jwt.decode(access_token, JWT_SECRET_KEY, algorithms=["HS256"])
    assert payload["sub"] == "testuser"
    assert payload["type"] == "access"

@pytest.mark.asyncio
async def test_login_failure(client):
    """Test login with wrong credentials"""
    response = client.post(
        "/api/v1/auth/token",
        data={
            "username": "wronguser",
            "password": "wrongpass"
        }
    )
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_refresh_token(client, test_user, async_session):
    """Test refresh token endpoint"""
    # First login to get tokens
    response = client.post(
        "/api/v1/auth/token",
        data={
            "username": "testuser",
            "password": "testpass123"
        }
    )
    tokens = response.json()
    
    # Use refresh token to get new access token
    response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]}
    )
    assert response.status_code == 200
    new_tokens = response.json()
    assert "access_token" in new_tokens
    assert new_tokens["access_token"] != tokens["access_token"]

@pytest.mark.asyncio
async def test_get_current_user(client, test_user):
    """Test getting current user details"""
    # Create a token for the test user
    access_token, _ = create_access_token(test_user.username)
    
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == test_user.username
    assert data["email"] == test_user.email

@pytest.mark.asyncio
async def test_update_user(client, test_user):
    """Test updating user profile"""
    access_token, _ = create_access_token(test_user.username)
    
    response = client.put(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "email": "updated@example.com"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "updated@example.com"

@pytest.mark.asyncio
async def test_change_password(client, test_user):
    """Test password change"""
    access_token, _ = create_access_token(test_user.username)
    
    response = client.post(
        "/api/v1/auth/me/change-password",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "current_password": "testpass123",
            "new_password": "newpass123"
        }
    )
    assert response.status_code == 200
    
    # Try logging in with new password
    response = client.post(
        "/api/v1/auth/token",
        data={
            "username": "testuser",
            "password": "newpass123"
        }
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_expired_token(client, test_user):
    """Test using expired token"""
    # Create an expired token
    now = datetime.now(timezone.utc)
    expired_token = jwt.encode(
        {
            "sub": test_user.username,
            "exp": int((now - timedelta(minutes=30)).timestamp()),
            "iat": int((now - timedelta(hours=1)).timestamp()),
            "is_superuser": False,
            "type": "access"
        },
        JWT_SECRET_KEY,
        algorithm="HS256"
    )
    
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_logout(client, test_user, async_session):
    """Test logout endpoint"""
    # First login to get tokens
    response = client.post(
        "/api/v1/auth/token",
        data={
            "username": "testuser",
            "password": "testpass123"
        }
    )
    tokens = response.json()
    
    # Logout
    response = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert response.status_code == 200
    
    # Verify refresh token is revoked
    stmt = select(RefreshToken).where(RefreshToken.token == tokens["refresh_token"])
    result = await async_session.execute(stmt)
    refresh_token = result.scalar_one()
    assert refresh_token.is_revoked