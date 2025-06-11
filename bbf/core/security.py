"""
Core security management system for the Bug Bounty Framework.

This module provides functionality for managing security features, including:
- Authentication and authorization
- Rate limiting
- Input validation and sanitization
- Security headers
- Audit logging
- Security policies
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
import time
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Type, TypeVar, Union
from urllib.parse import urlparse

import aiohttp
import bcrypt
import jwt
from aiohttp import web
from aiohttp.web import Request, Response
from aiohttp.web_middlewares import middleware
from aiohttp.web_request import Request
from aiohttp.web_response import Response
from aiohttp.web_exceptions import HTTPUnauthorized, HTTPForbidden, HTTPTooManyRequests

from .exceptions import (
    SecurityError,
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
    ValidationError,
    AuditError
)

logger = logging.getLogger(__name__)

# Type variables for generic functions
T = TypeVar('T')

class SecurityLevel(Enum):
    """Security level enumeration."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityPolicy:
    """
    Security policy configuration.
    
    This class manages security policies, including:
    - Password requirements
    - Rate limiting rules
    - Input validation rules
    - Security headers
    - Audit logging rules
    """
    
    def __init__(self, policy_path: Optional[Path] = None):
        """
        Initialize security policy.
        
        Args:
            policy_path: Path to policy configuration file
        """
        self.policy_path = policy_path or Path('data/security/policy.json')
        self.policy: Dict[str, Any] = {}
        self._load_policy()
    
    def _load_policy(self) -> None:
        """Load policy from file."""
        try:
            if self.policy_path.exists():
                with open(self.policy_path, 'r') as f:
                    self.policy = json.load(f)
            else:
                # Create default policy
                self.policy = self._create_default_policy()
                self._save_policy()
        except Exception as e:
            logger.error(f"Failed to load security policy: {e}")
            self.policy = self._create_default_policy()
    
    def _create_default_policy(self) -> Dict[str, Any]:
        """
        Create default security policy.
        
        Returns:
            Dictionary containing default policy
        """
        return {
            'password_policy': {
                'min_length': 12,
                'require_uppercase': True,
                'require_lowercase': True,
                'require_digits': True,
                'require_special': True,
                'max_age_days': 90,
                'history_size': 5
            },
            'rate_limiting': {
                'enabled': True,
                'default_limit': 100,
                'default_window': 60,
                'ip_limit': 1000,
                'ip_window': 3600,
                'user_limit': 500,
                'user_window': 3600
            },
            'input_validation': {
                'max_length': 10000,
                'allowed_schemes': ['http', 'https'],
                'allowed_hosts': ['*'],
                'blocked_patterns': [
                    r'<script.*?>',
                    r'javascript:',
                    r'data:',
                    r'vbscript:',
                    r'expression\(',
                    r'eval\(',
                    r'exec\(',
                    r'<iframe.*?>',
                    r'<object.*?>',
                    r'<embed.*?>'
                ]
            },
            'security_headers': {
                'enabled': True,
                'headers': {
                    'X-Content-Type-Options': 'nosniff',
                    'X-Frame-Options': 'DENY',
                    'X-XSS-Protection': '1; mode=block',
                    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                    'Content-Security-Policy': "default-src 'self'",
                    'Referrer-Policy': 'strict-origin-when-cross-origin',
                    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
                }
            },
            'audit_logging': {
                'enabled': True,
                'log_path': 'data/security/audit.log',
                'log_level': 'INFO',
                'log_format': 'json',
                'retention_days': 90,
                'sensitive_fields': [
                    'password',
                    'token',
                    'secret',
                    'key',
                    'authorization'
                ]
            },
            'authentication': {
                'jwt_secret': self._generate_secret(),
                'jwt_algorithm': 'HS256',
                'jwt_expiry': 3600,
                'refresh_expiry': 604800,
                'bcrypt_rounds': 12
            },
            'authorization': {
                'default_level': 'low',
                'roles': {
                    'admin': ['*'],
                    'user': ['read', 'write'],
                    'guest': ['read']
                }
            },
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }
    
    def _generate_secret(self) -> str:
        """
        Generate a random secret.
        
        Returns:
            Random secret string
        """
        return base64.b64encode(os.urandom(32)).decode('utf-8')
    
    def _save_policy(self) -> None:
        """Save policy to file."""
        try:
            # Create directory if it doesn't exist
            self.policy_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save policy
            with open(self.policy_path, 'w') as f:
                json.dump(self.policy, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save security policy: {e}")
            raise SecurityError(f"Failed to save policy: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get policy value.
        
        Args:
            key: Policy key
            default: Default value if key not found
            
        Returns:
            Policy value
        """
        return self.policy.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """
        Set policy value.
        
        Args:
            key: Policy key
            value: Policy value
        """
        self.policy[key] = value
        self.policy['updated_at'] = datetime.utcnow().isoformat()
        self._save_policy()
    
    def update(self, **kwargs) -> None:
        """
        Update multiple policy values.
        
        Args:
            **kwargs: Policy key-value pairs
        """
        self.policy.update(kwargs)
        self.policy['updated_at'] = datetime.utcnow().isoformat()
        self._save_policy()
    
    def validate_password(self, password: str) -> bool:
        """
        Validate password against policy.
        
        Args:
            password: Password to validate
            
        Returns:
            bool: True if password is valid, False otherwise
            
        Raises:
            ValidationError: If password is invalid
        """
        policy = self.policy['password_policy']
        
        try:
            # Check length
            if len(password) < policy['min_length']:
                raise ValidationError(
                    f"Password must be at least {policy['min_length']} characters"
                )
            
            # Check requirements
            if policy['require_uppercase'] and not re.search(r'[A-Z]', password):
                raise ValidationError("Password must contain uppercase letters")
            if policy['require_lowercase'] and not re.search(r'[a-z]', password):
                raise ValidationError("Password must contain lowercase letters")
            if policy['require_digits'] and not re.search(r'\d', password):
                raise ValidationError("Password must contain digits")
            if policy['require_special'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                raise ValidationError("Password must contain special characters")
            
            return True
            
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Password validation failed: {str(e)}")
    
    def validate_input(self, input_str: str, field_type: str = 'text') -> bool:
        """
        Validate input against policy.
        
        Args:
            input_str: Input to validate
            field_type: Type of input field
            
        Returns:
            bool: True if input is valid, False otherwise
            
        Raises:
            ValidationError: If input is invalid
        """
        policy = self.policy['input_validation']
        
        try:
            # Check length
            if len(input_str) > policy['max_length']:
                raise ValidationError(
                    f"Input exceeds maximum length of {policy['max_length']}"
                )
            
            # Check for blocked patterns
            for pattern in policy['blocked_patterns']:
                if re.search(pattern, input_str, re.IGNORECASE):
                    raise ValidationError(f"Input contains blocked pattern: {pattern}")
            
            # Type-specific validation
            if field_type == 'url':
                parsed = urlparse(input_str)
                if parsed.scheme not in policy['allowed_schemes']:
                    raise ValidationError(
                        f"URL scheme must be one of: {', '.join(policy['allowed_schemes'])}"
                    )
                if policy['allowed_hosts'] != ['*']:
                    if parsed.netloc not in policy['allowed_hosts']:
                        raise ValidationError(
                            f"Host must be one of: {', '.join(policy['allowed_hosts'])}"
                        )
            
            return True
            
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Input validation failed: {str(e)}")

class RateLimiter:
    """
    Rate limiter for API endpoints.
    
    This class implements rate limiting using a token bucket algorithm.
    """
    
    def __init__(self, policy: SecurityPolicy):
        """
        Initialize rate limiter.
        
        Args:
            policy: Security policy
        """
        self.policy = policy
        self.buckets: Dict[str, Dict[str, Any]] = {}
    
    def _get_bucket_key(self, request: Request) -> str:
        """
        Get bucket key for request.
        
        Args:
            request: HTTP request
            
        Returns:
            Bucket key
        """
        # Get client identifier
        client_id = request.headers.get('X-Forwarded-For', request.remote)
        
        # Get user identifier if available
        user_id = getattr(request, 'user', None)
        if user_id:
            return f"user:{user_id}"
        
        return f"ip:{client_id}"
    
    def _get_limits(self, bucket_key: str) -> Tuple[int, int]:
        """
        Get rate limits for bucket.
        
        Args:
            bucket_key: Bucket key
            
        Returns:
            Tuple of (limit, window)
        """
        policy = self.policy.policy['rate_limiting']
        
        if bucket_key.startswith('user:'):
            return policy['user_limit'], policy['user_window']
        return policy['ip_limit'], policy['ip_window']
    
    async def check_rate_limit(self, request: Request) -> bool:
        """
        Check if request is within rate limits.
        
        Args:
            request: HTTP request
            
        Returns:
            bool: True if request is allowed, False otherwise
            
        Raises:
            RateLimitError: If rate limit is exceeded
        """
        if not self.policy.get('rate_limiting', {}).get('enabled', True):
            return True
        
        bucket_key = self._get_bucket_key(request)
        limit, window = self._get_limits(bucket_key)
        
        # Get or create bucket
        bucket = self.buckets.get(bucket_key, {
            'tokens': limit,
            'last_update': time.time()
        })
        
        # Update bucket
        now = time.time()
        time_passed = now - bucket['last_update']
        bucket['tokens'] = min(
            limit,
            bucket['tokens'] + (time_passed * limit / window)
        )
        bucket['last_update'] = now
        
        # Check if request is allowed
        if bucket['tokens'] < 1:
            self.buckets[bucket_key] = bucket
            raise RateLimitError("Rate limit exceeded")
        
        # Consume token
        bucket['tokens'] -= 1
        self.buckets[bucket_key] = bucket
        
        return True

class Authenticator:
    """
    Authentication manager.
    
    This class handles user authentication, including:
    - Password hashing and verification
    - JWT token generation and validation
    - Session management
    """
    
    def __init__(self, policy: SecurityPolicy):
        """
        Initialize authenticator.
        
        Args:
            policy: Security policy
        """
        self.policy = policy
        self.sessions: Dict[str, Dict[str, Any]] = {}
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt.
        
        Args:
            password: Password to hash
            
        Returns:
            Hashed password
        """
        salt = bcrypt.gensalt(rounds=self.policy.get('authentication', {}).get('bcrypt_rounds', 12))
        return bcrypt.hashpw(password.encode(), salt).decode()
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            password: Password to verify
            hashed: Hashed password
            
        Returns:
            bool: True if password matches, False otherwise
        """
        return bcrypt.checkpw(password.encode(), hashed.encode())
    
    def generate_token(self, user_id: str, is_refresh: bool = False) -> str:
        """
        Generate JWT token.
        
        Args:
            user_id: User ID
            is_refresh: Whether to generate refresh token
            
        Returns:
            JWT token
        """
        policy = self.policy.get('authentication', {})
        expiry = policy.get('refresh_expiry' if is_refresh else 'jwt_expiry', 3600)
        
        payload = {
            'sub': user_id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=expiry),
            'type': 'refresh' if is_refresh else 'access'
        }
        
        return jwt.encode(
            payload,
            policy.get('jwt_secret', ''),
            algorithm=policy.get('jwt_algorithm', 'HS256')
        )
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate JWT token.
        
        Args:
            token: JWT token
            
        Returns:
            Token payload
            
        Raises:
            AuthenticationError: If token is invalid
        """
        try:
            policy = self.policy.get('authentication', {})
            payload = jwt.decode(
                token,
                policy.get('jwt_secret', ''),
                algorithms=[policy.get('jwt_algorithm', 'HS256')]
            )
            
            # Check token type
            if payload.get('type') != 'access':
                raise AuthenticationError("Invalid token type")
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {str(e)}")
    
    def refresh_token(self, refresh_token: str) -> Tuple[str, str]:
        """
        Refresh access token.
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            Tuple of (access_token, refresh_token)
            
        Raises:
            AuthenticationError: If refresh token is invalid
        """
        try:
            policy = self.policy.get('authentication', {})
            payload = jwt.decode(
                refresh_token,
                policy.get('jwt_secret', ''),
                algorithms=[policy.get('jwt_algorithm', 'HS256')]
            )
            
            # Check token type
            if payload.get('type') != 'refresh':
                raise AuthenticationError("Invalid token type")
            
            # Generate new tokens
            user_id = payload['sub']
            access_token = self.generate_token(user_id)
            new_refresh_token = self.generate_token(user_id, is_refresh=True)
            
            return access_token, new_refresh_token
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Refresh token has expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid refresh token: {str(e)}")

class Authorizer:
    """
    Authorization manager.
    
    This class handles user authorization, including:
    - Role-based access control
    - Permission checking
    - Security level enforcement
    """
    
    def __init__(self, policy: SecurityPolicy):
        """
        Initialize authorizer.
        
        Args:
            policy: Security policy
        """
        self.policy = policy
    
    def check_permission(self, user_roles: List[str], required_permission: str) -> bool:
        """
        Check if user has required permission.
        
        Args:
            user_roles: User roles
            required_permission: Required permission
            
        Returns:
            bool: True if user has permission, False otherwise
            
        Raises:
            AuthorizationError: If permission check fails
        """
        try:
            roles = self.policy.get('authorization', {}).get('roles', {})
            
            # Check each role
            for role in user_roles:
                if role not in roles:
                    continue
                
                # Check if role has permission
                permissions = roles[role]
                if '*' in permissions or required_permission in permissions:
                    return True
            
            raise AuthorizationError(
                f"User does not have required permission: {required_permission}"
            )
            
        except Exception as e:
            if isinstance(e, AuthorizationError):
                raise
            raise AuthorizationError(f"Permission check failed: {str(e)}")
    
    def check_security_level(self, user_level: SecurityLevel, required_level: SecurityLevel) -> bool:
        """
        Check if user meets required security level.
        
        Args:
            user_level: User's security level
            required_level: Required security level
            
        Returns:
            bool: True if user meets level, False otherwise
            
        Raises:
            AuthorizationError: If level check fails
        """
        try:
            levels = list(SecurityLevel)
            user_index = levels.index(user_level)
            required_index = levels.index(required_level)
            
            if user_index < required_index:
                raise AuthorizationError(
                    f"User security level {user_level.value} is below required level {required_level.value}"
                )
            
            return True
            
        except Exception as e:
            if isinstance(e, AuthorizationError):
                raise
            raise AuthorizationError(f"Security level check failed: {str(e)}")

class AuditLogger:
    """
    Audit logging manager.
    
    This class handles audit logging, including:
    - Logging security events
    - Logging user actions
    - Logging system events
    """
    
    def __init__(self, policy: SecurityPolicy):
        """
        Initialize audit logger.
        
        Args:
            policy: Security policy
        """
        self.policy = policy
        self.logger = logging.getLogger('bbf.audit')
        self._setup_logger()
    
    def _setup_logger(self) -> None:
        """Set up audit logger."""
        try:
            policy = self.policy.get('audit_logging', {})
            
            if not policy.get('enabled', True):
                self.logger.addHandler(logging.NullHandler())
                return
            
            # Create log directory
            log_path = Path(policy.get('log_path', 'data/security/audit.log'))
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Set up file handler
            handler = logging.FileHandler(log_path)
            handler.setLevel(policy.get('log_level', 'INFO'))
            
            # Set up formatter
            if policy.get('log_format') == 'json':
                formatter = logging.Formatter(
                    '%(message)s'
                )
            else:
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            
        except Exception as e:
            logger.error(f"Failed to set up audit logger: {e}")
            self.logger.addHandler(logging.NullHandler())
    
    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize sensitive data.
        
        Args:
            data: Data to sanitize
            
        Returns:
            Sanitized data
        """
        policy = self.policy.get('audit_logging', {})
        sensitive_fields = policy.get('sensitive_fields', [])
        
        def _sanitize_value(value: Any) -> Any:
            if isinstance(value, dict):
                return {k: _sanitize_value(v) for k, v in value.items()}
            if isinstance(value, list):
                return [_sanitize_value(v) for v in value]
            if isinstance(value, str):
                for field in sensitive_fields:
                    if field.lower() in value.lower():
                        return '***REDACTED***'
            return value
        
        return _sanitize_value(data)
    
    def log_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource: Optional[str] = None,
        status: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log audit event.
        
        Args:
            event_type: Type of event
            user_id: User ID
            action: Action performed
            resource: Resource affected
            status: Event status
            details: Additional details
        """
        try:
            if not self.policy.get('audit_logging', {}).get('enabled', True):
                return
            
            # Create event
            event = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': event_type,
                'user_id': user_id,
                'action': action,
                'resource': resource,
                'status': status,
                'details': self._sanitize_data(details or {})
            }
            
            # Log event
            if self.policy.get('audit_logging', {}).get('log_format') == 'json':
                self.logger.info(json.dumps(event))
            else:
                self.logger.info(
                    f"Event: {event_type}, User: {user_id}, "
                    f"Action: {action}, Resource: {resource}, "
                    f"Status: {status}, Details: {event['details']}"
                )
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            raise AuditError(f"Failed to log event: {str(e)}")

class SecurityManager:
    """
    Security manager for the framework.
    
    This class provides a central interface for:
    - Authentication and authorization
    - Rate limiting
    - Input validation
    - Security headers
    - Audit logging
    """
    
    def __init__(self, policy_path: Optional[Path] = None):
        """
        Initialize security manager.
        
        Args:
            policy_path: Path to policy configuration file
        """
        self.policy = SecurityPolicy(policy_path)
        self.rate_limiter = RateLimiter(self.policy)
        self.authenticator = Authenticator(self.policy)
        self.authorizer = Authorizer(self.policy)
        self.audit_logger = AuditLogger(self.policy)
    
    @middleware
    async def security_middleware(self, request: Request, handler: Any) -> Response:
        """
        Security middleware for HTTP requests.
        
        This middleware:
        1. Validates input
        2. Checks rate limits
        3. Validates authentication
        4. Checks authorization
        5. Adds security headers
        6. Logs audit events
        
        Args:
            request: HTTP request
            handler: Request handler
            
        Returns:
            HTTP response
            
        Raises:
            SecurityError: If security check fails
        """
        try:
            # Check rate limit
            await self.rate_limiter.check_rate_limit(request)
            
            # Get authentication token
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header[7:]
                try:
                    # Validate token
                    payload = self.authenticator.validate_token(token)
                    request['user'] = payload['sub']
                    request['user_roles'] = payload.get('roles', [])
                    request['security_level'] = SecurityLevel(payload.get('security_level', 'low'))
                except AuthenticationError as e:
                    raise HTTPUnauthorized(reason=str(e))
            
            # Process request
            response = await handler(request)
            
            # Add security headers
            if self.policy.get('security_headers', {}).get('enabled', True):
                headers = self.policy.get('security_headers', {}).get('headers', {})
                for key, value in headers.items():
                    response.headers[key] = value
            
            # Log audit event
            self.audit_logger.log_event(
                event_type='request',
                user_id=getattr(request, 'user', None),
                action=request.method,
                resource=str(request.url),
                status=str(response.status),
                details={
                    'headers': dict(request.headers),
                    'query': dict(request.query),
                    'remote': request.remote
                }
            )
            
            return response
            
        except RateLimitError as e:
            raise HTTPTooManyRequests(reason=str(e))
        except AuthenticationError as e:
            raise HTTPUnauthorized(reason=str(e))
        except AuthorizationError as e:
            raise HTTPForbidden(reason=str(e))
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            raise SecurityError(f"Security check failed: {str(e)}")
    
    def validate_password(self, password: str) -> bool:
        """
        Validate password against policy.
        
        Args:
            password: Password to validate
            
        Returns:
            bool: True if password is valid, False otherwise
            
        Raises:
            ValidationError: If password is invalid
        """
        return self.policy.validate_password(password)
    
    def validate_input(self, input_str: str, field_type: str = 'text') -> bool:
        """
        Validate input against policy.
        
        Args:
            input_str: Input to validate
            field_type: Type of input field
            
        Returns:
            bool: True if input is valid, False otherwise
            
        Raises:
            ValidationError: If input is invalid
        """
        return self.policy.validate_input(input_str, field_type)
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt.
        
        Args:
            password: Password to hash
            
        Returns:
            Hashed password
        """
        return self.authenticator.hash_password(password)
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            password: Password to verify
            hashed: Hashed password
            
        Returns:
            bool: True if password matches, False otherwise
        """
        return self.authenticator.verify_password(password, hashed)
    
    def generate_token(self, user_id: str, is_refresh: bool = False) -> str:
        """
        Generate JWT token.
        
        Args:
            user_id: User ID
            is_refresh: Whether to generate refresh token
            
        Returns:
            JWT token
        """
        return self.authenticator.generate_token(user_id, is_refresh)
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate JWT token.
        
        Args:
            token: JWT token
            
        Returns:
            Token payload
            
        Raises:
            AuthenticationError: If token is invalid
        """
        return self.authenticator.validate_token(token)
    
    def refresh_token(self, refresh_token: str) -> Tuple[str, str]:
        """
        Refresh access token.
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            Tuple of (access_token, refresh_token)
            
        Raises:
            AuthenticationError: If refresh token is invalid
        """
        return self.authenticator.refresh_token(refresh_token)
    
    def check_permission(self, user_roles: List[str], required_permission: str) -> bool:
        """
        Check if user has required permission.
        
        Args:
            user_roles: User roles
            required_permission: Required permission
            
        Returns:
            bool: True if user has permission, False otherwise
            
        Raises:
            AuthorizationError: If permission check fails
        """
        return self.authorizer.check_permission(user_roles, required_permission)
    
    def check_security_level(self, user_level: SecurityLevel, required_level: SecurityLevel) -> bool:
        """
        Check if user meets required security level.
        
        Args:
            user_level: User's security level
            required_level: Required security level
            
        Returns:
            bool: True if user meets level, False otherwise
            
        Raises:
            AuthorizationError: If level check fails
        """
        return self.authorizer.check_security_level(user_level, required_level)
    
    def log_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource: Optional[str] = None,
        status: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log audit event.
        
        Args:
            event_type: Type of event
            user_id: User ID
            action: Action performed
            resource: Resource affected
            status: Event status
            details: Additional details
        """
        self.audit_logger.log_event(
            event_type, user_id, action, resource, status, details
        ) 