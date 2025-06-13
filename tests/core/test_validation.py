"""
Tests for the validation module.

This module contains comprehensive test cases for the ValidationManager class,
verifying data validation, schema verification, and type checking functionality.
Tests are organized into categories: basic functionality, error handling,
security, performance, and integration tests.

Test Categories:
- Basic Functionality: Schema validation, type checking, format validation
- Error Handling: Invalid inputs, edge cases, error messages
- Security: Input sanitization, schema injection prevention
- Performance: Large data sets, concurrent validation
- Integration: Schema composition, custom validators

Each test category focuses on specific aspects of the validation system:
1. Basic Functionality: Core validation features and schema management
2. Error Handling: Robustness against invalid inputs and edge cases
3. Security: Protection against malicious inputs and data leaks
4. Performance: Efficiency with large datasets and concurrent operations
5. Integration: Compatibility with custom validators and schema composition
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import json
import asyncio
import time
from datetime import datetime
from typing import Dict, List, Optional, Union, Any, Callable
import ipaddress
import re

from bbf.core.validation import ValidationManager
from bbf.core.exceptions import ValidationError

# Test Configuration
TEST_CONFIG = {
    'strict_mode': True,
    'max_depth': 10,
    'max_array_length': 1000,
    'max_string_length': 10000,
    'allowed_types': ['string', 'integer', 'float', 'boolean', 'array', 'object'],
    'validation_timeout': 5.0,  # seconds
    'max_concurrent_validations': 10
}

# Test Schemas
TEST_SCHEMAS = {
    'target': {
        'type': 'object',
        'required': ['url', 'scope'],
        'properties': {
            'url': {'type': 'string', 'format': 'uri'},
            'scope': {'type': 'string', 'enum': ['in-scope', 'out-of-scope']},
            'tags': {'type': 'array', 'items': {'type': 'string'}},
            'metadata': {'type': 'object'}
        }
    },
    'finding': {
        'type': 'object',
        'required': ['type', 'severity', 'description'],
        'properties': {
            'type': {'type': 'string'},
            'severity': {'type': 'string', 'enum': ['low', 'medium', 'high', 'critical']},
            'description': {'type': 'string', 'minLength': 10},
            'evidence': {'type': 'string'},
            'timestamp': {'type': 'string', 'format': 'date-time'}
        }
    },
    'plugin_config': {
        'type': 'object',
        'required': ['name', 'version'],
        'properties': {
            'name': {'type': 'string', 'pattern': '^[a-zA-Z0-9_-]+$'},
            'version': {'type': 'string', 'pattern': '^\\d+\\.\\d+\\.\\d+$'},
            'settings': {'type': 'object'},
            'dependencies': {
                'type': 'object',
                'properties': {
                    'required': {'type': 'array', 'items': {'type': 'string'}},
                    'optional': {'type': 'array', 'items': {'type': 'string'}}
                }
            }
        }
    }
}

# Test Data
TEST_DATA = {
    'valid_target': {
        'url': 'https://example.com',
        'scope': 'in-scope',
        'tags': ['web', 'api'],
        'metadata': {'owner': 'team-a'}
    },
    'invalid_target': {
        'url': 'not-a-url',
        'scope': 'invalid-scope',
        'tags': 'not-an-array'
    },
    'valid_finding': {
        'type': 'xss',
        'severity': 'high',
        'description': 'Cross-site scripting vulnerability found in search parameter',
        'evidence': '<script>alert(1)</script>',
        'timestamp': datetime.now().isoformat()
    },
    'invalid_finding': {
        'type': 123,
        'severity': 'invalid',
        'description': 'too short'
    },
    'valid_plugin_config': {
        'name': 'test-plugin',
        'version': '1.0.0',
        'settings': {'timeout': 30},
        'dependencies': {
            'required': ['plugin-a'],
            'optional': ['plugin-b']
        }
    },
    'invalid_plugin_config': {
        'name': 'invalid name',
        'version': '1.0',
        'settings': 'not-an-object'
    }
}

# Test Fixtures
@pytest.fixture
async def validation_manager():
    """
    Create and initialize a ValidationManager instance for testing.
    
    This fixture ensures proper setup and cleanup of the validation manager
    for each test case. It also verifies that the manager is properly
    initialized before use and cleaned up after use.
    
    Returns:
        ValidationManager: An initialized validation manager instance.
    """
    manager = ValidationManager(TEST_CONFIG)
    await manager.initialize()
    yield manager
    await manager.cleanup()

@pytest.fixture
async def registered_schemas(validation_manager):
    """
    Register all test schemas with the validation manager.
    
    This fixture ensures that all test schemas are registered and available
    for validation tests. It also handles cleanup after tests.
    
    Args:
        validation_manager: The validation manager instance.
    
    Returns:
        Dict[str, Dict]: A dictionary of registered schema names and their schemas.
    """
    for name, schema in TEST_SCHEMAS.items():
        await validation_manager.register_schema(name, schema)
    return TEST_SCHEMAS

# Basic Functionality Tests
class TestBasicFunctionality:
    """Tests for basic validation functionality."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, validation_manager):
        """Test validation manager initialization and configuration."""
        assert validation_manager._initialized
        assert validation_manager._strict_mode == TEST_CONFIG['strict_mode']
        assert validation_manager._max_depth == TEST_CONFIG['max_depth']
        assert validation_manager._max_array_length == TEST_CONFIG['max_array_length']
        assert validation_manager._max_string_length == TEST_CONFIG['max_string_length']
        assert validation_manager._allowed_types == TEST_CONFIG['allowed_types']
        assert validation_manager._validation_timeout == TEST_CONFIG['validation_timeout']
        assert validation_manager._max_concurrent_validations == TEST_CONFIG['max_concurrent_validations']
    
    @pytest.mark.asyncio
    async def test_schema_registration(self, validation_manager):
        """Test schema registration and retrieval."""
        # Register test schemas
        for name, schema in TEST_SCHEMAS.items():
            await validation_manager.register_schema(name, schema)
            assert name in validation_manager.registered_schemas
            assert validation_manager.registered_schemas[name] == schema
            
            # Test schema retrieval
            retrieved_schema = await validation_manager.get_schema(name)
            assert retrieved_schema == schema
    
    @pytest.mark.asyncio
    async def test_schema_validation(self, validation_manager, registered_schemas):
        """Test validation against registered schemas."""
        # Test valid data
        assert await validation_manager.validate_data('target', TEST_DATA['valid_target'])
        assert await validation_manager.validate_data('finding', TEST_DATA['valid_finding'])
        assert await validation_manager.validate_data('plugin_config', TEST_DATA['valid_plugin_config'])
        
        # Test invalid data with detailed error messages
        with pytest.raises(ValidationError) as exc_info:
            await validation_manager.validate_data('target', TEST_DATA['invalid_target'])
        error_msg = str(exc_info.value).lower()
        assert 'validation failed' in error_msg
        assert 'url' in error_msg
        assert 'scope' in error_msg
        assert 'tags' in error_msg
    
    @pytest.mark.asyncio
    async def test_type_validation(self, validation_manager):
        """Test type validation for all supported types."""
        type_tests = {
            'string': ('test', 123, None),
            'integer': (123, '123', 123.45),
            'float': (123.45, '123.45', None),
            'boolean': (True, 'true', 1),
            'array': ([1, 2, 3], 'not-an-array', None),
            'object': ({'key': 'value'}, 'not-an-object', None)
        }
        
        for type_name, (valid_value, *invalid_values) in type_tests.items():
            # Test valid value
            assert await validation_manager.validate_type(type_name, valid_value)
            
            # Test invalid values
            for invalid_value in invalid_values:
                with pytest.raises(ValidationError) as exc_info:
                    await validation_manager.validate_type(type_name, invalid_value)
                assert f"expected {type_name}" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_format_validation(self, validation_manager):
        """Test format validation for common formats."""
        format_tests = {
            'uri': [
                ('https://example.com', True),
                ('http://localhost:8080', True),
                ('not-a-uri', False),
                ('ftp://invalid', False)
            ],
            'date-time': [
                (datetime.now().isoformat(), True),
                ('2024-02-14T12:00:00Z', True),
                ('not-a-date', False),
                ('2024-13-45', False)
            ],
            'email': [
                ('test@example.com', True),
                ('user.name+tag@domain.com', True),
                ('not-an-email', False),
                ('@domain.com', False)
            ],
            'hostname': [
                ('example.com', True),
                ('sub.domain.com', True),
                ('not-a-hostname', False),
                ('invalid..domain', False)
            ]
        }
        
        for format_name, test_cases in format_tests.items():
            for value, should_pass in test_cases:
                if should_pass:
                    assert await validation_manager.validate_format(format_name, value)
                else:
                    with pytest.raises(ValidationError) as exc_info:
                        await validation_manager.validate_format(format_name, value)
                    assert f"invalid {format_name}" in str(exc_info.value).lower()

# Error Handling Tests
class TestErrorHandling:
    """Tests for error handling and edge cases."""
    
    @pytest.mark.asyncio
    async def test_invalid_schema(self, validation_manager):
        """Test handling of invalid schema definitions."""
        invalid_schemas = [
            {'type': 'invalid_type'},
            {'properties': {'key': {'type': 'unknown_type'}}},
            {'required': 'not-an-array'},
            {'type': 'object', 'properties': {'key': {'type': 'string', 'format': 'unknown_format'}}},
            {'type': 'array', 'items': {'type': 'invalid_type'}}
        ]
        
        for schema in invalid_schemas:
            with pytest.raises(ValidationError) as exc_info:
                await validation_manager.register_schema('test', schema)
            assert 'invalid schema' in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_missing_schema(self, validation_manager):
        """Test handling of validation against non-existent schema."""
        with pytest.raises(ValidationError) as exc_info:
            await validation_manager.validate_data('non_existent', {})
        assert 'schema not found' in str(exc_info.value).lower()
        
        # Test schema retrieval
        with pytest.raises(ValidationError) as exc_info:
            await validation_manager.get_schema('non_existent')
        assert 'schema not found' in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_nested_validation_errors(self, validation_manager):
        """Test handling of nested validation errors."""
        schema = {
            'type': 'object',
            'properties': {
                'nested': {
                    'type': 'object',
                    'required': ['field1', 'field2'],
                    'properties': {
                        'field1': {'type': 'string'},
                        'field2': {'type': 'integer'},
                        'array_field': {
                            'type': 'array',
                            'items': {'type': 'string'}
                        }
                    }
                }
            }
        }
        
        await validation_manager.register_schema('test', schema)
        
        # Test multiple nested errors
        invalid_data = {
            'nested': {
                'field1': 123,  # Should be string
                'field2': 'not-an-int',  # Should be integer
                'array_field': [1, 2, 3]  # Should be array of strings
            }
        }
        
        with pytest.raises(ValidationError) as exc_info:
            await validation_manager.validate_data('test', invalid_data)
        
        error_msg = str(exc_info.value).lower()
        assert 'nested.field1' in error_msg
        assert 'nested.field2' in error_msg
        assert 'nested.array_field' in error_msg
    
    @pytest.mark.asyncio
    async def test_validation_timeout(self, validation_manager):
        """Test validation timeout handling."""
        # Create a schema that would cause infinite recursion
        recursive_schema = {
            'type': 'object',
            'properties': {
                'self': {'$ref': '#'}
            }
        }
        
        await validation_manager.register_schema('recursive', recursive_schema)
        
        # Create data that would cause infinite recursion
        recursive_data = {'self': {'self': {'self': {}}}}
        
        with pytest.raises(ValidationError) as exc_info:
            await validation_manager.validate_data('recursive', recursive_data)
        assert 'timeout' in str(exc_info.value).lower()

# Security Tests
class TestSecurity:
    """Tests for security-related validation features."""
    
    @pytest.mark.asyncio
    async def test_schema_injection_prevention(self, validation_manager):
        """Test prevention of schema injection attacks."""
        malicious_schemas = [
            {
                'type': 'object',
                'properties': {
                    'exec': {'type': 'string', 'pattern': '.*'}
                }
            },
            {
                'type': 'object',
                'properties': {
                    'eval': {'type': 'string', 'pattern': '.*'}
                }
            },
            {
                'type': 'object',
                'properties': {
                    'system': {'type': 'string', 'pattern': '.*'}
                }
            }
        ]
        
        for schema in malicious_schemas:
            with pytest.raises(ValidationError) as exc_info:
                await validation_manager.register_schema('malicious', schema)
            assert 'security' in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_large_input_handling(self, validation_manager):
        """Test handling of large input data."""
        # Create large data structures
        large_string = 'x' * (TEST_CONFIG['max_string_length'] + 1)
        large_array = [1] * (TEST_CONFIG['max_array_length'] + 1)
        deep_object = {}
        current = deep_object
        for _ in range(TEST_CONFIG['max_depth'] + 1):
            current['nested'] = {}
            current = current['nested']
        
        # Test string length limit
        with pytest.raises(ValidationError) as exc_info:
            await validation_manager.validate_type('string', large_string)
        assert 'string length' in str(exc_info.value).lower()
        
        # Test array length limit
        with pytest.raises(ValidationError) as exc_info:
            await validation_manager.validate_type('array', large_array)
        assert 'array length' in str(exc_info.value).lower()
        
        # Test object depth limit
        with pytest.raises(ValidationError) as exc_info:
            await validation_manager.validate_type('object', deep_object)
        assert 'max depth' in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_sensitive_data_validation(self, validation_manager):
        """Test validation of sensitive data fields."""
        sensitive_schema = {
            'type': 'object',
            'properties': {
                'password': {
                    'type': 'string',
                    'format': 'password',
                    'minLength': 8,
                    'pattern': '^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d@$!%*#?&]{8,}$'
                },
                'api_key': {
                    'type': 'string',
                    'format': 'api-key',
                    'pattern': '^[A-Za-z0-9]{32}$'
                },
                'credit_card': {
                    'type': 'string',
                    'format': 'credit-card',
                    'pattern': '^\\d{16}$'
                }
            }
        }
        
        await validation_manager.register_schema('sensitive', sensitive_schema)
        
        # Test valid sensitive data
        valid_data = {
            'password': 'StrongP@ss123',
            'api_key': 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
            'credit_card': '4111111111111111'
        }
        assert await validation_manager.validate_data('sensitive', valid_data)
        
        # Test invalid sensitive data
        invalid_data = {
            'password': 'weak',
            'api_key': 'invalid-key',
            'credit_card': '1234-5678-9012-3456'
        }
        
        with pytest.raises(ValidationError) as exc_info:
            await validation_manager.validate_data('sensitive', invalid_data)
        error_msg = str(exc_info.value).lower()
        assert 'password' in error_msg
        assert 'api_key' in error_msg
        assert 'credit_card' in error_msg

# Performance Tests
class TestPerformance:
    """Tests for validation performance and efficiency."""
    
    @pytest.mark.asyncio
    async def test_validation_speed(self, validation_manager):
        """Test validation performance with various data sizes."""
        # Create test data of different sizes
        data_sizes = [100, 1000, 10000]
        results = {}
        
        for size in data_sizes:
            # Create large object
            large_object = {
                'array': [str(i) for i in range(size)],
                'object': {str(i): i for i in range(size)}
            }
            
            # Measure validation time
            start_time = time.time()
            await validation_manager.validate_type('object', large_object)
            end_time = time.time()
            
            results[size] = end_time - start_time
        
        # Verify performance characteristics
        for i in range(len(data_sizes) - 1):
            current_size = data_sizes[i]
            next_size = data_sizes[i + 1]
            current_time = results[current_size]
            next_time = results[next_size]
            
            # Verify that time increase is sub-linear
            size_ratio = next_size / current_size
            time_ratio = next_time / current_time
            assert time_ratio < size_ratio
    
    @pytest.mark.asyncio
    async def test_concurrent_validation(self, validation_manager):
        """Test concurrent validation performance."""
        # Create multiple validation tasks
        async def validate():
            data = {
                'array': [str(i) for i in range(100)],
                'object': {str(i): i for i in range(100)}
            }
            return await validation_manager.validate_type('object', data)
        
        # Run concurrent validations
        num_tasks = TEST_CONFIG['max_concurrent_validations']
        tasks = [validate() for _ in range(num_tasks)]
        
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        end_time = time.time()
        
        # Verify all validations succeeded
        assert all(results)
        
        # Verify concurrent execution
        total_time = end_time - start_time
        assert total_time < num_tasks * 0.1  # Assuming each validation takes < 0.1s

# Integration Tests
class TestIntegration:
    """Tests for integration with other components."""
    
    @pytest.mark.asyncio
    async def test_custom_validators(self, validation_manager):
        """Test integration with custom validators."""
        # Define custom validators
        async def validate_password_strength(value: str) -> bool:
            if not isinstance(value, str):
                raise ValidationError("Password must be a string")
            if len(value) < 8:
                raise ValidationError("Password must be at least 8 characters")
            if not re.search(r'[A-Z]', value):
                raise ValidationError("Password must contain uppercase letters")
            if not re.search(r'[a-z]', value):
                raise ValidationError("Password must contain lowercase letters")
            if not re.search(r'\d', value):
                raise ValidationError("Password must contain numbers")
            return True
        
        async def validate_ip_range(value: str) -> bool:
            try:
                ip = ipaddress.ip_address(value)
                return ip.is_private
            except ValueError:
                raise ValidationError("Invalid IP address")
        
        # Register custom validators
        await validation_manager.register_validator('password-strength', validate_password_strength)
        await validation_manager.register_validator('private-ip', validate_ip_range)
        
        # Test custom validation
        schema = {
            'type': 'object',
            'properties': {
                'password': {'type': 'string', 'validator': 'password-strength'},
                'ip': {'type': 'string', 'validator': 'private-ip'}
            }
        }
        
        await validation_manager.register_schema('custom', schema)
        
        # Test valid data
        valid_data = {
            'password': 'StrongP@ss123',
            'ip': '192.168.1.1'
        }
        assert await validation_manager.validate_data('custom', valid_data)
        
        # Test invalid data
        invalid_data = {
            'password': 'weak',
            'ip': '8.8.8.8'
        }
        
        with pytest.raises(ValidationError) as exc_info:
            await validation_manager.validate_data('custom', invalid_data)
        error_msg = str(exc_info.value).lower()
        assert 'password' in error_msg
        assert 'ip' in error_msg
    
    @pytest.mark.asyncio
    async def test_schema_composition(self, validation_manager):
        """Test composition of multiple schemas."""
        # Define base schemas
        base_schemas = {
            'common': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string', 'pattern': '^[A-Za-z0-9-]+$'},
                    'created_at': {'type': 'string', 'format': 'date-time'},
                    'updated_at': {'type': 'string', 'format': 'date-time'}
                }
            },
            'metadata': {
                'type': 'object',
                'properties': {
                    'tags': {'type': 'array', 'items': {'type': 'string'}},
                    'description': {'type': 'string'},
                    'owner': {'type': 'string'}
                }
            }
        }
        
        # Register base schemas
        for name, schema in base_schemas.items():
            await validation_manager.register_schema(name, schema)
        
        # Create composed schema
        composed_schema = {
            'type': 'object',
            'allOf': [
                {'$ref': 'common'},
                {'$ref': 'metadata'},
                {
                    'properties': {
                        'status': {'type': 'string', 'enum': ['active', 'inactive']},
                        'priority': {'type': 'integer', 'minimum': 1, 'maximum': 5}
                    }
                }
            ]
        }
        
        await validation_manager.register_schema('composed', composed_schema)
        
        # Test valid composed data
        valid_data = {
            'id': 'test-123',
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'tags': ['test', 'composed'],
            'description': 'Test composed schema',
            'owner': 'team-a',
            'status': 'active',
            'priority': 3
        }
        assert await validation_manager.validate_data('composed', valid_data)
        
        # Test invalid composed data
        invalid_data = {
            'id': 'invalid id',
            'created_at': 'invalid-date',
            'tags': 'not-an-array',
            'status': 'invalid-status',
            'priority': 6
        }
        
        with pytest.raises(ValidationError) as exc_info:
            await validation_manager.validate_data('composed', invalid_data)
        error_msg = str(exc_info.value).lower()
        assert 'id' in error_msg
        assert 'created_at' in error_msg
        assert 'tags' in error_msg
        assert 'status' in error_msg
        assert 'priority' in error_msg
    
    @pytest.mark.asyncio
    async def test_data_transformation(self, validation_manager):
        """Test data transformation during validation."""
        # Define transformation functions
        async def transform_date(value: str) -> str:
            try:
                dt = datetime.fromisoformat(value)
                return dt.isoformat()
            except ValueError:
                raise ValidationError("Invalid date format")
        
        async def transform_tags(value: List[str]) -> List[str]:
            if not isinstance(value, list):
                raise ValidationError("Tags must be a list")
            return [tag.strip().lower() for tag in value if tag.strip()]
        
        # Register transformers
        await validation_manager.register_transformer('date', transform_date)
        await validation_manager.register_transformer('tags', transform_tags)
        
        # Create schema with transformations
        schema = {
            'type': 'object',
            'properties': {
                'date': {'type': 'string', 'transformer': 'date'},
                'tags': {'type': 'array', 'transformer': 'tags'}
            }
        }
        
        await validation_manager.register_schema('transform', schema)
        
        # Test data transformation
        input_data = {
            'date': '2024-02-14T12:00:00',
            'tags': [' Tag1 ', 'TAG2', '  tag3  ', '']
        }
        
        transformed_data = await validation_manager.validate_and_transform('transform', input_data)
        
        # Verify transformations
        assert transformed_data['date'] == '2024-02-14T12:00:00'
        assert transformed_data['tags'] == ['tag1', 'tag2', 'tag3']
        
        # Test invalid data
        invalid_data = {
            'date': 'invalid-date',
            'tags': 'not-an-array'
        }
        
        with pytest.raises(ValidationError) as exc_info:
            await validation_manager.validate_and_transform('transform', invalid_data)
        error_msg = str(exc_info.value).lower()
        assert 'date' in error_msg
        assert 'tags' in error_msg 