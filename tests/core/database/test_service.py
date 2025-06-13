"""
Tests for the database service layer.

This module contains comprehensive test cases for the database services,
verifying their CRUD operations, business logic, and error handling.
Tests are organized into categories: basic functionality, CRUD operations,
query operations, error handling, and integration.

Test Categories:
- Basic Functionality: Service initialization, session management, and cleanup
- CRUD Operations: Create, read, update, and delete operations for all entities
- Query Operations: Filtering, listing, and relationship queries
- Error Handling: Database errors, validation errors, and edge cases
- Integration: End-to-end service interaction and data flow

Each test category focuses on specific aspects of the database services:
1. Basic Functionality: Core service features and session management
2. CRUD Operations: Entity lifecycle management
3. Query Operations: Data retrieval and filtering
4. Error Handling: Exception handling and validation
5. Integration: Complete service workflow
"""

import pytest
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from unittest.mock import AsyncMock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from bbf.core.database.models import (
    Base, Finding, Stage, Plugin, Target,
    FindingStatus, FindingSeverity, StageStatus
)
from bbf.core.database.service import (
    finding_service, stage_service, plugin_service, target_service
)
from bbf.core.exceptions import DatabaseError

# Test Configuration
TEST_DB_URL = "sqlite:///:memory:"
engine = create_engine(TEST_DB_URL)
Session = sessionmaker(bind=engine)

# Test Data
TEST_FINDING_DATA = {
    'type': 'subdomain',
    'title': 'Discovered subdomain',
    'description': 'Found subdomain test.example.com',
    'severity': FindingSeverity.LOW,
    'confidence': 0.8,
    'status': FindingStatus.ACTIVE
}

TEST_STAGE_DATA = {
    'name': 'recon',
    'status': StageStatus.INITIALIZED
}

TEST_PLUGIN_DATA = {
    'name': 'subdomain_enum',
    'version': '1.0.0',
    'status': 'initialized'
}

TEST_TARGET_DATA = {
    'url': 'https://example.com',
    'scope': 'example.com',
    'status': 'active'
}

# Test Fixtures
@pytest.fixture(scope="function")
def db_session():
    """
    Create a new database session for a test.
    
    This fixture ensures proper database setup and cleanup for each test.
    It creates all tables before the test and drops them after.
    
    Returns:
        Session: A SQLAlchemy session instance.
    """
    Base.metadata.create_all(engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)

@pytest.fixture
async def test_target(db_session):
    """
    Create a test target for testing.
    
    This fixture provides a pre-configured target instance for use in tests.
    It ensures proper cleanup after each test.
    
    Returns:
        Target: A test target instance.
    """
    target = await target_service.create(
        db_session,
        **TEST_TARGET_DATA
    )
    return target

@pytest.fixture
async def test_stage(db_session, test_target):
    """
    Create a test stage for testing.
    
    This fixture provides a pre-configured stage instance linked to a test target.
    It ensures proper cleanup after each test.
    
    Returns:
        Stage: A test stage instance.
    """
    stage = await stage_service.create(
        db_session,
        target_id=test_target.id,
        **TEST_STAGE_DATA
    )
    return stage

@pytest.fixture
async def test_plugin(db_session, test_stage):
    """
    Create a test plugin for testing.
    
    This fixture provides a pre-configured plugin instance linked to a test stage.
    It ensures proper cleanup after each test.
    
    Returns:
        Plugin: A test plugin instance.
    """
    plugin = await plugin_service.create(
        db_session,
        stage_id=test_stage.id,
        **TEST_PLUGIN_DATA
    )
    return plugin

# Basic Functionality Tests
class TestBasicFunctionality:
    """Tests for basic database service functionality."""
    
    @pytest.mark.asyncio
    async def test_session_management(self, db_session):
        """Test database session management."""
        # Test session is active
        assert db_session.is_active
        
        # Test session cleanup
        db_session.close()
        assert not db_session.is_active
        
        # Test session recreation
        new_session = Session()
        assert new_session.is_active
        new_session.close()
    
    @pytest.mark.asyncio
    async def test_database_initialization(self, db_session):
        """Test database initialization and table creation."""
        # Verify tables exist
        inspector = engine.dialect.inspector
        tables = inspector.get_table_names()
        assert 'findings' in tables
        assert 'stages' in tables
        assert 'plugins' in tables
        assert 'targets' in tables

# CRUD Operation Tests
class TestFindingOperations:
    """Tests for finding CRUD operations."""
    
    @pytest.mark.asyncio
    async def test_create_finding(self, db_session, test_plugin):
        """Test finding creation."""
        # Create finding
        finding = await finding_service.create(
            db_session,
            plugin_id=test_plugin.id,
            **TEST_FINDING_DATA
        )
        
        # Verify creation
        assert finding.id is not None
        assert finding.plugin_id == test_plugin.id
        assert finding.type == TEST_FINDING_DATA['type']
        assert finding.severity == TEST_FINDING_DATA['severity']
        assert finding.confidence == TEST_FINDING_DATA['confidence']
        assert finding.status == TEST_FINDING_DATA['status']
        
        # Verify retrieval
        retrieved = await finding_service.get_by_id(db_session, finding.id)
        assert retrieved.id == finding.id
        assert retrieved.type == finding.type
    
    @pytest.mark.asyncio
    async def test_update_finding(self, db_session, test_plugin):
        """Test finding update."""
        # Create finding
        finding = await finding_service.create(
            db_session,
            plugin_id=test_plugin.id,
            **TEST_FINDING_DATA
        )
        
        # Update finding
        update_data = {
            'status': FindingStatus.VERIFIED,
            'confidence': 0.9,
            'description': 'Updated description'
        }
        updated = await finding_service.update(db_session, finding.id, **update_data)
        
        # Verify updates
        assert updated.status == FindingStatus.VERIFIED
        assert updated.confidence == 0.9
        assert updated.description == 'Updated description'
        
        # Test invalid update
        with pytest.raises(ValueError):
            await finding_service.update(db_session, finding.id, severity='invalid')
    
    @pytest.mark.asyncio
    async def test_delete_finding(self, db_session, test_plugin):
        """Test finding deletion."""
        # Create finding
        finding = await finding_service.create(
            db_session,
            plugin_id=test_plugin.id,
            **TEST_FINDING_DATA
        )
        
        # Delete finding
        await finding_service.delete(db_session, finding.id)
        
        # Verify deletion
        deleted = await finding_service.get_by_id(db_session, finding.id)
        assert deleted is None

class TestStageOperations:
    """Tests for stage CRUD operations."""
    
    @pytest.mark.asyncio
    async def test_create_stage(self, db_session, test_target):
        """Test stage creation."""
        # Create stage
        stage = await stage_service.create(
            db_session,
            target_id=test_target.id,
            **TEST_STAGE_DATA
        )
        
        # Verify creation
        assert stage.id is not None
        assert stage.name == TEST_STAGE_DATA['name']
        assert stage.target_id == test_target.id
        assert stage.status == TEST_STAGE_DATA['status']
        
        # Verify retrieval
        retrieved = await stage_service.get_by_id(db_session, stage.id)
        assert retrieved.id == stage.id
        assert retrieved.name == stage.name
    
    @pytest.mark.asyncio
    async def test_update_stage(self, db_session, test_target):
        """Test stage update."""
        # Create stage
        stage = await stage_service.create(
            db_session,
            target_id=test_target.id,
            **TEST_STAGE_DATA
        )
        
        # Update stage
        update_data = {
            'status': StageStatus.RUNNING,
            'progress': 0.5
        }
        updated = await stage_service.update(db_session, stage.id, **update_data)
        
        # Verify updates
        assert updated.status == StageStatus.RUNNING
        assert updated.progress == 0.5
        
        # Test invalid update
        with pytest.raises(ValueError):
            await stage_service.update(db_session, stage.id, status='invalid')

class TestPluginOperations:
    """Tests for plugin CRUD operations."""
    
    @pytest.mark.asyncio
    async def test_create_plugin(self, db_session, test_stage):
        """Test plugin creation."""
        # Create plugin
        plugin = await plugin_service.create(
            db_session,
            stage_id=test_stage.id,
            **TEST_PLUGIN_DATA
        )
        
        # Verify creation
        assert plugin.id is not None
        assert plugin.name == TEST_PLUGIN_DATA['name']
        assert plugin.stage_id == test_stage.id
        assert plugin.version == TEST_PLUGIN_DATA['version']
        assert plugin.status == TEST_PLUGIN_DATA['status']
        
        # Verify retrieval
        retrieved = await plugin_service.get_by_id(db_session, plugin.id)
        assert retrieved.id == plugin.id
        assert retrieved.name == plugin.name
    
    @pytest.mark.asyncio
    async def test_update_plugin(self, db_session, test_stage):
        """Test plugin update."""
        # Create plugin
        plugin = await plugin_service.create(
            db_session,
            stage_id=test_stage.id,
            **TEST_PLUGIN_DATA
        )
        
        # Update plugin
        update_data = {
            'status': 'running',
            'progress': 0.5
        }
        updated = await plugin_service.update(db_session, plugin.id, **update_data)
        
        # Verify updates
        assert updated.status == 'running'
        assert updated.progress == 0.5

class TestTargetOperations:
    """Tests for target CRUD operations."""
    
    @pytest.mark.asyncio
    async def test_create_target(self, db_session):
        """Test target creation."""
        # Create target
        target = await target_service.create(
            db_session,
            **TEST_TARGET_DATA
        )
        
        # Verify creation
        assert target.id is not None
        assert target.url == TEST_TARGET_DATA['url']
        assert target.scope == TEST_TARGET_DATA['scope']
        assert target.status == TEST_TARGET_DATA['status']
        
        # Verify retrieval
        retrieved = await target_service.get_by_id(db_session, target.id)
        assert retrieved.id == target.id
        assert retrieved.url == target.url
    
    @pytest.mark.asyncio
    async def test_update_target(self, db_session):
        """Test target update."""
        # Create target
        target = await target_service.create(
            db_session,
            **TEST_TARGET_DATA
        )
        
        # Update target
        update_data = {
            'status': 'completed',
            'scope': 'example.com,test.example.com'
        }
        updated = await target_service.update(db_session, target.id, **update_data)
        
        # Verify updates
        assert updated.status == 'completed'
        assert updated.scope == 'example.com,test.example.com'

# Query Operation Tests
class TestQueryOperations:
    """Tests for database query operations."""
    
    @pytest.mark.asyncio
    async def test_finding_queries(self, db_session, test_plugin):
        """Test finding query operations."""
        # Create multiple findings
        findings = []
        for i in range(3):
            finding = await finding_service.create(
                db_session,
                plugin_id=test_plugin.id,
                type='subdomain',
                title=f'Discovered subdomain {i}',
                description=f'Found subdomain test{i}.example.com',
                severity=FindingSeverity.LOW,
                confidence=0.8,
                status=FindingStatus.ACTIVE
            )
            findings.append(finding)
        
        # Test listing all findings
        all_findings = await finding_service.list(db_session)
        assert len(all_findings) == 3
        
        # Test filtering by plugin
        plugin_findings = await finding_service.list(
            db_session,
            plugin_id=test_plugin.id
        )
        assert len(plugin_findings) == 3
        
        # Test filtering by status
        active_findings = await finding_service.list(
            db_session,
            status=FindingStatus.ACTIVE
        )
        assert len(active_findings) == 3
        
        # Test filtering by severity
        low_findings = await finding_service.list(
            db_session,
            severity=FindingSeverity.LOW
        )
        assert len(low_findings) == 3
    
    @pytest.mark.asyncio
    async def test_relationship_queries(self, db_session, test_target, test_stage, test_plugin):
        """Test relationship query operations."""
        # Create finding
        finding = await finding_service.create(
            db_session,
            plugin_id=test_plugin.id,
            **TEST_FINDING_DATA
        )
        
        # Test finding relationships
        assert finding.plugin.stage.target.id == test_target.id
        assert finding.plugin.stage.id == test_stage.id
        assert finding.plugin.id == test_plugin.id
        
        # Test target relationships
        target_stages = await stage_service.list(db_session, target_id=test_target.id)
        assert len(target_stages) == 1
        assert target_stages[0].id == test_stage.id
        
        # Test stage relationships
        stage_plugins = await plugin_service.list(db_session, stage_id=test_stage.id)
        assert len(stage_plugins) == 1
        assert stage_plugins[0].id == test_plugin.id

# Error Handling Tests
class TestErrorHandling:
    """Tests for database error handling."""
    
    @pytest.mark.asyncio
    async def test_finding_errors(self, db_session):
        """Test finding service error handling."""
        # Test non-existent finding
        with pytest.raises(DatabaseError):
            await finding_service.get_by_id(db_session, 999999)
        
        with pytest.raises(DatabaseError):
            await finding_service.update(db_session, 999999, status=FindingStatus.ACTIVE)
        
        with pytest.raises(DatabaseError):
            await finding_service.delete(db_session, 999999)
    
    @pytest.mark.asyncio
    async def test_stage_errors(self, db_session):
        """Test stage service error handling."""
        # Test non-existent stage
        with pytest.raises(DatabaseError):
            await stage_service.get_by_id(db_session, 999999)
        
        with pytest.raises(DatabaseError):
            await stage_service.update(db_session, 999999, status=StageStatus.RUNNING)
    
    @pytest.mark.asyncio
    async def test_plugin_errors(self, db_session):
        """Test plugin service error handling."""
        # Test non-existent plugin
        with pytest.raises(DatabaseError):
            await plugin_service.get_by_id(db_session, 999999)
        
        with pytest.raises(DatabaseError):
            await plugin_service.update(db_session, 999999, status='running')
    
    @pytest.mark.asyncio
    async def test_target_errors(self, db_session):
        """Test target service error handling."""
        # Test non-existent target
        with pytest.raises(DatabaseError):
            await target_service.get_by_id(db_session, 999999)
        
        with pytest.raises(DatabaseError):
            await target_service.update(db_session, 999999, status='completed')
    
    @pytest.mark.asyncio
    async def test_validation_errors(self, db_session, test_plugin):
        """Test input validation error handling."""
        # Test invalid finding data
        with pytest.raises(ValueError):
            await finding_service.create(
                db_session,
                plugin_id=test_plugin.id,
                type='invalid_type',
                title='Test Finding',
                severity='invalid_severity',
                confidence=2.0,
                status='invalid_status'
            )
        
        # Test invalid stage data
        with pytest.raises(ValueError):
            await stage_service.create(
                db_session,
                name='',
                target_id=999999,
                status='invalid_status'
            )

# Integration Tests
class TestIntegration:
    """Tests for database service integration."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_workflow(self, db_session):
        """Test end-to-end database workflow."""
        # Create target
        target = await target_service.create(
            db_session,
            **TEST_TARGET_DATA
        )
        
        # Create stage
        stage = await stage_service.create(
            db_session,
            target_id=target.id,
            **TEST_STAGE_DATA
        )
        
        # Create plugin
        plugin = await plugin_service.create(
            db_session,
            stage_id=stage.id,
            **TEST_PLUGIN_DATA
        )
        
        # Create finding
        finding = await finding_service.create(
            db_session,
            plugin_id=plugin.id,
            **TEST_FINDING_DATA
        )
        
        # Update entities
        await target_service.update(db_session, target.id, status='completed')
        await stage_service.update(db_session, stage.id, status=StageStatus.COMPLETED)
        await plugin_service.update(db_session, plugin.id, status='completed')
        await finding_service.update(db_session, finding.id, status=FindingStatus.VERIFIED)
        
        # Verify final state
        updated_target = await target_service.get_by_id(db_session, target.id)
        updated_stage = await stage_service.get_by_id(db_session, stage.id)
        updated_plugin = await plugin_service.get_by_id(db_session, plugin.id)
        updated_finding = await finding_service.get_by_id(db_session, finding.id)
        
        assert updated_target.status == 'completed'
        assert updated_stage.status == StageStatus.COMPLETED
        assert updated_plugin.status == 'completed'
        assert updated_finding.status == FindingStatus.VERIFIED
        
        # Verify relationships
        assert updated_finding.plugin.id == updated_plugin.id
        assert updated_plugin.stage.id == updated_stage.id
        assert updated_stage.target.id == updated_target.id 