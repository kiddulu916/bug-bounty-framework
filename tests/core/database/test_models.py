"""
Tests for the database models.

This module contains comprehensive test cases for the database models,
verifying their structure, validation, relationships, and state transitions.
Tests are organized into categories: basic functionality, model validation,
relationships, state transitions, and constraints.

Test Categories:
- Basic Functionality: Model initialization, attribute access, and basic operations
- Model Validation: Field validation, constraints, and data integrity
- Relationships: Model relationships and cascading operations
- State Transitions: Status transitions and state management
- Constraints: Database constraints and unique requirements

Each test category focuses on specific aspects of the database models:
1. Basic Functionality: Core model features and attribute handling
2. Model Validation: Data validation and integrity checks
3. Relationships: Entity relationships and cascading behavior
4. State Transitions: Status changes and state management
5. Constraints: Database-level constraints and requirements
"""

import pytest
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from bbf.core.database.models import (
    Base, Finding, Stage, Plugin, Target,
    FindingStatus, FindingSeverity, StageStatus
)

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
    'status': FindingStatus.ACTIVE,
    'created_at': datetime.now()
}

TEST_STAGE_DATA = {
    'name': 'recon',
    'status': StageStatus.INITIALIZED,
    'started_at': datetime.now()
}

TEST_PLUGIN_DATA = {
    'name': 'subdomain_enum',
    'version': '1.0.0',
    'status': 'initialized',
    'started_at': datetime.now()
}

TEST_TARGET_DATA = {
    'url': 'https://example.com',
    'scope': 'example.com',
    'status': 'active',
    'created_at': datetime.now()
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
def test_target(db_session):
    """
    Create a test target for testing.
    
    This fixture provides a pre-configured target instance for use in tests.
    It ensures proper cleanup after each test.
    
    Returns:
        Target: A test target instance.
    """
    target = Target(**TEST_TARGET_DATA)
    db_session.add(target)
    db_session.commit()
    return target

@pytest.fixture
def test_stage(db_session, test_target):
    """
    Create a test stage for testing.
    
    This fixture provides a pre-configured stage instance linked to a test target.
    It ensures proper cleanup after each test.
    
    Returns:
        Stage: A test stage instance.
    """
    stage = Stage(target_id=test_target.id, **TEST_STAGE_DATA)
    db_session.add(stage)
    db_session.commit()
    return stage

@pytest.fixture
def test_plugin(db_session, test_stage):
    """
    Create a test plugin for testing.
    
    This fixture provides a pre-configured plugin instance linked to a test stage.
    It ensures proper cleanup after each test.
    
    Returns:
        Plugin: A test plugin instance.
    """
    plugin = Plugin(stage_id=test_stage.id, **TEST_PLUGIN_DATA)
    db_session.add(plugin)
    db_session.commit()
    return plugin

# Basic Functionality Tests
class TestBasicFunctionality:
    """Tests for basic model functionality."""
    
    def test_model_initialization(self, db_session):
        """Test model initialization and attribute access."""
        # Test Finding model
        finding = Finding(**TEST_FINDING_DATA)
        assert finding.type == TEST_FINDING_DATA['type']
        assert finding.title == TEST_FINDING_DATA['title']
        assert finding.severity == TEST_FINDING_DATA['severity']
        
        # Test Stage model
        stage = Stage(**TEST_STAGE_DATA)
        assert stage.name == TEST_STAGE_DATA['name']
        assert stage.status == TEST_STAGE_DATA['status']
        
        # Test Plugin model
        plugin = Plugin(**TEST_PLUGIN_DATA)
        assert plugin.name == TEST_PLUGIN_DATA['name']
        assert plugin.version == TEST_PLUGIN_DATA['version']
        
        # Test Target model
        target = Target(**TEST_TARGET_DATA)
        assert target.url == TEST_TARGET_DATA['url']
        assert target.scope == TEST_TARGET_DATA['scope']
    
    def test_timestamp_handling(self, db_session):
        """Test timestamp field handling."""
        # Test Finding timestamps
        finding = Finding(**TEST_FINDING_DATA)
        assert isinstance(finding.created_at, datetime)
        
        # Test Stage timestamps
        stage = Stage(**TEST_STAGE_DATA)
        assert isinstance(stage.started_at, datetime)
        
        # Test Plugin timestamps
        plugin = Plugin(**TEST_PLUGIN_DATA)
        assert isinstance(plugin.started_at, datetime)
        
        # Test Target timestamps
        target = Target(**TEST_TARGET_DATA)
        assert isinstance(target.created_at, datetime)

# Model Validation Tests
class TestModelValidation:
    """Tests for model validation and constraints."""
    
    def test_finding_validation(self, db_session, test_plugin):
        """Test Finding model validation."""
        # Test valid finding
        finding = Finding(plugin_id=test_plugin.id, **TEST_FINDING_DATA)
        db_session.add(finding)
        db_session.commit()
        assert finding.id is not None
        
        # Test missing required fields
        with pytest.raises(IntegrityError):
            invalid_finding = Finding(
                plugin_id=test_plugin.id,
                type='subdomain'
                # Missing required fields
            )
            db_session.add(invalid_finding)
            db_session.commit()
        
        # Test invalid severity
        with pytest.raises(ValueError):
            finding.severity = 'invalid_severity'
            db_session.commit()
        
        # Test invalid confidence
        with pytest.raises(ValueError):
            finding.confidence = 2.0  # Should be between 0 and 1
            db_session.commit()
    
    def test_stage_validation(self, db_session, test_target):
        """Test Stage model validation."""
        # Test valid stage
        stage = Stage(target_id=test_target.id, **TEST_STAGE_DATA)
        db_session.add(stage)
        db_session.commit()
        assert stage.id is not None
        
        # Test missing required fields
        with pytest.raises(IntegrityError):
            invalid_stage = Stage(
                name='recon'
                # Missing required fields
            )
            db_session.add(invalid_stage)
            db_session.commit()
        
        # Test invalid status
        with pytest.raises(ValueError):
            stage.status = 'invalid_status'
            db_session.commit()
    
    def test_plugin_validation(self, db_session, test_stage):
        """Test Plugin model validation."""
        # Test valid plugin
        plugin = Plugin(stage_id=test_stage.id, **TEST_PLUGIN_DATA)
        db_session.add(plugin)
        db_session.commit()
        assert plugin.id is not None
        
        # Test missing required fields
        with pytest.raises(IntegrityError):
            invalid_plugin = Plugin(
                name='subdomain_enum'
                # Missing required fields
            )
            db_session.add(invalid_plugin)
            db_session.commit()
    
    def test_target_validation(self, db_session):
        """Test Target model validation."""
        # Test valid target
        target = Target(**TEST_TARGET_DATA)
        db_session.add(target)
        db_session.commit()
        assert target.id is not None
        
        # Test missing required fields
        with pytest.raises(IntegrityError):
            invalid_target = Target(
                url='https://example.com'
                # Missing required fields
            )
            db_session.add(invalid_target)
            db_session.commit()
        
        # Test invalid URL
        with pytest.raises(ValueError):
            target.url = 'invalid-url'
            db_session.commit()

# Relationship Tests
class TestRelationships:
    """Tests for model relationships and cascading."""
    
    def test_finding_relationships(self, db_session, test_plugin):
        """Test Finding model relationships."""
        # Create finding
        finding = Finding(plugin_id=test_plugin.id, **TEST_FINDING_DATA)
        db_session.add(finding)
        db_session.commit()
        
        # Test plugin relationship
        assert finding.plugin == test_plugin
        assert finding.plugin.stage == test_plugin.stage
        assert finding.plugin.stage.target == test_plugin.stage.target
    
    def test_cascading_deletes(self, db_session, test_target, test_stage, test_plugin):
        """Test cascading delete operations."""
        # Create finding
        finding = Finding(plugin_id=test_plugin.id, **TEST_FINDING_DATA)
        db_session.add(finding)
        db_session.commit()
        
        # Delete target (should cascade)
        db_session.delete(test_target)
        db_session.commit()
        
        # Verify cascading deletes
        assert db_session.query(Stage).filter_by(id=test_stage.id).first() is None
        assert db_session.query(Plugin).filter_by(id=test_plugin.id).first() is None
        assert db_session.query(Finding).filter_by(id=finding.id).first() is None
    
    def test_relationship_constraints(self, db_session):
        """Test relationship constraints."""
        # Test non-existent foreign keys
        with pytest.raises(IntegrityError):
            finding = Finding(
                plugin_id=999999,  # Non-existent plugin
                **TEST_FINDING_DATA
            )
            db_session.add(finding)
            db_session.commit()
        
        with pytest.raises(IntegrityError):
            stage = Stage(
                target_id=999999,  # Non-existent target
                **TEST_STAGE_DATA
            )
            db_session.add(stage)
            db_session.commit()
        
        with pytest.raises(IntegrityError):
            plugin = Plugin(
                stage_id=999999,  # Non-existent stage
                **TEST_PLUGIN_DATA
            )
            db_session.add(plugin)
            db_session.commit()

# State Transition Tests
class TestStateTransitions:
    """Tests for model state transitions."""
    
    def test_finding_status_transitions(self, db_session, test_plugin):
        """Test Finding status transitions."""
        # Create finding
        finding = Finding(plugin_id=test_plugin.id, **TEST_FINDING_DATA)
        db_session.add(finding)
        db_session.commit()
        
        # Test valid transitions
        valid_transitions = [
            FindingStatus.VERIFIED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.DUPLICATE,
            FindingStatus.INVALID
        ]
        
        for status in valid_transitions:
            finding.status = status
            db_session.commit()
            assert finding.status == status
        
        # Test invalid transition
        with pytest.raises(ValueError):
            finding.status = 'invalid_status'
            db_session.commit()
    
    def test_stage_status_transitions(self, db_session, test_target):
        """Test Stage status transitions."""
        # Create stage
        stage = Stage(target_id=test_target.id, **TEST_STAGE_DATA)
        db_session.add(stage)
        db_session.commit()
        
        # Test valid transitions
        valid_transitions = [
            StageStatus.RUNNING,
            StageStatus.COMPLETED,
            StageStatus.FAILED,
            StageStatus.CANCELLED
        ]
        
        for status in valid_transitions:
            stage.status = status
            db_session.commit()
            assert stage.status == status
        
        # Test invalid transition
        with pytest.raises(ValueError):
            stage.status = 'invalid_status'
            db_session.commit()
    
    def test_plugin_status_transitions(self, db_session, test_stage):
        """Test Plugin status transitions."""
        # Create plugin
        plugin = Plugin(stage_id=test_stage.id, **TEST_PLUGIN_DATA)
        db_session.add(plugin)
        db_session.commit()
        
        # Test valid transitions
        valid_transitions = [
            'running',
            'completed',
            'failed',
            'cancelled'
        ]
        
        for status in valid_transitions:
            plugin.status = status
            db_session.commit()
            assert plugin.status == status
        
        # Test invalid transition
        with pytest.raises(ValueError):
            plugin.status = 'invalid_status'
            db_session.commit()

# Constraint Tests
class TestConstraints:
    """Tests for database constraints."""
    
    def test_unique_constraints(self, db_session, test_target):
        """Test unique constraints."""
        # Test unique stage name per target
        stage1 = Stage(target_id=test_target.id, **TEST_STAGE_DATA)
        db_session.add(stage1)
        db_session.commit()
        
        with pytest.raises(IntegrityError):
            stage2 = Stage(
                target_id=test_target.id,
                name=TEST_STAGE_DATA['name'],  # Same name
                status=StageStatus.INITIALIZED,
                started_at=datetime.now()
            )
            db_session.add(stage2)
            db_session.commit()
    
    def test_check_constraints(self, db_session, test_plugin):
        """Test check constraints."""
        # Test finding confidence range
        with pytest.raises(ValueError):
            finding = Finding(
                plugin_id=test_plugin.id,
                type='subdomain',
                title='Test Finding',
                description='Test description',
                severity=FindingSeverity.LOW,
                confidence=1.5,  # Invalid confidence
                status=FindingStatus.ACTIVE,
                created_at=datetime.now()
            )
            db_session.add(finding)
            db_session.commit()
        
        # Test stage progress range
        with pytest.raises(ValueError):
            stage = Stage(
                target_id=test_plugin.stage.target.id,
                name='test_stage',
                status=StageStatus.RUNNING,
                progress=1.5,  # Invalid progress
                started_at=datetime.now()
            )
            db_session.add(stage)
            db_session.commit()
    
    def test_not_null_constraints(self, db_session):
        """Test not-null constraints."""
        # Test finding required fields
        with pytest.raises(IntegrityError):
            finding = Finding(
                type='subdomain',
                # Missing required fields
                created_at=datetime.now()
            )
            db_session.add(finding)
            db_session.commit()
        
        # Test stage required fields
        with pytest.raises(IntegrityError):
            stage = Stage(
                name='recon',
                # Missing required fields
                started_at=datetime.now()
            )
            db_session.add(stage)
            db_session.commit() 