"""
Core framework module for the bug bounty framework.

This module provides the main BugBountyFramework class that orchestrates
the entire framework, including plugin management, execution, and security.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Union

from bbf.core.base import BaseService, BaseStage
from bbf.core.execution import ExecutionEngine
from bbf.core.validation import ValidationManager
from bbf.core.exceptions import FrameworkError, ValidationError

logger = logging.getLogger(__name__)

class BugBountyFramework(BaseService):
    """Main framework class that orchestrates the bug bounty framework."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Core components
        self._execution_engine: Optional[ExecutionEngine] = None
        self._validation_manager: Optional[ValidationManager] = None
        
        # Framework state
        self._stages: Dict[str, BaseStage] = {}
        self._targets: Dict[str, Dict[str, Any]] = {}
        self._findings: Dict[str, List[Dict[str, Any]]] = {}
        self._execution_history: List[Dict[str, Any]] = []
        
        # Framework settings
        self.max_concurrent_targets = self.config.get('max_concurrent_targets', 5)
        self.max_retries = self.config.get('max_retries', 3)
        self.execution_timeout = self.config.get('execution_timeout', 3600)  # 1 hour
        self.strict_mode = self.config.get('strict_mode', True)
    
    async def initialize(self) -> None:
        """Initialize the framework and its components."""
        if self._initialized:
            return
        
        logger.info("Initializing bug bounty framework")
        
        try:
            # Initialize execution engine
            self._execution_engine = ExecutionEngine({
                'max_workers': self.max_concurrent_targets,
                'max_concurrent_tasks': self.max_concurrent_targets,
                'execution_timeout': self.execution_timeout,
                'retry_count': self.max_retries
            })
            await self._execution_engine.initialize()
            
            # Initialize validation manager
            self._validation_manager = ValidationManager({
                'strict_mode': self.strict_mode
            })
            await self._validation_manager.initialize()
            
            # Register core schemas
            await self._register_core_schemas()
            
            self._initialized = True
            logger.info("Framework initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize framework: {str(e)}")
            await self.cleanup()
            raise FrameworkError(f"Initialization failed: {str(e)}")
    
    async def cleanup(self) -> None:
        """Clean up framework resources."""
        if not self._initialized:
            return
        
        logger.info("Cleaning up framework")
        
        try:
            # Clean up stages
            for stage in self._stages.values():
                await stage.cleanup()
            self._stages.clear()
            
            # Clean up execution engine
            if self._execution_engine:
                await self._execution_engine.cleanup()
                self._execution_engine = None
            
            # Clean up validation manager
            if self._validation_manager:
                await self._validation_manager.cleanup()
                self._validation_manager = None
            
            # Clear state
            self._targets.clear()
            self._findings.clear()
            self._execution_history.clear()
            
            self._initialized = False
            logger.info("Framework cleaned up successfully")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
            raise FrameworkError(f"Cleanup failed: {str(e)}")
    
    async def register_stage(self, stage: BaseStage) -> None:
        """Register a stage in the framework."""
        if not self._initialized:
            raise FrameworkError("Framework not initialized")
        
        if stage.name in self._stages:
            raise FrameworkError(f"Stage already registered: {stage.name}")
        
        try:
            await stage.initialize()
            self._stages[stage.name] = stage
            logger.info(f"Registered stage: {stage.name}")
            
        except Exception as e:
            raise FrameworkError(f"Failed to register stage: {str(e)}")
    
    async def add_target(self, target: Dict[str, Any]) -> str:
        """Add a target to the framework."""
        if not self._initialized:
            raise FrameworkError("Framework not initialized")
        
        try:
            # Validate target data
            await self._validation_manager.validate_schema('target', target)
            
            # Generate target ID
            target_id = f"target_{len(self._targets) + 1}"
            
            # Store target
            self._targets[target_id] = {
                **target,
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Added target: {target_id}")
            return target_id
            
        except ValidationError as e:
            raise FrameworkError(f"Invalid target data: {str(e)}")
        except Exception as e:
            raise FrameworkError(f"Failed to add target: {str(e)}")
    
    async def execute_stage(
        self,
        stage_name: str,
        target_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Execute a stage for specified targets."""
        if not self._initialized:
            raise FrameworkError("Framework not initialized")
        
        if stage_name not in self._stages:
            raise FrameworkError(f"Stage not found: {stage_name}")
        
        if not target_ids:
            target_ids = list(self._targets.keys())
        
        # Validate targets
        invalid_targets = [tid for tid in target_ids if tid not in self._targets]
        if invalid_targets:
            raise FrameworkError(f"Invalid targets: {invalid_targets}")
        
        stage = self._stages[stage_name]
        execution_id = f"exec_{len(self._execution_history) + 1}"
        
        try:
            # Update target statuses
            for target_id in target_ids:
                self._targets[target_id]['status'] = 'running'
                self._targets[target_id]['updated_at'] = datetime.utcnow().isoformat()
            
            # Execute stage
            start_time = datetime.utcnow()
            results = await self._execution_engine.execute_stage(
                stage,
                [self._targets[tid] for tid in target_ids]
            )
            end_time = datetime.utcnow()
            
            # Process results
            for target_id, result in zip(target_ids, results):
                if result.get('status') == 'success':
                    # Update findings
                    if 'findings' in result:
                        if target_id not in self._findings:
                            self._findings[target_id] = []
                        self._findings[target_id].extend(result['findings'])
                    
                    # Update target status
                    self._targets[target_id]['status'] = 'completed'
                else:
                    self._targets[target_id]['status'] = 'failed'
                
                self._targets[target_id]['updated_at'] = datetime.utcnow().isoformat()
            
            # Record execution
            execution_record = {
                'id': execution_id,
                'stage': stage_name,
                'targets': target_ids,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': (end_time - start_time).total_seconds(),
                'status': 'success' if all(r.get('status') == 'success' for r in results) else 'failed',
                'results': results
            }
            self._execution_history.append(execution_record)
            
            return execution_record
            
        except Exception as e:
            # Update target statuses on failure
            for target_id in target_ids:
                self._targets[target_id]['status'] = 'failed'
                self._targets[target_id]['updated_at'] = datetime.utcnow().isoformat()
            
            logger.error(f"Stage execution failed: {str(e)}")
            raise FrameworkError(f"Stage execution failed: {str(e)}")
    
    async def get_target_status(self, target_id: str) -> Dict[str, Any]:
        """Get the current status of a target."""
        if not self._initialized:
            raise FrameworkError("Framework not initialized")
        
        if target_id not in self._targets:
            raise FrameworkError(f"Target not found: {target_id}")
        
        return {
            'id': target_id,
            'status': self._targets[target_id]['status'],
            'findings': self._findings.get(target_id, []),
            'created_at': self._targets[target_id]['created_at'],
            'updated_at': self._targets[target_id]['updated_at']
        }
    
    async def get_execution_history(
        self,
        stage_name: Optional[str] = None,
        target_id: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Get execution history with optional filtering."""
        if not self._initialized:
            raise FrameworkError("Framework not initialized")
        
        # Filter executions
        filtered_history = self._execution_history
        
        if stage_name:
            filtered_history = [
                e for e in filtered_history
                if e['stage'] == stage_name
            ]
        
        if target_id:
            filtered_history = [
                e for e in filtered_history
                if target_id in e['targets']
            ]
        
        # Apply limit
        if limit is not None:
            filtered_history = filtered_history[-limit:]
        
        return filtered_history
    
    async def _register_core_schemas(self) -> None:
        """Register core validation schemas."""
        # Target schema
        target_schema = {
            'type': 'object',
            'required': ['url', 'scope'],
            'properties': {
                'url': {
                    'type': 'string',
                    'format': 'uri'
                },
                'scope': {
                    'type': 'array',
                    'items': {
                        'type': 'string'
                    }
                },
                'options': {
                    'type': 'object',
                    'additionalProperties': True
                }
            }
        }
        await self._validation_manager.register_schema('target', target_schema)
        
        # Finding schema
        finding_schema = {
            'type': 'object',
            'required': ['type', 'severity', 'description'],
            'properties': {
                'type': {
                    'type': 'string'
                },
                'severity': {
                    'type': 'string',
                    'enum': ['low', 'medium', 'high', 'critical']
                },
                'description': {
                    'type': 'string'
                },
                'evidence': {
                    'type': 'object',
                    'additionalProperties': True
                },
                'remediation': {
                    'type': 'string'
                }
            }
        }
        await self._validation_manager.register_schema('finding', finding_schema)
        
        # Plugin config schema
        plugin_config_schema = {
            'type': 'object',
            'required': ['name', 'version'],
            'properties': {
                'name': {
                    'type': 'string'
                },
                'version': {
                    'type': 'string'
                },
                'config': {
                    'type': 'object',
                    'additionalProperties': True
                },
                'dependencies': {
                    'type': 'array',
                    'items': {
                        'type': 'string'
                    }
                }
            }
        }
        await self._validation_manager.register_schema('plugin_config', plugin_config_schema)
    
    @property
    def registered_stages(self) -> Set[str]:
        """Get the set of registered stage names."""
        return set(self._stages.keys())
    
    @property
    def target_count(self) -> int:
        """Get the number of registered targets."""
        return len(self._targets)
    
    @property
    def execution_count(self) -> int:
        """Get the number of completed executions."""
        return len(self._execution_history)
