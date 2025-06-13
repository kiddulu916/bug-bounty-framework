"""
Stage module for the bug bounty framework.

This module provides the Stage class that represents a stage in the framework's
execution pipeline, such as reconnaissance, scanning, or testing.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Union

from bbf.core.base import BaseService, BaseStage
from bbf.core.exceptions import StageError

logger = logging.getLogger(__name__)

class Stage(BaseStage):
    """Base class for all stages in the framework."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Stage state
        self._plugins: Dict[str, Any] = {}
        self._targets: Dict[str, Dict[str, Any]] = {}
        self._findings: Dict[str, List[Dict[str, Any]]] = {}
        self._execution_history: List[Dict[str, Any]] = []
        
        # Stage settings
        self.max_concurrent_plugins = self.config.get('max_concurrent_plugins', 3)
        self.plugin_timeout = self.config.get('plugin_timeout', 1800)  # 30 minutes
        self.retry_count = self.config.get('retry_count', 3)
        self.retry_delay = self.config.get('retry_delay', 60)  # 1 minute
    
    async def initialize(self) -> None:
        """Initialize the stage."""
        if self._initialized:
            return
        
        logger.info(f"Initializing stage: {self.name}")
        
        try:
            # Initialize plugins
            await self._initialize_plugins()
            
            self._initialized = True
            logger.info(f"Stage {self.name} initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize stage {self.name}: {str(e)}")
            await self.cleanup()
            raise StageError(f"Initialization failed: {str(e)}")
    
    async def cleanup(self) -> None:
        """Clean up stage resources."""
        if not self._initialized:
            return
        
        logger.info(f"Cleaning up stage: {self.name}")
        
        try:
            # Clean up plugins
            for plugin in self._plugins.values():
                await plugin.cleanup()
            self._plugins.clear()
            
            # Clear state
            self._targets.clear()
            self._findings.clear()
            self._execution_history.clear()
            
            self._initialized = False
            logger.info(f"Stage {self.name} cleaned up successfully")
            
        except Exception as e:
            logger.error(f"Error cleaning up stage {self.name}: {str(e)}")
            raise StageError(f"Cleanup failed: {str(e)}")
    
    async def register_plugin(self, plugin: Any) -> None:
        """Register a plugin in the stage."""
        if not self._initialized:
            raise StageError("Stage not initialized")
        
        if plugin.name in self._plugins:
            raise StageError(f"Plugin already registered: {plugin.name}")
        
        try:
            await plugin.initialize()
            self._plugins[plugin.name] = plugin
            logger.info(f"Registered plugin in stage {self.name}: {plugin.name}")
            
        except Exception as e:
            raise StageError(f"Failed to register plugin: {str(e)}")
    
    async def add_target(self, target: Dict[str, Any]) -> str:
        """Add a target to the stage."""
        if not self._initialized:
            raise StageError("Stage not initialized")
        
        try:
            # Generate target ID
            target_id = f"target_{len(self._targets) + 1}"
            
            # Store target
            self._targets[target_id] = {
                **target,
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Added target to stage {self.name}: {target_id}")
            return target_id
            
        except Exception as e:
            raise StageError(f"Failed to add target: {str(e)}")
    
    async def execute(
        self,
        target_ids: Optional[List[str]] = None,
        plugin_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Execute the stage for specified targets and plugins."""
        if not self._initialized:
            raise StageError("Stage not initialized")
        
        if not target_ids:
            target_ids = list(self._targets.keys())
        
        if not plugin_names:
            plugin_names = list(self._plugins.keys())
        
        # Validate targets and plugins
        invalid_targets = [tid for tid in target_ids if tid not in self._targets]
        if invalid_targets:
            raise StageError(f"Invalid targets: {invalid_targets}")
        
        invalid_plugins = [p for p in plugin_names if p not in self._plugins]
        if invalid_plugins:
            raise StageError(f"Invalid plugins: {invalid_plugins}")
        
        execution_id = f"exec_{len(self._execution_history) + 1}"
        
        try:
            # Update target statuses
            for target_id in target_ids:
                self._targets[target_id]['status'] = 'running'
                self._targets[target_id]['updated_at'] = datetime.utcnow().isoformat()
            
            # Execute plugins
            start_time = datetime.utcnow()
            results = await self._execute_plugins(
                plugin_names,
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
                'stage': self.name,
                'plugins': plugin_names,
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
            raise StageError(f"Stage execution failed: {str(e)}")
    
    async def get_target_status(self, target_id: str) -> Dict[str, Any]:
        """Get the current status of a target."""
        if not self._initialized:
            raise StageError("Stage not initialized")
        
        if target_id not in self._targets:
            raise StageError(f"Target not found: {target_id}")
        
        return {
            'id': target_id,
            'status': self._targets[target_id]['status'],
            'findings': self._findings.get(target_id, []),
            'created_at': self._targets[target_id]['created_at'],
            'updated_at': self._targets[target_id]['updated_at']
        }
    
    async def get_execution_history(
        self,
        plugin_name: Optional[str] = None,
        target_id: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Get execution history with optional filtering."""
        if not self._initialized:
            raise StageError("Stage not initialized")
        
        # Filter executions
        filtered_history = self._execution_history
        
        if plugin_name:
            filtered_history = [
                e for e in filtered_history
                if plugin_name in e['plugins']
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
    
    async def _initialize_plugins(self) -> None:
        """Initialize stage plugins."""
        # This method should be overridden by subclasses to initialize
        # stage-specific plugins
        pass
    
    async def _execute_plugins(
        self,
        plugin_names: List[str],
        targets: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Execute plugins for targets."""
        results = []
        
        # Create execution tasks
        tasks = []
        for target in targets:
            target_tasks = []
            for plugin_name in plugin_names:
                plugin = self._plugins[plugin_name]
                task = asyncio.create_task(
                    self._execute_plugin_with_retry(plugin, target)
                )
                target_tasks.append(task)
            tasks.append(asyncio.gather(*target_tasks))
        
        # Execute tasks with concurrency limit
        semaphore = asyncio.Semaphore(self.max_concurrent_plugins)
        async def execute_with_semaphore(task):
            async with semaphore:
                return await task
        
        # Wait for all tasks to complete
        for target_tasks in tasks:
            try:
                target_results = await asyncio.gather(
                    *[execute_with_semaphore(task) for task in target_tasks],
                    return_exceptions=True
                )
                
                # Process results
                target_status = 'success'
                target_findings = []
                
                for result in target_results:
                    if isinstance(result, Exception):
                        target_status = 'failed'
                        logger.error(f"Plugin execution failed: {str(result)}")
                    else:
                        if result.get('status') == 'failed':
                            target_status = 'failed'
                        if 'findings' in result:
                            target_findings.extend(result['findings'])
                
                results.append({
                    'status': target_status,
                    'findings': target_findings
                })
                
            except Exception as e:
                logger.error(f"Target execution failed: {str(e)}")
                results.append({
                    'status': 'failed',
                    'error': str(e)
                })
        
        return results
    
    async def _execute_plugin_with_retry(
        self,
        plugin: Any,
        target: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a plugin with retry logic."""
        for attempt in range(self.retry_count):
            try:
                # Execute plugin with timeout
                async with asyncio.timeout(self.plugin_timeout):
                    result = await plugin.execute(target)
                    return {
                        'status': 'success',
                        'plugin': plugin.name,
                        **result
                    }
                
            except asyncio.TimeoutError:
                logger.warning(
                    f"Plugin {plugin.name} timed out after {self.plugin_timeout}s"
                )
                if attempt < self.retry_count - 1:
                    await asyncio.sleep(self.retry_delay)
                    continue
                return {
                    'status': 'failed',
                    'plugin': plugin.name,
                    'error': 'Execution timed out'
                }
                
            except Exception as e:
                logger.error(f"Plugin {plugin.name} failed: {str(e)}")
                if attempt < self.retry_count - 1:
                    await asyncio.sleep(self.retry_delay)
                    continue
                return {
                    'status': 'failed',
                    'plugin': plugin.name,
                    'error': str(e)
                }
    
    @property
    def registered_plugins(self) -> Set[str]:
        """Get the set of registered plugin names."""
        return set(self._plugins.keys())
    
    @property
    def target_count(self) -> int:
        """Get the number of registered targets."""
        return len(self._targets)
    
    @property
    def execution_count(self) -> int:
        """Get the number of completed executions."""
        return len(self._execution_history) 