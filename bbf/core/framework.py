"""
Core framework for the Bug Bounty Framework.

This module contains the main BFFramework class which orchestrates
the execution of stages and plugins.
"""

import asyncio
import inspect
import logging
import os
from typing import Dict, List, Optional, Any, Type, Set, Callable, Coroutine
from pathlib import Path
import importlib
import pkgutil
from concurrent.futures import ThreadPoolExecutor, as_completed

from .plugin import BasePlugin, PluginRegistry
from .state import StateManager
from .exceptions import (
    BBFError, PluginError, PluginDependencyError, PluginExecutionError,
    StageError, StageExecutionError, ConfigurationError
)

logger = logging.getLogger(__name__)


class BFFramework:
    """
    Main framework class for the Bug Bounty Framework.
    
    This class is responsible for:
    - Managing the execution lifecycle of stages
    - Loading and managing plugins
    - Handling errors and recovery
    - Managing state across stages and plugins
    - Providing utilities for plugins
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Bug Bounty Framework.
        
        Args:
            config: Framework configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        self._setup_logging()
        
        # Initialize state manager
        state_dir = self.config.get('state_dir')
        self.state = StateManager(state_dir=state_dir)
        
        # Plugin registry
        self.plugin_registry = PluginRegistry()
        
        # Stages and plugins
        self.stages: Dict[str, 'Stage'] = {}
        self.plugins: Dict[str, BasePlugin] = {}
        
        # Thread pool for running blocking operations
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.config.get('max_workers', os.cpu_count() or 4)
        )
        
        # Event loop
        self.loop = asyncio.get_event_loop()
        
        # Framework state
        self.initialized = False
        self.running = False
        self.current_stage: Optional[str] = None
    
    def _setup_logging(self) -> None:
        """Set up logging configuration."""
        log_level = self.config.get('log_level', 'INFO').upper()
        log_file = self.config.get('log_file')
        
        # Configure root logger
        logging.basicConfig(
            level=getattr(logging, log_level, logging.INFO),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[]
        )
        
        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, log_level, logging.INFO))
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        logging.getLogger('').addHandler(console_handler)
        
        # Add file handler if log file is specified
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(getattr(logging, log_level, logging.INFO))
            file_handler.setFormatter(formatter)
            logging.getLogger('').addHandler(file_handler)
    
    async def initialize(self) -> None:
        """
        Initialize the framework.
        
        This method should be called before running any stages.
        """
        if self.initialized:
            logger.warning("Framework already initialized")
            return
        
        logger.info("Initializing Bug Bounty Framework")
        
        try:
            # Load plugins
            await self._load_plugins()
            
            # Initialize stages
            self._initialize_stages()
            
            self.initialized = True
            logger.info("Framework initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize framework: {e}", exc_info=True)
            raise BBFError(f"Framework initialization failed: {e}") from e
    
    async def _load_plugins(self) -> None:
        """Load plugins from configured directories."""
        plugin_dirs = self.config.get('plugin_dirs', [])
        if not plugin_dirs:
            logger.warning("No plugin directories configured")
            return
        
        logger.info(f"Loading plugins from directories: {plugin_dirs}")
        
        for plugin_dir in plugin_dirs:
            if not os.path.isdir(plugin_dir):
                logger.warning(f"Plugin directory not found: {plugin_dir}")
                continue
                
            # Import all Python modules in the plugin directory
            for finder, name, _ in pkgutil.iter_modules([plugin_dir]):
                try:
                    module = importlib.import_module(f"{plugin_dir}.{name}")
                    logger.debug(f"Imported plugin module: {module.__name__}")
                except Exception as e:
                    logger.error(f"Failed to import plugin module {name}: {e}", exc_info=True)
    
    def _initialize_stages(self) -> None:
        """Initialize the framework stages."""
        from ..stages import (
            ReconStage, ScanStage, TestStage, ReportStage
        )
        
        # Create default stages if none are defined
        if not self.stages:
            self.stages = {
                'recon': ReconStage(self),
                'scan': ScanStage(self),
                'test': TestStage(self),
                'report': ReportStage(self),
            }
        
        logger.info(f"Initialized stages: {list(self.stages.keys())}")
    
    async def run_stage(self, stage_name: str, **kwargs) -> Dict[str, Any]:
        """
        Run a specific stage.
        
        Args:
            stage_name: Name of the stage to run
            **kwargs: Additional arguments to pass to the stage
            
        Returns:
            Dictionary containing the results of the stage
            
        Raises:
            StageExecutionError: If the stage fails to execute
        """
        if not self.initialized:
            await self.initialize()
        
        if stage_name not in self.stages:
            raise StageExecutionError(f"Unknown stage: {stage_name}")
        
        self.current_stage = stage_name
        stage = self.stages[stage_name]
        
        logger.info(f"Starting stage: {stage_name}")
        
        try:
            # Run the stage
            results = await stage.run(**kwargs)
            
            # Save state after successful stage execution
            self.state.save_state()
            
            logger.info(f"Completed stage: {stage_name}")
            return results
            
        except Exception as e:
            logger.error(f"Stage {stage_name} failed: {e}", exc_info=True)
            raise StageExecutionError(f"Stage {stage_name} failed: {e}") from e
            
        finally:
            self.current_stage = None
    
    async def run_all_stages(self, **kwargs) -> Dict[str, Any]:
        """
        Run all stages in sequence.
        
        Args:
            **kwargs: Additional arguments to pass to each stage
            
        Returns:
            Dictionary containing the results from all stages
        """
        if not self.initialized:
            await self.initialize()
        
        results = {}
        
        for stage_name in self.stages:
            try:
                stage_results = await self.run_stage(stage_name, **kwargs)
                results[stage_name] = stage_results
                
                # Pass results to next stage if needed
                kwargs['previous_results'] = results
                
            except Exception as e:
                logger.error(f"Pipeline failed at stage {stage_name}: {e}", exc_info=True)
                raise StageExecutionError(f"Pipeline failed at stage {stage_name}") from e
        
        return results
    
    def get_plugin(self, plugin_name: str) -> BasePlugin:
        """
        Get a plugin instance by name.
        
        Args:
            plugin_name: Name of the plugin to retrieve
            
        Returns:
            The plugin instance
            
        Raises:
            PluginError: If the plugin is not found
        """
        if plugin_name not in self.plugins:
            try:
                plugin_class = self.plugin_registry.get_plugin_class(plugin_name)
                self.plugins[plugin_name] = plugin_class()
            except Exception as e:
                raise PluginError(f"Failed to initialize plugin {plugin_name}: {e}") from e
                
        return self.plugins[plugin_name]
    
    async def run_in_thread(self, func: Callable, *args, **kwargs) -> Any:
        """
        Run a blocking function in a thread pool.
        
        Args:
            func: The function to run
            *args: Positional arguments to pass to the function
            **kwargs: Keyword arguments to pass to the function
            
        Returns:
            The result of the function
        """
        return await self.loop.run_in_executor(
            self.thread_pool,
            lambda: func(*args, **kwargs)
        )
    
    async def run_plugins_parallel(
        self,
        plugin_names: List[str],
        *args,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Run multiple plugins in parallel.
        
        Args:
            plugin_names: List of plugin names to run
            *args: Positional arguments to pass to each plugin
            **kwargs: Keyword arguments to pass to each plugin
            
        Returns:
            Dictionary mapping plugin names to their results
        """
        tasks = []
        
        for plugin_name in plugin_names:
            plugin = self.get_plugin(plugin_name)
            task = asyncio.create_task(self._run_plugin_safely(plugin, *args, **kwargs))
            tasks.append((plugin_name, task))
        
        # Wait for all tasks to complete
        results = {}
        for plugin_name, task in tasks:
            try:
                results[plugin_name] = await task
            except Exception as e:
                logger.error(f"Plugin {plugin_name} failed: {e}", exc_info=True)
                results[plugin_name] = {"error": str(e), "success": False}
        
        return results
    
    async def _run_plugin_safely(
        self,
        plugin: BasePlugin,
        *args,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Run a plugin with error handling and state management.
        
        Args:
            plugin: The plugin instance to run
            *args: Positional arguments to pass to the plugin
            **kwargs: Keyword arguments to pass to the plugin
            
        Returns:
            Dictionary containing the plugin's results
        """
        plugin_name = plugin.name
        logger.info(f"Starting plugin: {plugin_name}")
        
        try:
            # Load plugin state
            plugin_state = self.state.get_plugin_state(plugin_name)
            plugin.state = plugin_state
            
            # Run plugin setup
            await plugin.setup()
            
            # Run the plugin
            results = await plugin.run(*args, **kwargs)
            
            # Run plugin cleanup
            await plugin.cleanup()
            
            # Save plugin state
            self.state.set_plugin_state(plugin_name, plugin.state)
            
            logger.info(f"Completed plugin: {plugin_name}")
            return {
                "success": True,
                "results": results,
                "state": plugin.state
            }
            
        except Exception as e:
            logger.error(f"Plugin {plugin_name} failed: {e}", exc_info=True)
            
            # Save error state
            self.state.set_plugin_state(plugin_name, {
                **plugin.state,
                "error": str(e),
                "success": False,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            raise PluginExecutionError(f"Plugin {plugin_name} failed: {e}") from e
    
    async def close(self) -> None:
        """
        Clean up resources used by the framework.
        """
        logger.info("Shutting down Bug Bounty Framework")
        
        # Close all plugins
        for plugin in self.plugins.values():
            if hasattr(plugin, 'close') and callable(plugin.close):
                try:
                    if inspect.iscoroutinefunction(plugin.close):
                        await plugin.close()
                    else:
                        await self.run_in_thread(plugin.close)
                except Exception as e:
                    logger.error(f"Error closing plugin {plugin.name}: {e}", exc_info=True)
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)
        
        # Save final state
        self.state.save_state()
        
        self.running = False
        logger.info("Bug Bounty Framework shutdown complete")
    
    def __del__(self) -> None:
        """Ensure resources are cleaned up when the framework is garbage collected."""
        if hasattr(self, 'running') and self.running:
            logger.warning("Framework was not properly closed before destruction")
            if self.loop.is_running():
                self.loop.create_task(self.close())
            else:
                self.loop.run_until_complete(self.close())
    
    def __enter__(self):
        """Context manager entry."""
        if not self.loop.is_running():
            self.loop.run_until_complete(self.initialize())
        else:
            asyncio.create_task(self.initialize())
        self.running = True
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self.loop.is_running():
            self.loop.create_task(self.close())
        else:
            self.loop.run_until_complete(self.close())


class Stage:
    """
    Base class for all stages in the Bug Bounty Framework.
    
    Stages are the main building blocks of the framework's execution flow.
    Each stage is responsible for a specific phase of the testing process.
    """
    
    def __init__(self, framework: BFFramework):
        """
        Initialize the stage.
        
        Args:
            framework: Reference to the parent framework instance
        """
        self.framework = framework
        self.name = self.__class__.__name__.replace('Stage', '').lower()
        self.log = logging.getLogger(f"bbf.stage.{self.name}")
    
    async def run(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the stage.
        
        This method should be overridden by subclasses to implement
        the specific functionality of the stage.
        
        Args:
            **kwargs: Additional arguments specific to the stage
            
        Returns:
            Dictionary containing the results of the stage
        """
        raise NotImplementedError("Stage subclasses must implement the run() method")
    
    async def get_plugins(self) -> List[str]:
        """
        Get the list of plugins to run in this stage.
        
        Returns:
            List of plugin names to run
        """
        return []
    
    async def run_plugins(self, **kwargs) -> Dict[str, Any]:
        """
        Run all plugins configured for this stage.
        
        Args:
            **kwargs: Additional arguments to pass to the plugins
            
        Returns:
            Dictionary mapping plugin names to their results
        """
        plugin_names = await self.get_plugins()
        if not plugin_names:
            self.log.warning(f"No plugins configured for stage {self.name}")
            return {}
            
        self.log.info(f"Running {len(plugin_names)} plugins in stage {self.name}")
        return await self.framework.run_plugins_parallel(plugin_names, **kwargs)
