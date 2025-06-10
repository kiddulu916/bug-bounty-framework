"""
Standalone script to debug plugin discovery in the Bug Bounty Framework.
"""
import sys
import os
import logging
import tempfile
import importlib.util
import inspect
import traceback
from pathlib import Path
from typing import Dict, Any, Type, List, Optional, TypeVar

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Add some color to the logs
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[31;1m', # Bright Red
        'RESET': '\033[0m'      # Reset
    }
    
    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
            record.msg = f"{self.COLORS.get(levelname, '')}{record.msg}{self.COLORS['RESET']}"
        return super().format(record)

# Apply colored formatter to the root logger
for handler in logging.root.handlers:
    handler.setFormatter(ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s'))

T = TypeVar('T')

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

def create_test_plugin(directory: Path) -> Path:
    """Create a test plugin file in the specified directory."""
    plugin_code = '''
from typing import Dict, Any
from bbf.core.plugin import BasePlugin, plugin

@plugin
class TestPluginD(BasePlugin):
    name = "test_plugin_d"
    description = "Test plugin D"
    version = "1.0.0"

    async def run(self, *args, **kwargs) -> Dict[str, Any]:
        """Execute the plugin's main functionality."""
        target = args[0] if args else kwargs.get('target', '')
        return await self.execute(target, **kwargs)

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute the plugin's main functionality with target parameter."""
        return {'status': 'success', 'plugin': self.name}
'''
    
    plugin_file = directory / "test_plugin_d.py"
    plugin_file.write_text(plugin_code)
    
    # Verify the file was created and has content
    assert plugin_file.exists(), f"Plugin file was not created at {plugin_file}"
    file_content = plugin_file.read_text()
    assert file_content.strip(), f"Plugin file is empty: {plugin_file}"
    
    logger.info(f"Created test plugin at: {plugin_file}")
    logger.debug(f"Plugin file contents:\n{file_content}")
    
    return plugin_file

def load_plugin_from_file(file_path: Path, base_class: Type[T]) -> Optional[Type[T]]:
    """
    Load a plugin class from a file.
    
    Args:
        file_path: Path to the Python file containing the plugin.
        base_class: The base class that the plugin must inherit from.
        
    Returns:
        The plugin class if found, None otherwise.
    """
    logger.info(f"\n{'='*80}")
    logger.info(f"Loading plugin from file: {file_path}")
    
    if not file_path.exists():
        logger.error(f"File does not exist: {file_path}")
        return None
        
    if not file_path.is_file():
        logger.error(f"Path is not a file: {file_path}")
        return None
    
    # Read the file content for debugging
    try:
        content = file_path.read_text(encoding='utf-8')
        logger.debug(f"File content (first 200 chars): {content[:200]}...")
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return None
    
    # Generate a unique module name
    module_name = f"plugin_{file_path.stem}"
    
    try:
        # Load the module from the file
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            logger.error(f"Could not load spec for {file_path}")
            return None
            
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        
        # Execute the module
        spec.loader.exec_module(module)
        logger.info(f"Successfully loaded module: {module_name}")
        
        # Find all classes in the module that are subclasses of base_class
        # but not the base_class itself
        plugin_classes = []
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, base_class) and 
                obj != base_class and 
                obj.__module__ == module_name):
                logger.info(f"Found plugin class: {obj.__name__}")
                plugin_classes.append(obj)
        
        if not plugin_classes:
            logger.warning(f"No plugin classes found in {file_path}")
            return None
            
        if len(plugin_classes) > 1:
            logger.warning(f"Multiple plugin classes found in {file_path}, "
                         f"using the first one: {plugin_classes[0].__name__}")
            
        return plugin_classes[0]
        
    except Exception as e:
        logger.error(f"Error loading plugin from {file_path}: {e}")
        logger.debug(traceback.format_exc())
        return None

def test_plugin_discovery():
    """Test plugin discovery in a temporary directory."""
    # Create a temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir = Path(temp_dir)
        logger.info(f"\n{'='*80}")
        logger.info(f"Created temporary directory: {temp_dir}")
        
        # Create a test plugin
        plugin_file = create_test_plugin(temp_dir)
        
        # List files in the directory
        logger.info("\nFiles in directory:")
        for f in temp_dir.glob('*'):
            logger.info(f"- {f.name} (size: {f.stat().st_size} bytes)")
        
        # First, try loading the plugin directly
        logger.info("\n=== Testing direct plugin loading ===")
        from bbf.core.plugin import BasePlugin
        
        plugin_class = load_plugin_from_file(plugin_file, BasePlugin)
        if plugin_class:
            logger.info(f"Successfully loaded plugin class: {plugin_class.__name__}")
            logger.info(f"Plugin name: {getattr(plugin_class, 'name', 'N/A')}")
            
            # Try to create an instance and call a method
            try:
                instance = plugin_class({})
                logger.info("Successfully created plugin instance")
                
                import asyncio
                logger.info("Executing plugin...")
                result = asyncio.run(instance.execute("example.com"))
                logger.info(f"Execution result: {result}")
                
                # Also test the run method
                logger.info("Testing run method...")
                run_result = asyncio.run(instance.run("example.com"))
                logger.info(f"Run method result: {run_result}")
                
            except Exception as e:
                logger.error(f"Error creating/executing plugin: {e}")
                logger.debug(traceback.format_exc())
        else:
            logger.error("Failed to load plugin class")
        
        # Now test the discover_plugins_in_directory function
        logger.info("\n=== Testing discover_plugins_in_directory ===")
        from bbf.utils.plugin_utils import discover_plugins_in_directory
        
        logger.info("Discovering plugins...")
        plugins = discover_plugins_in_directory(temp_dir, BasePlugin)
        
        # Print results
        logger.info(f"\nDiscovered {len(plugins)} plugins:")
        for name, plugin_class in plugins.items():
            logger.info(f"- {name}: {plugin_class.__module__}.{plugin_class.__name__}")
            
            # Try to create an instance and call a method
            try:
                instance = plugin_class({})
                logger.info(f"  Successfully created instance")
                
                import asyncio
                logger.info("  Executing plugin...")
                result = asyncio.run(instance.execute("example.com"))
                logger.info(f"  Execution result: {result}")
                
                # Also test the run method
                logger.info("  Testing run method...")
                run_result = asyncio.run(instance.run("example.com"))
                logger.info(f"  Run method result: {run_result}")
                
            except Exception as e:
                logger.error(f"  Error creating/executing plugin: {e}")
                logger.debug(traceback.format_exc())
        
        assert "test_plugin_d" in plugins, f"Plugin 'test_plugin_d' not found in {plugins}"
        
    logger.info("\nTemporary directory cleaned up")

if __name__ == "__main__":
    logger.info("Starting plugin discovery test...")
    test_plugin_discovery()
    logger.info("Test completed")
