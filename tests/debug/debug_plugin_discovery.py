"""
Debug script for plugin discovery issues.
"""
import sys
import os
import logging
from pathlib import Path
from typing import Dict, Any, Type, TypeVar, Optional
import importlib.util
import inspect

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

# Import the BasePlugin
from bbf.core.plugin import BasePlugin

# Type variable for plugin classes
T = TypeVar('T', bound=BasePlugin)

def load_plugin_from_file(file_path: str, base_class: Type[T]) -> Optional[Type[T]]:
    """Debug version of load_plugin_from_file with more logging."""
    file_path = Path(file_path)
    logger.info(f"Loading plugin from file: {file_path}")
    
    if not file_path.exists() or not file_path.is_file():
        logger.error(f"File not found: {file_path}")
        return None
    
    try:
        # Create a module name from the file path
        module_name = file_path.stem
        logger.debug(f"Module name: {module_name}")
        
        # Load the module
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None:
            logger.error(f"Could not load spec for {file_path}")
            return None
        if spec.loader is None:
            logger.error(f"No loader found for {file_path}")
            return None
        
        module = importlib.util.module_from_spec(spec)
        logger.debug(f"Created module: {module}")
        
        # Add the module to sys.modules
        sys.modules[module_name] = module
        
        # Execute the module
        spec.loader.exec_module(module)
        logger.debug(f"Executed module: {module}")
        
        # Find the plugin class in the module
        logger.debug("Searching for plugin classes...")
        for name, obj in inspect.getmembers(module):
            if not inspect.isclass(obj):
                continue
                
            logger.debug(f"Found class: {name}")
            logger.debug(f"Class details: {obj}")
            
            try:
                is_subclass = issubclass(obj, base_class)
                is_base = obj is base_class
                is_abstract = inspect.isabstract(obj)
                
                logger.debug(f"  is_subclass: {is_subclass}")
                logger.debug(f"  is_base: {is_base}")
                logger.debug(f"  is_abstract: {is_abstract}")
                
                if is_subclass and not is_base and not is_abstract:
                    logger.info(f"Found valid plugin class: {name}")
                    return obj
                    
            except Exception as e:
                logger.warning(f"Error checking class {name}: {e}")
        
        logger.warning(f"No valid plugin classes found in {file_path}")
        return None
        
    except Exception as e:
        logger.exception(f"Error loading plugin from {file_path}")
        return None

def main():
    """Main function to test plugin loading."""
    # Create a temporary plugin file
    import tempfile
    import textwrap
    
    # Create a temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        logger.info(f"Created temporary directory: {temp_dir}")
        
        # Create a test plugin file
        plugin_code = """
from typing import Dict, Any
from bbf.core.plugin import BasePlugin, plugin

@plugin
class TestPluginD(BasePlugin):
    name = "test_plugin_d"
    description = "Test plugin D"
    version = "1.0.0"
    
    async def run(self, *args, **kwargs) -> Dict[str, Any]:
        target = args[0] if args else kwargs.get("target", "")
        return await self.execute(target, **kwargs)
        
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        return {"status": "success", "plugin": self.name}
"""
        
        plugin_path = Path(temp_dir) / "test_plugin_d.py"
        with open(plugin_path, 'w') as f:
            f.write(textwrap.dedent(plugin_code))
        
        logger.info(f"Created test plugin at: {plugin_path}")
        
        # Try to load the plugin
        plugin_class = load_plugin_from_file(plugin_path, BasePlugin)
        
        if plugin_class:
            logger.info(f"Successfully loaded plugin: {plugin_class.__name__}")
            logger.info(f"Plugin name: {getattr(plugin_class, 'name', 'N/A')}")
        else:
            logger.error("Failed to load plugin")

if __name__ == "__main__":
    main()
