"""
Direct test of plugin discovery functionality.
"""
import sys
import os
import logging
from pathlib import Path
import tempfile
import shutil

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

def main():
    """Main function to test plugin discovery."""
    # Create a temporary directory for our test
    temp_dir = Path(tempfile.mkdtemp())
    logger.info(f"Created temporary directory: {temp_dir}")
    
    try:
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
        plugin_path = temp_dir / "test_plugin_d.py"
        with open(plugin_path, 'w') as f:
            f.write(plugin_code)
        logger.info(f"Created test plugin at: {plugin_path}")
        
        # Verify the file was created
        assert plugin_path.exists(), f"Plugin file was not created at {plugin_path}"
        logger.info(f"Plugin file exists: {plugin_path.exists()}")
        logger.info(f"Plugin file contents:\n{plugin_path.read_text()}")
        
        # Import the discover_plugins_in_directory function
        from bbf.utils.plugin_utils import discover_plugins_in_directory
        from bbf.core.plugin import BasePlugin
        
        # Try to discover plugins
        logger.info("\n" + "="*80)
        logger.info("Starting plugin discovery...")
        plugins = discover_plugins_in_directory(temp_dir, BasePlugin)
        logger.info("="*80 + "\n")
        
        # Print results
        logger.info(f"Discovered plugins: {plugins}")
        
        if not plugins:
            logger.error("No plugins were discovered!")
            logger.info("Directory contents:")
            for f in temp_dir.glob('*'):
                logger.info(f"- {f.name} (is_file: {f.is_file()}, size: {f.stat().st_size} bytes)")
                if f.is_file():
                    logger.info(f"  First 100 chars: {f.read_text()[:100]}...")
        else:
            for name, plugin_class in plugins.items():
                logger.info(f"Found plugin: {name}")
                logger.info(f"  Class: {plugin_class.__name__}")
                logger.info(f"  Module: {plugin_class.__module__}")
                logger.info(f"  File: {getattr(plugin_class, '__module__', '?')}")
                
                # Try to create an instance and call a method
                try:
                    instance = plugin_class({})
                    logger.info(f"  Successfully created instance: {instance}")
                    
                    import asyncio
                    result = asyncio.run(instance.execute("example.com"))
                    logger.info(f"  Execution result: {result}")
                except Exception as e:
                    logger.error(f"  Error creating/executing plugin: {e}", exc_info=True)
    
    finally:
        # Clean up
        logger.info("Cleaning up temporary directory...")
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.info("Done.")

if __name__ == "__main__":
    main()
