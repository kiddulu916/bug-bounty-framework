"""
Simple test to verify plugin loading works.
"""
import sys
import os
import importlib.util
import inspect
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

# Import the BasePlugin
try:
    from bbf.core.plugin import BasePlugin, plugin
    print("Successfully imported BasePlugin and plugin decorator")
except ImportError as e:
    print(f"Error importing BasePlugin: {e}")
    sys.exit(1)

# Create a simple plugin in memory
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

# Save to a temporary file
import tempfile
with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
    f.write(plugin_code)
    temp_path = f.name

print(f"Created temporary plugin file at: {temp_path}")

# Try to load the plugin
print("\nAttempting to load plugin...")

# Load the module
module_name = Path(temp_path).stem
spec = importlib.util.spec_from_file_location(module_name, temp_path)
module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module
spec.loader.exec_module(module)

# Find the plugin class
plugin_class = None
for name, obj in inspect.getmembers(module):
    if inspect.isclass(obj) and hasattr(obj, 'name') and obj.name == 'test_plugin_d':
        plugin_class = obj
        break

if plugin_class:
    print(f"\nSuccessfully loaded plugin class: {plugin_class.__name__}")
    print(f"Plugin name: {plugin_class.name}")
    print(f"Plugin description: {plugin_class.description}")
    print(f"Plugin version: {plugin_class.version}")
    
    # Try to create an instance
    try:
        instance = plugin_class({})
        print("\nSuccessfully created plugin instance")
        print(f"Instance name: {instance.name}")
    except Exception as e:
        print(f"\nError creating plugin instance: {e}")
else:
    print("\nFailed to find plugin class in the module")
    print("Available members in module:")
    for name, obj in inspect.getmembers(module):
        print(f"- {name}: {type(obj)}")

# Clean up
os.unlink(temp_path)
print(f"\nCleaned up temporary file: {temp_path}")
