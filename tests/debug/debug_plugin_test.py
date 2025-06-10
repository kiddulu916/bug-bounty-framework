"""
Simple test script to debug plugin loading.
"""
import sys
import os
import importlib.util
import inspect
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

def create_test_plugin(directory: Path) -> Path:
    """Create a test plugin file."""
    plugin_code = '''
from typing import Dict, Any
from bbf.core.plugin import BasePlugin, plugin

@plugin
class TestPluginD(BasePlugin):
    """Test plugin D for unit testing."""
    name = "test_plugin_d"
    description = "Test plugin D"
    version = "1.0.0"

    async def run(self, *args, **kwargs) -> Dict[str, Any]:
        """Execute the plugin's main functionality."""
        target = args[0] if args else kwargs.get('target', '')
        return await self.execute(target, **kwargs)

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute the plugin's main functionality with target parameter."""
        return {'status': 'success', 'plugin': self.name, 'target': target}
'''
    
    plugin_file = directory / "test_plugin_d.py"
    plugin_file.write_text(plugin_code)
    return plugin_file

def load_plugin(file_path: Path):
    """Load a plugin from a file."""
    print(f"\n{'='*80}")
    print(f"Loading plugin from: {file_path}")
    
    # Verify file exists
    if not file_path.exists():
        print(f"Error: File does not exist: {file_path}")
        return None
    
    # Read file content
    try:
        content = file_path.read_text(encoding='utf-8')
        print("File content:")
        print("-" * 80)
        print(content[:500])  # Print first 500 chars
        print("-" * 80)
    except Exception as e:
        print(f"Error reading file: {e}")
        return None
    
    # Create a module name
    module_name = f"plugin_{file_path.stem}"
    
    try:
        # Load the module
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None:
            print("Error: Could not create module spec")
            return None
            
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        
        print(f"\nExecuting module: {module_name}")
        spec.loader.exec_module(module)
        print("Module executed successfully")
        
        # Find plugin classes
        print("\nSearching for plugin classes:")
        for name, obj in inspect.getmembers(module, inspect.isclass):
            print(f"Found class: {name}")
            print(f"  Module: {getattr(obj, '__module__', '?')}")
            
            # Check if it's a plugin class
            from bbf.core.plugin import BasePlugin
            if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                print(f"  Found plugin class: {name}")
                print(f"  Plugin name: {getattr(obj, 'name', 'N/A')}")
                return obj
        
        print("No plugin classes found")
        return None
        
    except Exception as e:
        print(f"Error loading plugin: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    """Main function."""
    import tempfile
    import shutil
    
    # Create a temporary directory
    temp_dir = Path(tempfile.mkdtemp())
    print(f"Created temporary directory: {temp_dir}")
    
    try:
        # Create a test plugin
        plugin_file = create_test_plugin(temp_dir)
        print(f"Created test plugin at: {plugin_file}")
        
        # Try to load the plugin
        plugin_class = load_plugin(plugin_file)
        
        if plugin_class:
            print("\nPlugin loaded successfully!")
            print(f"Plugin class: {plugin_class.__name__}")
            print(f"Plugin name: {getattr(plugin_class, 'name', 'N/A')}")
            
            # Try to create an instance and call a method
            try:
                print("\nCreating plugin instance...")
                instance = plugin_class({})
                
                import asyncio
                print("Calling execute method...")
                result = asyncio.run(instance.execute("example.com"))
                print(f"Execution result: {result}")
                
            except Exception as e:
                print(f"Error creating/calling plugin: {e}")
                import traceback
                traceback.print_exc()
        
    finally:
        # Clean up
        print(f"\nCleaning up temporary directory: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
