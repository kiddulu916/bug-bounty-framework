"""
Test script to debug plugin loading.
"""
import sys
import os
import inspect
import tempfile
import shutil
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

def create_test_plugin(directory):
    """Create a test plugin file."""
    plugin_code = """
from typing import Dict, Any
from bbf.core.plugin import BasePlugin, plugin

@plugin
class TestPluginD(BasePlugin):
    name = "test_plugin_d"
    description = "Test plugin D"
    version = "1.0.0"

    async def run(self, *args, **kwargs):
        target = args[0] if args else kwargs.get('target', '')
        return await self.execute(target, **kwargs)

    async def execute(self, target: str, **kwargs):
        return {'status': 'success', 'plugin': self.name, 'target': target}
"""
    plugin_file = directory / "test_plugin_d.py"
    plugin_file.write_text(plugin_code)
    return plugin_file

def load_plugin(file_path):
    """Load a plugin from a file with detailed logging."""
    print(f"\n{'='*80}")
    print(f"[DEBUG] Loading plugin from: {file_path}")
    print(f"[DEBUG] Current working directory: {os.getcwd()}")
    print(f"[DEBUG] Python path: {sys.path}")
    
    if not file_path.exists():
        print(f"[ERROR] File does not exist: {file_path}")
        print(f"[DEBUG] Current directory contents: {os.listdir(file_path.parent)}")
        return None
    
    try:
        content = file_path.read_text(encoding='utf-8')
        print("[DEBUG] File content:")
        print("-" * 80)
        print(content)
        print("-" * 80)
    except Exception as e:
        print(f"[ERROR] Error reading file: {e}")
        import traceback
        traceback.print_exc()
        return None
    
    try:
        # Import the module directly
        import importlib.util
        module_name = f"plugin_{file_path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None:
            print("Error: Could not create module spec")
            return None
            
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        
        print("\nModule attributes:")
        for attr in dir(module):
            if not attr.startswith('__'):
                print(f"- {attr}")
        
        # Find plugin classes
        from bbf.core.plugin import BasePlugin
        
        print("\nSearching for plugin classes:")
        for name, obj in inspect.getmembers(module, inspect.isclass):
            print(f"\nFound class: {name}")
            print(f"Module: {getattr(obj, '__module__', '?')}")
            
            try:
                is_subclass = issubclass(obj, BasePlugin)
                print(f"Is subclass of BasePlugin: {is_subclass}")
                print(f"Is BasePlugin: {obj is BasePlugin}")
                print(f"Is abstract: {inspect.isabstract(obj)}")
                
                if is_subclass and obj is not BasePlugin and not inspect.isabstract(obj):
                    print(f"Found plugin class: {name}")
                    print(f"Plugin name: {getattr(obj, 'name', 'N/A')}")
                    return obj
                    
            except Exception as e:
                print(f"Error checking class: {e}")
        
        print("No valid plugin classes found")
        return None
        
    except Exception as e:
        print(f"Error loading plugin: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    """Main function."""
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
