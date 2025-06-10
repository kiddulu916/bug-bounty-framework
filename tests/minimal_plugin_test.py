"""
Minimal test script to debug plugin loading.
"""
import sys
import os
import tempfile
import importlib.util
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

def create_test_plugin(directory):
    """Create a test plugin file."""
    plugin_code = """
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

def main():
    """Main function."""
    print("Starting plugin loading test...")
    
    # Create a temporary directory
    temp_dir = Path(tempfile.mkdtemp())
    print(f"Created temporary directory: {temp_dir}")
    
    try:
        # Create a test plugin
        plugin_file = create_test_plugin(temp_dir)
        print(f"Created test plugin at: {plugin_file}")
        
        # Verify file exists
        if not plugin_file.exists():
            print("Error: Plugin file was not created")
            return
            
        # Print file content for debugging
        print("\nPlugin file content:")
        print("-" * 80)
        print(plugin_file.read_text())
        print("-" * 80)
        
        # Try to import the module
        module_name = "test_plugin_d"
        spec = importlib.util.spec_from_file_location(module_name, plugin_file)
        if spec is None:
            print("Error: Could not create module spec")
            return
            
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        
        print("\nExecuting module...")
        spec.loader.exec_module(module)
        print("Module executed successfully")
        
        # Check what was imported
        print("\nModule attributes:")
        for name in dir(module):
            if not name.startswith('__'):
                print(f"- {name}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        # Clean up
        print(f"\nCleaning up temporary directory: {temp_dir}")
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        # Print plugin registry for debugging
        try:
            from bbf.core.plugin import PluginRegistry
            print("\nPlugin registry contents:")
            print("-" * 80)
            print(f"Registered plugins: {PluginRegistry._plugins}")
        except Exception as e:
            print(f"Error checking plugin registry: {e}")

if __name__ == "__main__":
    main()
