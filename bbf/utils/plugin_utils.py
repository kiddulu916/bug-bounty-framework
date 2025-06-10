"""
Utility functions for plugin management in the Bug Bounty Framework.
"""

import importlib
import inspect
import logging
import pkgutil
from pathlib import Path
from typing import Dict, List, Optional, Set, Type, TypeVar, Any, Union

from bbf.core.plugin import BasePlugin
from bbf.core.exceptions import PluginError

logger = logging.getLogger(__name__)

# Type variable for plugin classes
T = TypeVar('T', bound=BasePlugin)

def load_plugin_from_file(file_path: Union[str, Path], base_class: Type[T]) -> Optional[Type[T]]:
    """
    Load a plugin class from a Python file.
    
    Args:
        file_path: Path to the Python file containing the plugin.
        base_class: The base class that the plugin must inherit from.
        
    Returns:
        The plugin class if found, None otherwise.
        
    Raises:
        PluginError: If there's an error loading the plugin.
    """
    file_path = Path(file_path)
    print(f"\n{'='*80}")
    print(f"Loading plugin from file: {file_path.absolute()}")
    
    if not file_path.exists() or not file_path.is_file():
        error_msg = f"Plugin file not found or not a file: {file_path}"
        print(f"ERROR: {error_msg}")
        raise PluginError(error_msg)
    
    try:
        # Read file content for debugging
        file_content = file_path.read_text(encoding='utf-8')
        print(f"File exists, size: {len(file_content)} bytes")
        print("File content (first 200 chars):")
        print("-" * 80)
        print(file_content[:200] + ("..." if len(file_content) > 200 else ""))
        print("-" * 80)
        
        # Create a module name from the file path
        module_name = f"plugin_{file_path.stem}"
        print(f"Module name: {module_name}")
        
        # Load the module
        print(f"Creating module spec from file: {file_path}")
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            error_msg = f"Could not load spec for {file_path}"
            print(f"ERROR: {error_msg}")
            raise PluginError(error_msg)
        
        print(f"Creating module from spec")
        module = importlib.util.module_from_spec(spec)
        
        # Add the module to sys.modules
        sys.modules[module_name] = module
        
        print(f"Executing module")
        spec.loader.exec_module(module)
        print(f"Module loaded successfully")
        
        # Find the plugin class in the module
        print("\nSearching for plugin classes in module:")
        print(f"Module attributes: {[a for a in dir(module) if not a.startswith('__')]}")
        
        plugin_classes = []
        for name, obj in inspect.getmembers(module, inspect.isclass):
            print(f"\nFound class: {name}")
            
            # Skip classes that are not defined in this module
            if getattr(obj, '__module__', '') != module_name:
                print(f"  - Skipping: Class {name} is defined in {getattr(obj, '__module__', '?')}, not in {module_name}")
                continue
                
            print(f"  - Module: {getattr(obj, '__module__', '?')}")
            print(f"  - Is class: {inspect.isclass(obj)}")
            print(f"  - Is abstract: {inspect.isabstract(obj)}")
            
            # Check if the class is a subclass of base_class
            is_subclass = False
            try:
                is_subclass = issubclass(obj, base_class)
                print(f"  - Is subclass of {base_class.__name__}: {is_subclass}")
            except Exception as e:
                print(f"  - Error checking subclass: {e}")
            
            # Check if the class is the base class itself
            is_base = obj is base_class
            print(f"  - Is base class: {is_base}")
            
            # Check if the class is abstract
            is_abstract = inspect.isabstract(obj)
            print(f"  - Is abstract: {is_abstract}")
            
            # Check if the class has a name attribute
            has_name = hasattr(obj, 'name')
            print(f"  - Has 'name' attribute: {has_name}")
            if has_name:
                print(f"  - Plugin name: {getattr(obj, 'name', 'N/A')}")
            
            # Check if the class has the required methods
            has_run = hasattr(obj, 'run') and callable(getattr(obj, 'run'))
            has_execute = hasattr(obj, 'execute') and callable(getattr(obj, 'execute'))
            print(f"  - Has 'run' method: {has_run}")
            print(f"  - Has 'execute' method: {has_execute}")
            
            # Check if this is a valid plugin class
            if is_subclass and not is_base and not is_abstract:
                print(f"  - Found valid plugin class: {name}")
                plugin_classes.append(obj)
            else:
                print(f"  - Not a valid plugin class")
        
        if not plugin_classes:
            print("\nNo valid plugin classes found in the module")
            return None
            
        if len(plugin_classes) > 1:
            print(f"\nWARNING: Found multiple plugin classes, using the first one: {plugin_classes[0].__name__}")
            
        return plugin_classes[0]
                
    except Exception as e:
        print(f"\nERROR loading plugin from {file_path}:")
        import traceback
        traceback.print_exc()
        raise PluginError(f"Error loading plugin from {file_path}: {e}") from e

def discover_plugins_in_directory(
    directory: Union[str, Path],
    base_class: Type[T],
    recursive: bool = False
) -> Dict[str, Type[T]]:
    """
    Discover plugins in a directory.
    
    Args:
        directory: Directory to search for plugins.
        base_class: The base class that plugins must inherit from.
        recursive: Whether to search recursively in subdirectories.
        
    Returns:
        A dictionary mapping plugin names to plugin classes.
    """
    print("\n" + "="*80)
    print(f"[DEBUG] discover_plugins_in_directory: {directory}")
    print(f"[DEBUG] base_class: {base_class}")
    print(f"[DEBUG] recursive: {recursive}")
    
    directory = Path(directory).absolute()
    plugins: Dict[str, Type[T]] = {}
    
    print(f"[DEBUG] Resolved directory path: {directory}")
    
    if not directory.exists():
        error_msg = f"Plugin directory not found: {directory}"
        print(f"[ERROR] {error_msg}")
        logger.error(error_msg)
        return plugins
        
    if not directory.is_dir():
        error_msg = f"Plugin path is not a directory: {directory}"
        print(f"[ERROR] {error_msg}")
        logger.error(error_msg)
        return plugins
    
    # Print directory contents for debugging
    try:
        dir_contents = list(directory.glob('*'))
        print(f"[DEBUG] Directory contents ({len(dir_contents)} items):")
        for item in dir_contents:
            print(f"  - {item.name} ({'dir' if item.is_dir() else 'file'}, {item.stat().st_size} bytes)")
    except Exception as e:
        print(f"[WARNING] Could not list directory contents: {e}")
    
    # Get all Python files in the directory
    pattern = "**/*.py" if recursive else "*.py"
    print(f"[DEBUG] Searching for files matching pattern: {pattern}")
    
    file_count = 0
    for file_path in directory.glob(pattern):
        file_count += 1
        print(f"\n[DEBUG] Found file: {file_path}")
        
        # Skip __init__.py and other special files
        if file_path.name.startswith('_') or file_path.name.startswith('.'):
            print(f"[DEBUG] Skipping special file: {file_path}")
        if file_path.name.startswith('_') or file_path.name == '__init__.py':
            print(f"Skipping special file: {file_path}")
            continue
            
        print(f"Attempting to load plugin from: {file_path}")
        
        try:
            print(f"Loading plugin from: {file_path.absolute()}")
            plugin_class = load_plugin_from_file(file_path, base_class)
            
            if plugin_class is not None:
                print(f"Successfully loaded plugin class: {plugin_class.__name__}")
                
                if hasattr(plugin_class, 'name'):
                    plugin_name = plugin_class.name
                    print(f"Found plugin class: {plugin_name} in {file_path}")
                    
                    if plugin_name in plugins:
                        print(f"WARNING: Plugin name '{plugin_name}' from {file_path} "
                              f"is already registered by another plugin. Skipping.")
                        continue
                        
                    print(f"Registering plugin: {plugin_name}")
                    plugins[plugin_name] = plugin_class
                else:
                    print(f"WARNING: Plugin class in {file_path} is missing a 'name' attribute.")
                    print(f"Available attributes: {[a for a in dir(plugin_class) if not a.startswith('_')]}")
            else:
                print(f"No plugin class found in {file_path}")
                
        except Exception as e:
            print(f"ERROR loading plugin from {file_path}:")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*80}")
    print(f"Plugin discovery complete. Found {len(plugins)} plugins:")
    for name, cls in plugins.items():
        print(f"- {name}: {cls.__module__}.{cls.__name__}")
    print("="*80)
    
    return plugins

def discover_plugins_in_package(
    package,
    base_class: Type[T],
    recursive: bool = True
) -> Dict[str, Type[T]]:
    """
    Discover plugins in a Python package.
    
    Args:
        package: The package to search for plugins.
        base_class: The base class that plugins must inherit from.
        recursive: Whether to search recursively in subpackages.
        
    Returns:
        A dictionary mapping plugin names to plugin classes.
    """
    plugins: Dict[str, Type[T]] = {}
    
    try:
        # Get the package path
        if hasattr(package, '__path__'):
            package_path = package.__path__
        else:
            package_path = [str(Path(package.__file__).parent)]
        
        # Iterate through all modules in the package
        for finder, name, is_pkg in pkgutil.iter_modules(package_path, package.__name__ + '.'):
            try:
                # Import the module
                module = importlib.import_module(name)
                
                # Find plugin classes in the module
                for _, obj in inspect.getmembers(module):
                    if (
                        inspect.isclass(obj)
                        and issubclass(obj, base_class)
                        and obj is not base_class
                        and not inspect.isabstract(obj)
                    ):
                        if hasattr(obj, 'name'):
                            plugin_name = obj.name
                            if plugin_name in plugins:
                                logger.warning(
                                    f"Plugin name '{plugin_name}' from {name} "
                                    f"is already registered by another plugin. Skipping."
                                )
                                continue
                            plugins[plugin_name] = obj
                
                # Recursively search in subpackages if enabled
                if recursive and is_pkg:
                    try:
                        subpackage = importlib.import_module(name)
                        sub_plugins = discover_plugins_in_package(
                            subpackage, base_class, recursive
                        )
                        # Merge plugins, handling name conflicts
                        for name, plugin in sub_plugins.items():
                            if name not in plugins:
                                plugins[name] = plugin
                    except ImportError as e:
                        logger.warning(f"Could not import subpackage {name}: {e}")
                        
            except Exception as e:
                logger.error(f"Error processing module {name}: {e}", exc_info=True)
                
    except Exception as e:
        logger.error(f"Error discovering plugins in package {package.__name__}: {e}", exc_info=True)
    
    return plugins

def get_plugin_class(plugin_name: str, base_class: Type[T]) -> Optional[Type[T]]:
    """
    Get a plugin class by name.
    
    Args:
        plugin_name: The name of the plugin to find.
        base_class: The base class that the plugin must inherit from.
        
    Returns:
        The plugin class if found, None otherwise.
    """
    # Try to import the module directly
    try:
        module = importlib.import_module(plugin_name)
        for _, obj in inspect.getmembers(module):
            if (
                inspect.isclass(obj)
                and issubclass(obj, base_class)
                and obj is not base_class
                and not inspect.isabstract(obj)
                and hasattr(obj, 'name')
                and obj.name == plugin_name
            ):
                return obj
    except ImportError:
        pass
    
    return None

def create_plugin_instance(
    plugin_name: str,
    base_class: Type[T],
    config: Optional[Dict[str, Any]] = None,
    **kwargs
) -> Optional[T]:
    """
    Create an instance of a plugin by name.
    
    Args:
        plugin_name: The name of the plugin to instantiate.
        base_class: The base class that the plugin must inherit from.
        config: Optional configuration for the plugin.
        **kwargs: Additional keyword arguments to pass to the plugin constructor.
        
    Returns:
        An instance of the plugin, or None if the plugin could not be found or instantiated.
    """
    plugin_class = get_plugin_class(plugin_name, base_class)
    if plugin_class is None:
        logger.error(f"Plugin not found: {plugin_name}")
        return None
    
    try:
        # Create an instance of the plugin
        return plugin_class(config or {}, **kwargs)
    except Exception as e:
        logger.error(f"Error creating instance of plugin {plugin_name}: {e}", exc_info=True)
        return None
