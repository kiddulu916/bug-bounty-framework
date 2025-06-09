"""
Basic usage example for the Bug Bounty Framework.

This script demonstrates how to use the framework to perform a simple
subdomain enumeration scan on a target domain.
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bbf.core.framework import BFFramework

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('bug_bounty_framework.log')
    ]
)

logger = logging.getLogger(__name__)

async def main():
    """
    Main function to demonstrate the Bug Bounty Framework usage.
    """
    # Configuration
    config = {
        'target': 'example.com',  # Replace with your target domain
        'output_dir': 'reports',
        'log_level': 'INFO',
        'stages': {
            'recon': {
                'enabled': True,
                'plugins': ['subdomain_enumeration']
            },
            'scan': {
                'enabled': False  # Disable other stages for this example
            },
            'test': {
                'enabled': False  # Disable other stages for this example
            },
            'report': {
                'enabled': True
            }
        },
        'plugins': {
            'subdomain_enumeration': {
                'max_workers': 20,
                'timeout': 5,
                'rate_limit': 0.1,
                'use_search_engines': True,
                'use_cert_transparency': True
            }
        }
    }

    # Initialize the framework
    framework = BFFramework(config)
    
    try:
        # Initialize the framework
        await framework.initialize()
        
        logger.info("Starting Bug Bounty Framework")
        logger.info(f"Target: {config['target']}")
        
        # Run the recon stage
        logger.info("Starting Recon stage...")
        recon_results = await framework.run_stage('recon')
        
        # Print the results
        if recon_results and 'subdomain_enumeration' in recon_results:
            subdomains = recon_results['subdomain_enumeration'].get('subdomains', [])
            logger.info(f"\nFound {len(subdomains)} subdomains:")
            for subdomain in sorted(subdomains):
                logger.info(f"  - {subdomain}")
        
        # Generate a report
        logger.info("\nGenerating report...")
        await framework.run_stage('report')
        
        logger.info("\nScan completed successfully!")
        
    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
        return 1
    finally:
        # Clean up resources
        await framework.close()
    
    return 0

if __name__ == "__main__":
    # Run the main function
    sys.exit(asyncio.run(main()))
