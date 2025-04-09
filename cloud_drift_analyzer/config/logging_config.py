import os
import yaml
from pathlib import Path
from typing import Optional
import logging.config
import structlog

from ..core.logging import configure_logging

def load_logging_config(
    environment: str = "development",
    config_dir: Optional[str] = None,
    override_level: Optional[str] = None
) -> None:
    """
    Load logging configuration for the specified environment.
    
    Args:
        environment: Environment name ("development", "production", "test")
        config_dir: Optional directory containing config files
        override_level: Optional override for log level
    """
    # Determine config directory
    if config_dir is None:
        config_dir = str(Path(__file__).parent)
    
    # Map environment to config file
    env_map = {
        "development": "logging_dev.yaml",
        "production": "logging_prod.yaml",
        "test": "logging_test.yaml"
    }
    
    config_file = env_map.get(environment, "logging_dev.yaml")
    config_path = os.path.join(config_dir, config_file)
    
    try:
        # Load YAML config
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            
        # Override log level if specified
        if override_level:
            config['root']['level'] = override_level
            for logger in config.get('loggers', {}).values():
                logger['level'] = override_level
        
        # Configure Python logging
        logging.config.dictConfig(config)
        
        # Configure structlog
        configure_logging(
            log_level=config['root']['level'],
            json_format='json' in config.get('formatters', {}),
            log_file=config.get('handlers', {}).get('file', {}).get('filename')
        )
        
    except Exception as e:
        # Fall back to basic configuration
        print(f"Error loading logging config: {str(e)}")
        print("Falling back to basic configuration")
        configure_logging()