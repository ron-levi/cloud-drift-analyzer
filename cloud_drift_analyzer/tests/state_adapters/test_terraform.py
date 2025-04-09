import json
import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock

from cloud_drift_analyzer.state_adapters.terraform import TerraformStateAdapter
from cloud_drift_analyzer.core.models import ResourceState

@pytest.fixture
def mock_tfstate():
    return {
        "version": 4,
        "terraform_version": "1.0.0",
        "resources": [
            {
                "type": "aws_s3_bucket",
                "name": "test_bucket",
                "provider": "aws",
                "instances": [
                    {
                        "index_key": "test-bucket-id",
                        "attributes": {
                            "bucket": "test-bucket-name",
                            "region": "us-west-2"
                        }
                    }
                ]
            }
        ]
    }

@pytest.fixture
def mock_tf_files():
    return """
resource "aws_s3_bucket" "test_bucket" {
    bucket = "test-bucket-name"
    region = "us-west-2"
}
"""

class TestTerraformStateAdapter:
    
    @pytest.mark.asyncio
    async def test_parse_tfstate_file(self, mock_tfstate, tmp_path):
        # Create a temporary tfstate file
        state_file = tmp_path / "terraform.tfstate"
        with open(state_file, 'w') as f:
            json.dump(mock_tfstate, f)
        
        adapter = TerraformStateAdapter(str(state_file))
        resources = await adapter.get_resources()
        
        assert len(resources) == 1
        resource = resources[0]
        assert resource.resource_type == "aws_s3_bucket"
        assert resource.provider == "aws"
        assert resource.resource_id == "test-bucket-id"
        assert resource.properties["bucket"] == "test-bucket-name"
        assert resource.properties["region"] == "us-west-2"

    @pytest.mark.asyncio
    async def test_parse_terraform_directory(self, mock_tf_files, tmp_path):
        # Create a temporary directory with Terraform files
        tf_dir = tmp_path / "terraform"
        tf_dir.mkdir()
        
        main_tf = tf_dir / "main.tf"
        main_tf.write_text(mock_tf_files)
        
        # Mock the terraform command outputs
        mock_show_output = {
            "values": {
                "root_module": {
                    "resources": [
                        {
                            "provider_name": "aws",
                            "type": "s3_bucket",
                            "name": "test_bucket",
                            "instances": [
                                {
                                    "attributes": {
                                        "bucket": "test-bucket-name",
                                        "region": "us-west-2"
                                    }
                                }
                            ]
                        }
                    ]
                }
            }
        }
        
        with patch('subprocess.run') as mock_run:
            # Mock terraform init
            mock_init = Mock()
            mock_init.returncode = 0
            
            # Mock terraform show
            mock_show = Mock()
            mock_show.returncode = 0
            mock_show.stdout = json.dumps(mock_show_output)
            
            mock_run.side_effect = [mock_init, mock_show]
            
            adapter = TerraformStateAdapter(str(tf_dir))
            resources = await adapter.get_resources()
            
            assert len(resources) == 1
            resource = resources[0]
            assert resource.resource_type == "aws_s3_bucket"
            assert resource.provider == "aws"
            assert resource.properties["bucket"] == "test-bucket-name"
            assert resource.properties["region"] == "us-west-2"
            
            # Verify terraform commands were called
            assert mock_run.call_count == 2
            mock_run.assert_any_call(['terraform', 'init'], check=True, capture_output=True)
            mock_run.assert_any_call(['terraform', 'show', '-json'], check=True, capture_output=True, text=True)