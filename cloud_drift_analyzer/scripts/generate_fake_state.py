import json
import os

# Example fake Terraform state data
fake_state = {
    "version": 4,
    "terraform_version": "1.3.0",
    "serial": 1,
    "lineage": "fake-lineage-1234",
    "outputs": {},
    "resources": [
        {
            "module": "module.fake_module",
            "mode": "managed",
            "type": "aws_instance",
            "name": "fake_instance",
            "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
            "instances": [
                {
                    "schema_version": 1,
                    "attributes": {
                        "ami": "ami-12345678",
                        "id": "i-0fakeinstance",
                        "instance_type": "t2.micro",
                        "tags": {
                            "Name": "fake-instance"
                        }
                    }
                }
            ]
        }
    ]
}

def write_fake_state_file(path):
    with open(path, "w") as f:
        json.dump(fake_state, f, indent=2)
    print(f"Fake Terraform state written to {path}")

if __name__ == "__main__":
    state_path = os.environ.get("FAKE_TFSTATE_PATH", "fake_terraform.tfstate")
    write_fake_state_file(state_path)