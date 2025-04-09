import os

repo_structure = {
    "cloud_drift_analyzer": {
        "core": {
            "engine.py": "",
            "models.py": "",
            "comparator.py": "",
            "utils.py": "",
        },
        "state_adapters": {
            "base.py": "",
            "terraform.py": "",
            "pulumi.py": "",
        },
        "providers": {
            "base.py": "",
            "aws": {
                "client.py": "",
                "mappers.py": "",
            },
            "gcp": {},
        },
        "reporters": {
            "base.py": "",
            "json_reporter.py": "",
            "html_reporter.py": "",
        },
        "api": {
            "main.py": "",
            "routes": {
                "health.py": "",
                "drift.py": "",
            },
        },
        "scheduler": {
            "cron.py": "",
        },
        "db": {
            "models.py": "",
            "crud.py": "",
            "database.py": "",
        },
        "cli": {
            "main.py": "",
        },
        "plugins": {
            "slack_notifier.py": "",
        },
        "tests": {
            "core": {},
            "state_adapters": {},
            "providers": {},
        },
        "scripts": {
            "generate_fake_state.py": "",
        },
        "Dockerfile": "",
        "pyproject.toml": "",
        "README.md": "",
        ".env.example": "",
    }
}


def create_structure(base_path, structure):
    for name, content in structure.items():
        path = os.path.join(base_path, name)
        if isinstance(content, dict):
            os.makedirs(path, exist_ok=True)
            create_structure(path, content)
        else:
            with open(path, "w") as f:
                f.write(content)


if __name__ == "__main__":
    create_structure(".", repo_structure)
    print("Project structure generated successfully!")