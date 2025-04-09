import asyncio
import json
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table

from ..state_adapters.terraform import TerraformStateAdapter
from ..core.logging import get_logger, configure_logging, log_duration, LogContext

app = typer.Typer(help="Cloud Drift Analyzer CLI")
console = Console()
logger = get_logger(__name__)

@app.callback()
def init(
    log_level: str = typer.Option(
        "INFO",
        "--log-level",
        "-l",
        help="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
    ),
    json_logs: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output logs in JSON format"
    ),
    log_file: Optional[str] = typer.Option(
        None,
        "--log-file",
        "-f",
        help="Log file path (optional)"
    )
):
    """Initialize the CLI application."""
    configure_logging(
        log_level=log_level,
        json_format=json_logs,
        log_file=log_file
    )
    logger.info("cli_initialized",
                log_level=log_level,
                json_format=json_logs,
                log_file=log_file)

@app.command()
def get_terraform_state(
    path: str = typer.Argument(
        ...,
        help="Path to a .tfstate file or directory containing .tf files"
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path for JSON state (optional)"
    ),
    format: str = typer.Option(
        "table",
        "--format", "-f",
        help="Output format: 'table' or 'json'"
    )
):
    """Fetch and display Terraform state from a file or directory."""
    with LogContext(command="get_terraform_state", path=path, format=format):
        try:
            with log_duration(logger, "terraform_state_retrieval"):
                logger.info("creating_terraform_adapter")
                adapter = TerraformStateAdapter(path)
                
                logger.info("fetching_resources")
                resources = asyncio.run(adapter.get_resources())
                logger.info("resources_fetched", count=len(resources))
                
                if format == "json":
                    # Convert to JSON-serializable format
                    output = [resource.model_dump() for resource in resources]
                    
                    if output_file:
                        # Write to file
                        logger.info("writing_json_output", file=output_file)
                        with open(output_file, 'w') as f:
                            json.dump(output, f, indent=2)
                        console.print(f"[green]State written to {output_file}[/green]")
                    else:
                        # Print to console
                        console.print_json(data=output)
                else:
                    # Create rich table
                    logger.debug("creating_table_output")
                    table = Table()
                    table.add_column("Resource Type", style="cyan")
                    table.add_column("Resource ID", style="green")
                    table.add_column("Provider", style="yellow")
                    
                    for resource in resources:
                        table.add_row(
                            resource.resource_type,
                            resource.resource_id,
                            resource.provider
                        )
                    
                    console.print(table)
                    
        except Exception as e:
            logger.error("command_failed", error=str(e))
            console.print(f"[red]Error: {str(e)}[/red]")
            raise typer.Exit(1)

@app.command()
def analyze_drift(
    state_path: str = typer.Argument(
        ...,
        help="Path to IaC state file or directory"
    ),
    provider: str = typer.Option(
        "aws",
        "--provider", "-p",
        help="Cloud provider (aws, gcp)"
    ),
    environment: str = typer.Option(
        "production",
        "--env", "-e",
        help="Environment name"
    ),
    notify: bool = typer.Option(
        False,
        "--notify",
        help="Send notifications if drift is detected"
    )
):
    """Analyze infrastructure drift between IaC and cloud resources."""
    with LogContext(
        command="analyze_drift",
        state_path=state_path,
        provider=provider,
        environment=environment
    ):
        try:
            with log_duration(logger, "drift_analysis"):
                logger.info("starting_drift_analysis")
                # TODO: Implement drift analysis command
                logger.warning("drift_analysis_not_implemented")
                console.print("[yellow]Drift analysis not yet implemented[/yellow]")
                
        except Exception as e:
            logger.error("command_failed", error=str(e))
            console.print(f"[red]Error: {str(e)}[/red]")
            raise typer.Exit(1)

if __name__ == "__main__":
    app()