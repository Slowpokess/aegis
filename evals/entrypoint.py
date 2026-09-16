from app.cli.main import cli
from evals.cli import eval_cli

cli.add_typer(eval_cli, name="eval")

__all__ = ["cli"]


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
