import click

@click.group()
def cli():
    """A simple CLI tool."""
    pass

@cli.command()
@click.option("--name", prompt="Enter your name", help="Your name to greet")
def greet(name):
    """Greets the user."""
    click.echo(f"Hello, {name}!")

@cli.command()
@click.argument("number", type=int)
def square(number):
    """Squares a given number."""
    click.echo(f"The square of {number} is {number * number}")

if __name__ == "__main__":
    cli()
