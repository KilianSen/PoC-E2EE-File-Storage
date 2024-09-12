import click
from . import proof_of_concept as implementation


@click.command()
@click.argument('username')
@click.argument('password')
def register(username: str, password: str):
    click.echo(f"Registering user {username}")
    implementation.register(username, password)
    implementation.login(username, password)
    click.echo("User registered and logged in")

@click.command()
@click.argument('username')
@click.argument('password')
def login(username: str, password: str):
    implementation.login(username, password)
    click.echo("Logged in")

@click.command()
def logout():
    implementation.logout()
    click.echo("Logged out")

@click.command()
@click.argument('path')
def upload(path: str):
    """
    Upload a file to the server with end to end encryption
    :param path:
    :return:
    """
    click.echo(f"Uploading file at {path}")
    uri = implementation.upload(path)
    click.echo(f"File uploaded! Access it with URI {uri}")

@click.command()
@click.argument('uri')
@click.argument('path')
def download(uri: str, path: str):
    """
    Download a file from the server with end to end encryption
    :param uri:
    :param path:
    :return:
    """
    click.echo(f"Downloading file with URI {uri} to {path}")
    implementation.download(uri, path)
    click.echo("Download complete")

@click.command()
@click.argument('uri')
def delete(uri: str):
    """
    Delete a file from the server with end to end encryption
    :param uri:
    :return:
    """
    click.echo(f"Deleting file with URI {uri}")
    implementation.delete(uri)
    click.echo("File deleted")

@click.command()
def delete_user():
    """
    Delete the current user
    :return:
    """
    click.echo("Deleting user...")
    implementation.delete_user()
    click.echo("User deleted")

@click.command()
def files():
    """
    Get all files uploaded by the user + their URIs
    :return:
    """
    click.echo("Getting files...")
    files = implementation.get_files()
    for file, uri in files:
        click.echo(f"{file}: {uri}")


@click.group()
def cli():
    ...

def main():
    cli.add_command(register)
    cli.add_command(login)
    cli.add_command(logout)
    cli.add_command(files)
    cli.add_command(upload)
    cli.add_command(download)
    cli()