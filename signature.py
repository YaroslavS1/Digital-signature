import os

import click
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

PRIVATE_KEY = 'private_key.pem'
PUBLIC_KEY = 'public_key.pem'
FILE = 'example.txt'
SIGNATURE = 'signature.sgn'

SEPARATOR = '\n'


def sanitaizee_key(key):
    list_string = key.split(r'\n')
    return f"{SEPARATOR.join(list_string)}"


def get_hash(path_to_the_file):
    h = SHA256.new()
    with open(path_to_the_file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h


@click.command()
@click.option('-p_private', '--path_to_private_key', default=os.path.join(os.getcwd(), PRIVATE_KEY),
              prompt='Enter path to private key', type=click.STRING,
              help=f'Path to private key.')
@click.option('-p_file', '--path_to_the_file', default=os.path.join(os.getcwd(), FILE), prompt='Enter path to file',
              type=click.Path(exists=True, dir_okay=False, readable=True), help=f'Path to file.')
@click.option('-p_signature', '--path_to_the_signature', default=os.path.join(os.getcwd(), SIGNATURE),
              prompt='Enter path to save signature', type=click.Path(exists=False, dir_okay=False, readable=True),
              help=f'Path to save signature.')
def sign(path_to_private_key, path_to_the_file, path_to_the_signature):
    """Sign file with digital signature."""
    try:
        f = open(path_to_private_key, 'r')
        key = RSA.import_key(f.read())
    except FileNotFoundError:
        raise FileNotFoundError('Private key not found')

    h = get_hash(path_to_the_file)

    signature = pkcs1_15.new(key).sign(h)
    f = open(path_to_the_signature, 'wb')
    f.write(signature)
    f.close()

    click.echo(f'\033[32mSignature saved - {path_to_the_signature}')


@click.command()
@click.option('-p_public', '--path_to_public_key', default=os.path.join(os.getcwd(), PUBLIC_KEY),
              prompt='Enter path to public key or public key directly', type=click.STRING,
              help=f'Path to public key or public key directly.')
@click.option('-p_file', '--path_to_the_file', default=os.path.join(os.getcwd(), FILE), prompt='Enter path to file',
              type=click.Path(exists=True, dir_okay=False, readable=True), help=f'Path to file.')
@click.option('-p_signature', '--like_signature', default=os.path.join(os.getcwd(), SIGNATURE),
              prompt='Enter path to save signature', type=click.Path(exists=True, dir_okay=False, readable=True),
              help=f'Path to save signature.')
def verify(path_to_public_key, path_to_the_file, like_signature):
    """Verify signature."""
    try:
        if os.path.exists(path_to_public_key):
            f_key = open(path_to_public_key, 'r')
            pubkey = RSA.import_key(f_key.read())
        else:
            pubkey = RSA.import_key(sanitaizee_key(path_to_public_key))
    except Exception as e:
        raise ValueError(e)

    try:
        f_signature = open(like_signature, 'rb')
        signature = f_signature.read()
    except FileNotFoundError:
        raise FileNotFoundError('Signature not found')

    h = get_hash(path_to_the_file)
    try:
        pkcs1_15.new(pubkey).verify(h, signature)
    except ValueError:
        click.echo(f'\033[4m\033[31mThe signature for file {path_to_the_file} not valid')
    else:
        click.echo(f'\033[4m\033[32mThe signature for file {path_to_the_file} is valid')


@click.command()
@click.option('-p_private', '--path_to_private_key', default=os.path.join(os.getcwd(), PRIVATE_KEY),
              prompt='Enter path to private key', type=click.Path(exists=True, dir_okay=False, readable=True),
              help=f'Path to private key.')
@click.option('-p_public', '--path_to_public_key', default=os.path.join(os.getcwd(), PUBLIC_KEY),
              prompt='Enter path to save public key', type=click.Path(exists=False, dir_okay=False, readable=True),
              help=f'Path to save public key.')
def public_key(path_to_private_key, path_to_public_key):
    """Create a public key from a private key."""
    try:
        f = open(path_to_private_key, 'r')
        key = RSA.import_key(f.read())
    except FileNotFoundError:
        raise FileNotFoundError('Private key not found')

    pubkey = key.publickey()
    repr_pubkey = pubkey.export_key('PEM')
    f = open(path_to_public_key, 'wb')
    f.write(repr_pubkey)
    f.close()

    click.echo(f'\033[32mPublic key saved - {path_to_public_key}\n'
               f'\033[34m\033[2m{repr_pubkey.decode("utf-8")}\033[0m\n'
               f'\nFOR COPY:\n'
               f'\033[35m{str(repr_pubkey)[2:-1]}')


@click.command()
@click.option('-p', '--path', default=os.path.join(os.getcwd(), PRIVATE_KEY), prompt='Enter path to save private key',
              type=click.Path(exists=False, dir_okay=False, readable=True), help=f'Path to save private key.')
def private_key(path):
    """Create private key."""
    key = RSA.generate(1024, os.urandom)
    repr_key = key.export_key('PEM')
    f = open(path, 'wb')
    f.write(repr_key)
    f.close()

    click.echo(f'\033[32mPrivate key saved - {path}\n'
               f'\033[34m\033[2m{repr_key.decode("utf-8")}')


@click.group()
def cli():
    pass


cli.add_command(public_key)
cli.add_command(private_key)
cli.add_command(sign)
cli.add_command(verify)


if __name__ == '__main__':
    cli()
