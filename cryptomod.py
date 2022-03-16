import click
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

PRIVATE_KEY = 'private_key.pem'
PUBLIC_KEY = 'public_key.pem'
FILE = 'example.txt'
SIGNATURE = 'signature.txt'


@click.command()
@click.option('-p_private', '--path_to_private_key', default=os.path.join('./', PRIVATE_KEY),
              prompt='Enter path to private key', type=click.Path(exists=True, dir_okay=False, readable=True),
              help=f'Path to private key')
@click.option('-p_file', '--path_to_the_file', default=os.path.join('./', FILE), prompt='Enter path to file',
              type=click.Path(exists=True, dir_okay=False, readable=True), help=f'Path to file')
@click.option('-p_signature', '--path_to_the_signature', default=os.path.join('./', SIGNATURE),
              prompt='Enter path to signature', type=click.Path(exists=False, dir_okay=False, readable=True),
              help=f'Path to signature')
def sign_file(path_to_private_key, path_to_the_file, path_to_the_signature):
    h = SHA256.new()
    with open(path_to_the_file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)

    try:
        f = open(path_to_private_key, 'r')
        key = RSA.import_key(f.read())
    except FileNotFoundError:
        raise FileNotFoundError('Private key not found')

    signature = pkcs1_15.new(key).sign(h)
    f = open(path_to_the_signature, 'wb')
    f.write(signature)
    f.close()

    click.echo(f'Signature saved - {path_to_the_signature}')


@click.command()
@click.option('-p_public', '--path_to_public_key', default=os.path.join('./', PUBLIC_KEY),
              prompt='Enter path to public key', type=click.Path(exists=True, dir_okay=False, readable=True),
              help=f'Path to public key')
@click.option('-p_file', '--path_to_the_file', default=os.path.join('./', FILE), prompt='Enter path to file',
              type=click.Path(exists=True, dir_okay=False, readable=True), help=f'Path to file')
@click.option('-p_signature', '--path_to_the_signature', default=os.path.join('./', SIGNATURE),
              prompt='Enter path to signature', type=click.Path(exists=True, dir_okay=False, readable=True),
              help=f'Path to store signature')
def verify_signature(path_to_public_key, path_to_the_file, path_to_the_signature):
    print(path_to_public_key, path_to_the_file, path_to_the_signature)
    try:
        f_key = open(path_to_public_key, 'r')
        pubkey = RSA.import_key(f_key.read())
    except FileNotFoundError:
        raise FileNotFoundError('Private key not found')

    try:
        f_signature = open(path_to_the_signature, 'rb')
        signature = f_signature.read()
    except FileNotFoundError:
        raise FileNotFoundError('Signature not found')

    h = SHA256.new()
    with open(path_to_the_file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    try:
        pkcs1_15.new(pubkey).verify(h, signature)
    except ValueError:
        raise ValueError('Signature is invalid')
    else:
        click.echo(f'the signature for file {path_to_the_file} is valid')


@click.command()
@click.option('-p_private', '--path_to_private_key', default=os.path.join('./', PRIVATE_KEY),
              prompt='Enter the path to private key', type=click.Path(exists=True, dir_okay=False, readable=True),
              help=f'Path to store private key')
@click.option('-p_public', '--path_to_public_key', default=os.path.join('./', PUBLIC_KEY),
              prompt='Enter the path to public key', type=click.Path(exists=False, dir_okay=False, readable=True),
              help=f'Path to store public key')
def get_public_key(path_to_private_key, path_to_public_key):
    try:
        f = open(path_to_private_key, 'r')
        key = RSA.import_key(f.read())
    except FileNotFoundError:
        raise FileNotFoundError('Private key not found')

    pubkey = key.publickey()
    f = open(path_to_public_key, 'wb')
    f.write(pubkey.export_key('PEM'))
    f.close()

    click.echo(f'Public key saved - {path_to_public_key}')


@click.command()
@click.option('-p', '--path', default=os.path.join('./', PRIVATE_KEY), prompt='Enter the path to save private key',
              type=click.Path(exists=False, dir_okay=False, readable=True), help=f'Path to store private key')
def get_private_key(path):
    """Create private key"""
    key = RSA.generate(1024, os.urandom)
    f = open(path, 'wb')
    f.write(key.export_key('PEM'))
    f.close()

    click.echo(f'Private key saved - {path}')


@click.group()
# @click.option('--m', default='', prompt='enter the path', help=f'path to store private key')
def main():
    pass


main.add_command(get_private_key)
main.add_command(get_public_key)
main.add_command(sign_file)
main.add_command(verify_signature)


if __name__ == '__main__':
    main()
