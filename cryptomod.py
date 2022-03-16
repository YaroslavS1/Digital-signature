import click
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

PRIVATE_KEY = 'private_key.pem'
PUBLIC_KEY = 'public_key.pem'
FILE = 'example.txt'
ELECTRONIC_SIGNATURE = 'signature.txt'


def sanitaize_path(path, default_path):
    return path if path != '' else default_path


@click.command()
@click.option('--path_to_public_key', default='', prompt='enter the path', help=f'path to store public key')
@click.option('--path_to_the_file', default='', prompt='enter the path', help=f'path to file')
@click.option('--path_to_the_signature', default='', prompt='enter the path', help=f'signature path')
def verify_signature(path_to_public_key, path_to_the_file, path_to_the_signature):
    _path_to_public = sanitaize_path(path_to_public_key, PUBLIC_KEY)
    _path_to_the_file = sanitaize_path(path_to_the_file, FILE)
    _path_to_the_signature = sanitaize_path(path_to_the_signature, ELECTRONIC_SIGNATURE)

    try:
        f_key = open(_path_to_public, 'r')
        pubkey = RSA.import_key(f_key.read())
    except FileNotFoundError:
        raise FileNotFoundError('Private key not found')

    try:
        f_signature = open(_path_to_the_signature, 'rb')
        signature = f_signature.read()
    except FileNotFoundError:
        raise FileNotFoundError('Signature not found')

    h = SHA256.new()
    with open(_path_to_the_file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    try:
        pkcs1_15.new(pubkey).verify(h, signature)
    except ValueError:
        raise ValueError('Signature is invalid')
    else:
        click.echo(f'the signature for the file {_path_to_the_file} is valid')


@click.command()
@click.option('--path_to_private_key', default='', prompt='enter the path', help=f'path to store private key')
@click.option('--path_to_the_file', default='', prompt='enter the path', help=f'path to file')
@click.option('--path_to_the_signature', default='', prompt='enter the path', help=f'signature path')
def sign_file(path_to_private_key, path_to_the_file, path_to_the_signature):
    _path_to_private = sanitaize_path(path_to_private_key, PRIVATE_KEY)
    _path_to_the_file = sanitaize_path(path_to_the_file, FILE)
    _path_to_the_signature = sanitaize_path(path_to_the_signature, ELECTRONIC_SIGNATURE)

    h = SHA256.new()
    with open(_path_to_the_file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)

    try:
        f = open(_path_to_private, 'r')
        key = RSA.import_key(f.read())
    except FileNotFoundError:
        raise FileNotFoundError('Private key not found')

    signature = pkcs1_15.new(key).sign(h)
    f = open(_path_to_the_signature, 'wb')
    f.write(signature)
    f.close()

    click.echo(f'Signature saved - {_path_to_the_signature}')


@click.command()
@click.option('--path_to_private_key', default='', prompt='enter the path', help=f'path to store private key')
@click.option('--path_to_public_key', default='', prompt='enter the path', help=f'path to store public key')
def get_public_key(path_to_private_key, path_to_public_key):
    _path_to_private = sanitaize_path(path_to_private_key, PRIVATE_KEY)
    _path_to_public = sanitaize_path(path_to_public_key, PUBLIC_KEY)

    try:
        f = open(_path_to_private, 'r')
        key = RSA.import_key(f.read())
    except FileNotFoundError:
        raise FileNotFoundError('Private key not found')

    pubkey = key.publickey()
    f = open(_path_to_public, 'wb')
    f.write(pubkey.export_key('PEM'))
    f.close()

    click.echo(f'Public key saved - {_path_to_public}')


@click.command()
@click.option('--path', default='', prompt='enter the path', help=f'path to store private key')
def get_private_key(path):
    _path = path if path != '' else PRIVATE_KEY
    key = RSA.generate(1024, os.urandom)
    f = open(_path, 'wb')
    f.write(key.export_key('PEM'))
    f.close()

    click.echo(f'Private key saved - {_path}')


@click.group()
def main():
    pass


main.add_command(get_private_key)
main.add_command(get_public_key)
main.add_command(sign_file)
main.add_command(verify_signature)


if __name__ == '__main__':
    main()
