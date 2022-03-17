import os

import click
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from fetch_email import DOWNNLOAD
from fetch_email import FetchEmail
from helpers import get_hash
from helpers import sanitize_key
from send_email import send_email as send_email_

PRIVATE_KEY = 'private_key.pem'
PUBLIC_KEY = 'public_key.pem'

FILE = 'example.txt'
SIGNATURE = 'signature.sgn'


@click.command()
@click.option('-p_private', '--path_private_key', default=os.path.join(os.getcwd(), PRIVATE_KEY),
              prompt='Enter path to private key', type=click.STRING,
              help=f'Path to private key.')
@click.option('-p_file', '--path_file', default=os.path.join(os.getcwd(), FILE), prompt='Enter path to file',
              type=click.Path(exists=True, dir_okay=False, readable=True), help=f'Path to file.')
@click.option('-p_signature', '--path_signature', default=os.path.join(os.getcwd(), SIGNATURE),
              prompt='Enter path to save signature', type=click.Path(exists=False, dir_okay=False, readable=True),
              help=f'Path to save signature.')
def sign(path_private_key, path_file, path_signature):
    """Sign file with digital signature."""
    try:
        f = open(path_private_key, 'r')
        key = RSA.import_key(f.read())
    except FileNotFoundError:
        raise FileNotFoundError('Private key not found')

    h = get_hash(path_file)

    signature = pkcs1_15.new(key).sign(h)
    f = open(path_signature, 'wb')
    f.write(signature)
    f.close()

    click.echo(f'\033[32mSignature saved - {path_signature}')


@click.command()
@click.option('-p_public', '--path_public_key', default=os.path.join(os.getcwd(), PUBLIC_KEY),
              prompt='Enter path to public key or public key directly', type=click.STRING,
              help=f'Path to public key or public key directly.')
@click.option('-p_file', '--path_file', default=os.path.join(os.getcwd(), FILE), prompt='Enter path to file',
              type=click.Path(exists=True, dir_okay=False, readable=True), help=f'Path to file.')
@click.option('-p_signature', '--path_signature', default=os.path.join(os.getcwd(), SIGNATURE),
              prompt='Enter path to signature', type=click.Path(exists=True, dir_okay=False, readable=True),
              help=f'Path to signature.')
def verify(path_public_key, path_file, path_signature):
    """Verify signature."""
    try:
        if os.path.exists(path_public_key):
            f_key = open(path_public_key, 'r')
            pubkey = RSA.import_key(f_key.read())
        else:
            pubkey = RSA.import_key(sanitize_key(path_public_key))
    except Exception as e:
        raise ValueError(e)

    try:
        f_signature = open(path_signature, 'rb')
        signature = f_signature.read()
    except FileNotFoundError:
        raise FileNotFoundError('Signature not found')

    h = get_hash(path_file)
    try:
        pkcs1_15.new(pubkey).verify(h, signature)
    except ValueError:
        click.echo(f'\033[4m\033[31mThe signature for file {path_file} not valid')
    else:
        click.echo(f'\033[4m\033[32mThe signature for file {path_file} is valid')


@click.command()
@click.option('-p_private', '--path_private_key', default=os.path.join(os.getcwd(), PRIVATE_KEY),
              prompt='Enter path to private key', type=click.Path(exists=True, dir_okay=False, readable=True),
              help=f'Path to private key.')
@click.option('-p_public', '--path_public_key', default=os.path.join(os.getcwd(), PUBLIC_KEY),
              prompt='Enter path to save public key', type=click.Path(exists=False, dir_okay=False, readable=True),
              help=f'Path to save public key.')
def public_key(path_private_key, path_public_key):
    """Create a public key from a private key."""
    try:
        f = open(path_private_key, 'r')
        key = RSA.import_key(f.read())
    except FileNotFoundError:
        raise FileNotFoundError('Private key not found')

    pubkey = key.publickey()
    repr_pubkey = pubkey.export_key('PEM')
    f = open(path_public_key, 'wb')
    f.write(repr_pubkey)
    f.close()

    click.echo(f'\033[32mPublic key saved - {path_public_key}\n'
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


@click.command()
@click.option('-m', '--mail', prompt='Address from which you want to send an email.', type=click.STRING,
              help=f'Enter the email.', default='Iaro5laI3@yandex.ru')
@click.password_option(confirmation_prompt=False)
@click.option('-p_public', '--path_public_key', default=os.path.join(os.getcwd(), PUBLIC_KEY),
              prompt='Enter path to public key or public key directly',
              type=click.Path(exists=True, dir_okay=False, readable=True), help=f'Path to public key.')
@click.option('-p_file', '--path_file', default=os.path.join(os.getcwd(), FILE), prompt='Enter path to file',
              type=click.Path(exists=True, dir_okay=False, readable=True), help=f'Path to file.')
@click.option('-p_signature', '--path_signature', default=os.path.join(os.getcwd(), SIGNATURE),
              prompt='Enter path to signature', type=click.Path(exists=True, dir_okay=False, readable=True),
              help=f'Path to signature.')
@click.option('-r', '--recipient', prompt='Enter the recipient', type=click.STRING, help=f"Recipient's mail.",
              default='Iaro5laI3@yandex.ru')
def send_email(mail, password, path_public_key, path_file, path_signature, recipient):
    send_email_(
        files=(path_public_key, path_file, path_signature),
        recipients=recipient,
        user=mail,
        password=password)


@click.command()
@click.option('-m', '--mail', prompt='Enter email address', type=click.STRING,
              help=f'Enter the address from which you want to download files.', default='Iaro5laI3@yandex.ru')
@click.password_option(confirmation_prompt=False)
@click.option('-p_file', '--path', default=os.path.join(os.getcwd(), DOWNNLOAD), prompt='Enter path to save',
              type=click.Path(exists=False, dir_okay=True, readable=True), help=f'Path to save.')
def fetch_email(mail, password, path):
    a = FetchEmail(username=mail, password=password)
    a.save_attachment(a.fetch_unread_messages()[0], path)


@click.group()
def cli():
    pass


cli.add_command(public_key)
cli.add_command(private_key)
cli.add_command(sign)
cli.add_command(verify)
cli.add_command(send_email)
cli.add_command(fetch_email)


if __name__ == '__main__':
    cli()
