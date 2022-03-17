import os
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from platform import python_version

import click
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import codecs
import email
import imaplib
import os

PRIVATE_KEY = 'private_key.pem'
PUBLIC_KEY = 'public_key.pem'
FILE = 'example.txt'
SIGNATURE = 'signature.sgn'

SERVER = 'smtp.yandex.ru'
SERVER_ = 'imap.yandex.ru'
SUBJECT = 'ЭЦП'
TEXT = 'ЭЦП'
HTML = '<html><head></head><body><p> ' + TEXT + '</p></body></html>'

SEPARATOR = '\n'


class FetchEmail():

    connection = None
    error = None

    def __init__(self, mail_server, username, password):
        self.connection = imaplib.IMAP4_SSL(mail_server)
        self.connection.login(username, password)
        self.connection.select(readonly=False)  # so we can mark mails as read

    def close_connection(self):
        """
        Close the connection to the IMAP server
        """
        self.connection.close()

    def save_attachment(self, msg, download_folder="./"):
        """
        Given a message, save its attachments to the specified
        download folder (default is /tmp)

        return: file path to attachment
        """
        att_path = "No attachment found."
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue

            filename = part.get_filename()
            att_path = os.path.join(download_folder, filename)

            if not os.path.isfile(att_path):
                fp = open(att_path, 'wb')
                fp.write(part.get_payload(decode=True))
                fp.close()
        return att_path

    def fetch_unread_messages(self):
        """
        Retrieve unread messages
        """
        emails = []
        (result, messages) = self.connection.search(None, 'UnSeen')
        # print(str(messages[0])[2:-1])
        if result == "OK":
            for message in str(messages[0])[2:-1].split(' '):
                try:
                    ret, data = self.connection.fetch(message, '(RFC822)')
                except:
                    print("No new emails to read.")
                    self.close_connection()
                    exit()

                msg = email.message_from_bytes(data[0][1])
                if not isinstance(msg, str):
                    emails.append(msg)
                response, data = self.connection.store(message, '+FLAGS', '\\Seen')

            return emails

        self.error = "Failed to retreive emails."
        return emails

    def parse_email_address(self, email_address):
        """
        Helper function to parse out the email address from the message

        return: tuple (name, address). Eg. ('John Doe', 'jdoe@example.com')
        """
        return email.utils.parseaddr(email_address)


def send_massege(files, recipients, user, password):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = SUBJECT
    msg['From'] = 'Python script <' + user + '>'
    msg['To'] = recipients
    msg['Reply-To'] = user
    msg['Return-Path'] = user
    msg['X-Mailer'] = 'Python/ ' + (python_version())

    part_text = MIMEText(TEXT, 'plain')
    part_html = MIMEText(HTML, 'html')

    msg.attach(part_text)
    msg.attach(part_html)

    for file in files:
        filepath = file
        basename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)

        part_file = MIMEBase('application', 'octet-stream; name="{}"'.format(basename))
        part_file.set_payload(open(filepath, "rb").read())
        part_file.add_header('Content-Description', basename)
        part_file.add_header('Content-Disposition', 'attachment; filename="{}"; size={}'.format(basename, filesize))
        encoders.encode_base64(part_file)
        msg.attach(part_file)

    mail = smtplib.SMTP_SSL(SERVER, 465)
    mail.login(user, password)
    mail.sendmail(user, recipients, msg.as_string())
    mail.quit()


def sanitize_key(key):
    list_string = key.split(r'\n')
    return f"{SEPARATOR.join(list_string)}"


def get_hash(path_to_the_file):
    h = SHA256.new()
    with open(path_to_the_file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h


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
@click.option(
    "--password", prompt=True, hide_input=True,
    confirmation_prompt=True
)
def encode(password):
    click.echo(f"encoded: {codecs.encode(password, 'rot13')}")


@click.command()
@click.option('-m', '--mail', prompt='Address from which you want to send an email.', type=click.STRING,
              help=f'Enter the address.', default='Iaro5laI3@yandex.ru')
@click.password_option()
@click.option('-p_public', '--path_public_key', default=os.path.join(os.getcwd(), PUBLIC_KEY),
              prompt='Enter path to public key or public key directly',
              type=click.Path(exists=True, dir_okay=False, readable=True), help=f'Path to public key.')
@click.option('-p_file', '--path_file', default=os.path.join(os.getcwd(), FILE), prompt='Enter path to file',
              type=click.Path(exists=True, dir_okay=False, readable=True), help=f'Path to file.')
@click.option('-p_signature', '--path_signature', default=os.path.join(os.getcwd(), SIGNATURE),
              prompt='Enter path to signature', type=click.Path(exists=True, dir_okay=False, readable=True),
              help=f'Path to signature.')
@click.option('-r', '--recipient', prompt='Recipient.', type=click.STRING, help=f'Enter the recipient.',
              default='Iaro5laI3@yandex.ru')
def send(mail, password, path_public_key, path_file, path_signature, recipient):
    send_massege(
        files=(path_public_key, path_file, path_signature),
        recipients=recipient,
        user=mail,
        password=password
    )


@click.command()
@click.option('-m', '--mail', prompt='Address from which you want to send an email.', type=click.STRING,
              help=f'Enter the address.', default='Iaro5laI3@yandex.ru')
@click.password_option()
@click.option('-p_file', '--path', default=os.path.join(os.getcwd(), 'Download/'), prompt='Enter path to save',
              type=click.Path(exists=False, dir_okay=True, readable=True), help=f'Path to file.')
def get(mail, password, path):
    a = FetchEmail(mail_server=SERVER_, username=mail, password=password)
    a.save_attachment(a.fetch_unread_messages()[0], path)


@click.group()
def cli():
    pass


cli.add_command(public_key)
cli.add_command(private_key)
cli.add_command(sign)
cli.add_command(verify)
cli.add_command(send)
cli.add_command(get)


if __name__ == '__main__':
    cli()
