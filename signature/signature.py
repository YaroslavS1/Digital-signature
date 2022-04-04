import os

# import click
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

# from fetch_email import DOWNLOAD
from fetch_email import FetchEmail
from helpers import get_hash
from send_email import send_email as send_email_

PRIVATE_KEY = 'private_key.pem'
PUBLIC_KEY = 'public_key.pem'

FILE = 'example.txt'
SIGNATURE = 'signature.sgn'


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

    print(f'Signature saved - {path_signature}')


def verify(path_public_key, path_file, path_signature):
    """Verify signature."""
    try:
        f_key = open(path_public_key, 'r')
        pubkey = RSA.import_key(f_key.read())
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
        print(f'Подпись для файла {path_file} не действительна')
    else:
        print(f'Подпись для файла {path_file} действительна')


def public_key(path_private_key, path_public_key):
    """Create a public key from a private key."""
    try:
        f = open(path_private_key, 'r')
        key = RSA.import_key(f.read())
    except FileNotFoundError:
        raise FileNotFoundError('Приватный ключ не найден')

    pubkey = key.publickey()
    repr_pubkey = pubkey.export_key('PEM')
    f = open(path_public_key, 'wb')
    f.write(repr_pubkey)
    f.close()

    print(f'Публичный ключь созранен по адресу - {path_public_key}\n'
          f'{repr_pubkey.decode("utf-8")}')


def private_key(path):
    """Create private key."""
    key = RSA.generate(1024, os.urandom)
    repr_key = key.export_key('PEM')
    f = open(path, 'wb')
    f.write(repr_key)
    f.close()

    print(f'Приватный ключь созранен по адресу - {path}\n'
          f'{repr_key.decode("utf-8")}')


def send_email(mail, password, path_public_key, path_file, path_signature, recipient):
    """Send email with file, public key and digital signature"""
    send_email_(
        files=(path_public_key, path_file, path_signature),
        recipients=recipient,
        user=mail,
        password=password)


def fetch_email(mail, password, path):
    """Save the file, public key and signature from the last email to a folder"""
    walker = FetchEmail(username=mail, password=password)
    msgs = walker.fetch_unread_messages()[0]
    walker.save_attachment(msgs, path)


def cli():
    print(f'Выбирете команду:\n'
          f'1 - Создать приватный ключь\n'
          f'2 - Создать публичный ключ\n'
          f'3 - Подписать'
          f'4 - Отправить письмо\n'
          f'5 - Получить письмо\n'
          f'6 - Проверить подпись\n'
          f'0 - Выйти')
    key = int(input())
    if key == 1:
        print('Введите путь куда хотите сохранить приватный ключь')
        path = input()
        private_key(path)
        cli()
    elif key == 2:
        print('Введите путь до приватного ключа')
        path_privat = input()
        print('Введите путь куда хотите сохранить приватный ключь')
        path_public = input()
        public_key(path_privat, path_public)
        cli()
    elif key == 3:
        print('Введите путь до приватного ключа')
        path_privat = input()
        print('Введите путь до файла')
        path_file = input()
        print('Введите путь по которому хотите сохранить подпись')
        path_sign = input()
        sign(path_privat, path_file, path_sign)
        cli()
    elif key == 4:
        print('Введите адрес электронной почты с которого хотите отправить письмо')
        mail = input()
        print('Пароль')
        passord = input()
        print('Введите путь до приватного ключа')
        path_private = input()
        print('Введите путь до файла')
        path_file = input()
        print('Введите путь до подписи')
        path_sign = input()
        print('Введите почту куда отправить')
        mail_ = input()
        send_email(mail, passord, path_private, path_file, path_sign, mail_)
        cli()
    elif key == 5:
        print('Введите адрес электронной почты')
        mail = input()
        print('Пароль')
        passord = input()
        print('Введите куда сохранить файлы полученные поп почте')
        path = input()
        fetch_email(mail, passord, path)
        cli()
    elif key == 6:
        print('Введите путь до приватного ключа')
        path_privat = input()
        print('Введите путь до файла')
        path_file = input()
        print('Введите путь по которому хотите сохранить подпись')
        path_sign = input()
        verify(path_privat, path_file, path_sign)
        cli()
    elif key == 0:
        return None
