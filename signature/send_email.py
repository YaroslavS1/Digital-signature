import os
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from platform import python_version

__all__ = ['send_email']

SERVER = 'smtp.yandex.ru'
SUBJECT = 'ЭЦП'
TEXT = 'ЭЦП'
HTML = '<html><head></head><body><p> ' + TEXT + '</p></body></html>'


def send_email(files, recipients, user, password):
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
