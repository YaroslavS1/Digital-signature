# Signature
## A simple script that implements a digital signature

# Installation

## install virtualenv
```console
python -m venv venv
```

### Windows
```console
.\venv\Scripts\activate
```
### Linux/Mac OS
```console
source venv/bin/activate
```
## install signature
```console
pip install -e ./signature  
```
# Usage
## Main command groups
```
Usage: signature [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  fetch-email  Save the file, public key and signature from the last...
  private-key  Create private key.
  public-key   Create a public key from a private key.
  send-email   Send email with file, public key and digital signature
  sign         Sign file with digital signature.
  verify       Verify signature.
```
### private-key
```
Usage: signature private-key [OPTIONS]

  Create private key.

Options:
  -p, --path FILE  Path to save private key.
  --help           Show this message and exit.
```
### private-key
```
Usage: signature public-key [OPTIONS]

  Create a public key from a private key.

Options:
  -p_private, --path_to_private_key FILE
                                  Path to private key.
  -p_public, --path_to_public_key FILE
                                  Path to save public key.
  --help                          Show this message and exit.

```
### sign
```
Usage: signature sign [OPTIONS]

  Sign file with digital signature.

Options:
  -p_private, --path_to_private_key FILE
                                  Path to private key.
  -p_file, --path_to_the_file FILE
                                  Path to file.
  -p_signature, --path_to_the_signature FILE
                                  Path to save signature.
  --help                          Show this message and exit.
```
### fetch-email
```
Usage: signature fetch-email [OPTIONS]

Save the file, public key and signature from the last email to a folder

Options:
-m, --mail TEXT       Enter the address from which you want to download
files.
--password TEXT
-p_file, --path PATH  Path to save.
--help                Show this message and exit.
```
### send-email
```
Usage: signature send-email [OPTIONS]

  Send email with file, public key and digital signature

Options:
  -m, --mail TEXT                 Enter the email.
  --password TEXT
  -p_public, --path_public_key FILE
                                  Path to public key.
  -p_file, --path_file FILE       Path to file.
  -p_signature, --path_signature FILE
                                  Path to signature.
  -r, --recipient TEXT            Recipient's mail.
  --help                          Show this message and exit.
```
### verify
```
Usage: signature verify [OPTIONS]

  Verify signature.

Options:
  -p_public, --path_to_public_key TEXT
                                  Path to public key or public key directly.
  -p_file, --path_to_the_file FILE
                                  Path to file.
  -p_signature, --like_signature FILE
                                  Path to signature.
  --help                          Show this message and exit.
```