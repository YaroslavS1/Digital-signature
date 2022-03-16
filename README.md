# Signature
## A simple script that implements a digital signature

# Installation

## install virtualenv
```console
python -m venv venv
```
## install signature
```console
python -e ./Digital-signature
```
# Usage
```
Usage: signature [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  private-key  Create private key.
  public-key   Create a public key from a private key.
  sign         Sign file with digital signature.
  verify       Verify signature.

```
## signature private-key
```
Usage: signature private-key [OPTIONS]

  Create private key.

Options:
  -p, --path FILE  Path to save private key.
  --help           Show this message and exit.
```
## signature private-key
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
## signature sign
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
## signature verify
```
Usage: signature verify [OPTIONS]

  Verify signature.

Options:
  -p_public, --path_to_public_key TEXT
                                  Path to public key or public key directly.
  -p_file, --path_to_the_file FILE
                                  Path to file.
  -p_signature, --like_signature FILE
                                  Path to save signature.
  --help                          Show this message and exit.
```

