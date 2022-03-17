from Crypto.Hash import SHA256

__all__ = [
    'sanitize_key',
    'get_hash'
]

SEPARATOR = '\n'


def sanitize_key(key):
    list_string = key.split(r'\n')
    return f"{SEPARATOR.join(list_string)}"


def get_hash(path_to_the_file):
    hash_value = SHA256.new()
    with open(path_to_the_file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_value.update(chunk)
    return hash_value
