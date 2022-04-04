from setuptools import setup, find_packages

setup(
    name='signature',
    version='0.1.0',
    py_modules=['signature'],
    # packages=find_packages('fetch_email'),
    install_requires=[
        'Click',
        'pycryptodome'
    ],
    entry_points={
        'console_scripts': [
            'signature = signature:cli',
        ],
    },
)
