import codecs
import os
from setuptools import setup


def read(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, rel_path), 'r') as fp:
        return fp.read()


def get_version(rel_path):
    for line in read(rel_path).splitlines():
        if line.startswith('__version__'):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    else:
        raise RuntimeError("Unable to find version string.")


setup(
    name="scanoss",
    version=get_version("src/scanoss/__init__.py"),
    author="SCANOSS",
    author_email="info@scanoss.com",
    license='MIT',
    description='Simple Python library to use the SCANOSS APIs.',
    long_description=read("PACKAGE.md"),
    long_description_content_type='text/markdown',
    install_requires=["requests",  # TODO Add min req for python 3.10 here - urllib3>=1.26.8 and requests>=2.27.0?
                      "crc32c>=2.2", "binaryornot", "progress", "grpcio<=1.42.0",
                      "protobuf>=3.16.0,<=3.19.1"
                      ],
    include_package_data=True,
    package_data={'': ['data/*.json', 'data/*.txt']},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent"
    ],
    python_requires='>=3.7'
)
