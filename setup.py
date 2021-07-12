import codecs
import os
from setuptools import setup, find_packages


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
    license='GPL 2.0 or later',
    description='Simple Python library to use the SCANOSS APIs.',
    long_description=read("PACKAGE.md"),
    long_description_content_type='text/markdown',
    install_requires=["requests", "crc32c", "binaryornot", "progress"],
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent"
    ],
    python_requires='>=3.6'
)
