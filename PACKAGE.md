# SCANOSS Python Package
The SCANOSS python package provides a simple easy to consume library for interacting with SCANOSS APIs/Engine.

## Installation
To install (from [pypi.org](https://pypi.org/project/scanoss)), please run:
```bash
pip3 install scanoss
```
To upgrade an existing installation please run:
```bash
pip3 install --upgrade scanoss
```

### Docker
Alternatively, there is a docker image of the compiled package. It can be found [here](https://github.com/scanoss/scanoss.py/pkgs/container/scanoss-py).
Details of how to run it can be found [here](https://github.com/scanoss/scanoss.py/blob/main/GHCR.md).

## Usage
The package can be run from the command line, or consumed from another Python script.

### CLI Usage
The Python package manager (pip), will register the following command during installation:
```bash
scanoss-py
```
It is also possible to launch it using:
```bash
python3 -m scanoss.cli
```

Running the bare command will list the available sub-commands:
```bash
> scanoss-py

usage: scanoss-py [-h] {version,ver,scan,sc,fingerprint,fp,wfp,dependencies,dp,dep} ...

SCANOSS Python CLI. Ver: 0.9.0, License: MIT

optional arguments:
  -h, --help            show this help message and exit

Sub Commands:
  valid subcommands

  {version,ver,scan,sc,fingerprint,fp,wfp,dependencies,dp,dep}
                        sub-command help
    version (ver)       SCANOSS version
    scan (sc)           Scan source code
    fingerprint (fp, wfp)
                        Fingerprint source code
    dependencies (dp, dep)
                        Scan source code for dependencies
```

From there it is possible to scan a source code folder:

````bash
> scanoss-py scan -o scan-output.json <source-folder>
````

#### Scanning for Dependencies
The SCANOSS CLI supports dependency decoration. In order for this to work, it requires the installation of scancode:
```python
pip install scancode-toolkit
```
Dependencies can then be decorated by adding the ``--dependencies`` option to the scanner:
```bash
> scanoss-py scan --dependencies -o scan-output.json <source-folder>
```

### Package Usage
The **scanoss** package can also be used in other Python projects/scripts. A good example of how to consume it can be found [here](https://github.com/scanoss/scanoss.py/blob/main/src/scanoss/cli.py).

In general the easiest way to consume it is to import the required module as follows:
```python
from scanoss.scanner import Scanner

def main():
    scanner = Scanner()
    scanner.scan_folder( '.' )
    
if __name__ == "__main__":
    main()
```

## Scanning URL and API Key
By Default, scanoss uses the API URL endpoint for SCANOSS OSS KB: https://osskb.org/api/scan/direct.
This API does not require an API key.

These values can be changed from the command line using:
```bash
> scanoss-py scan --apiurl <URL> --key <KEY>
```

From code, it would look like this:
```python
from scanoss.scanner import Scanner

def main():
    scanner = Scanner(url='new-url', api_key='key')
    scanner.scan_folder( '.' )
    
if __name__ == "__main__":
    main()
```

## Requirements
Python 3.7 or higher.

## Source code
The source for this package can be found [here](https://github.com/scanoss/scanoss.py).

## Changelog
Details of each release can be found [here](https://github.com/scanoss/scanoss.py/blob/main/CHANGELOG.md).
