# SCANOSS Python Package
The SCANOSS python package provides a simple easy to consume library for interacting with SCANOSS APIs/Engine.

To install, please run:
````
pip3 install -r requirements.txt
````

# Usage
The package can be run from the command line, or consumed from another Python script.

## CLI Usage
The Python package manager (pip), will register the following command during installation:
````
scanoss-py
````
It is also possible to launch it using:
````
python3 -m scanoss.cli
````

Running the bare command will list the available commands:
````
> scanoss-py

usage: scanoss-py [-h] {version,ver,scan,sc,fingerprint,fp,wfp} ...

SCANOSS Python CLI. Ver: 0.2.0, License: GPL 2.0-or-later

optional arguments:
  -h, --help            show this help message and exit

Sub Commands:
  valid subcommands

  {version,ver,scan,sc,fingerprint,fp,wfp}
                        sub-command help
    version (ver)       SCANOSS version
    scan (sc)           Scan source code
    fingerprint (fp, wfp)
                        Fingerprint source code

````

From there it is possible to scan a source code folder:

````
> scanoss-py scan -o scan-output.json <source-folder>
````

## Scanning URL
By Default, scanoss uses the API URL endpoint for SCANOSS OSS KB: https://osskb.or/api/scan/direct.

## Requirements
Python 3.6 or higher.

