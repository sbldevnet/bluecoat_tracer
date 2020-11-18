# Symantec Advanced Security Gateway Tracert Tool (Blue Coat Proxy)
# `WORK IN PROGRESS`

## Table of contents
- [Description](#description)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Requirements](#requirements)
- [Contribute](#contribute)
- [License](#license)

## Description
CLI tool for policy lookups in Symantec Advanced Security Gateway.
It allows you to easily locate the rule in the policy that matches the input parameters (Source/Destination IP, domain, proxy port, authentication method, etc).


## Features
* Show policy rules that match with a source IP.
* `WIP` Show policy rules that match with a destination URL.
* `WIP` Show policy rules that match with a source IP and destination URL.
* List and select authentication method.
* Select explicit proxy port.
* List and download the desired policy version.


## Installation
```bash
pip install -r requirements.txt
```


## Usage
1. Edit `vars.py` and modify variables.
2. Execute CLI
```bash
python3 bluecoat_tracer.py
```
3. Interact with menu
`picture`


## Requirements

#### Offline mode
* python3 & requirements file installed.
* xml proxy policy.

#### Online mode
* python3 & requirements file installed.
* xml proxy policy (can be downloaded with the script).
* Network access to Symantec Management Center and user with API permissions.
* Network access to Symantec Proxy Management Console and user with read permissions.


## Contribute
Contributions are always welcome!
`WIP` CICD test and python quality code.


## License
The code in this repository is under GNU General Public License v3.0
