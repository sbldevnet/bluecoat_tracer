# Symantec Advanced Security Gateway Tracert Tool (Blue Coat Proxy)

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
* Dispalys the policy rules that match with a source IP.
* `WIP` Displays the policy rules that match with a destination URL.
* Displays the policy rules that match with a source IP and destination URL.
* List and select authentication method.
* Select explicit proxy port.
* List and download the desired policy version.


## Installation
```bash
pip install -r requirements.txt
```


## Usage
1. Edit `vars.py` and modify variables.
2. Execute python script
```bash
python3 bluecoat_tracer.py
```
3. Interact with menu
```bash
[GLOBAL VARIABLES]
Auth method: 
Proxy Port: 8080
Exclude layers: ['Layer_Test']

[OPTIONS]
[1]: Search source IP match
[2]: [WIP] Search destination (IP/FQDN/URL)
[3]: Search source/destination
[4]: Get / Select authentication
[5]: Select proxy port
[6]: Download policy xml
[0]: Exit
Select Option: 
```


## Requirements

#### Offline mode [WIP]
`vars.py`
```python3
ONLINE = False
```
* python3 & requirements file installed.
* xml proxy policy.

#### Online mode
`vars.py`
```python3
ONLINE = True
```
* python3 & requirements file installed.
* xml proxy policy (can be downloaded with the script).
* Network access to Symantec Management Center and user with API permissions.
* Network access to Symantec Proxy Management Console and user with read permissions.


## Contribute
Contributions are always welcome!

`WIP` CICD test and python quality code.


## License
The code in this repository is under GNU General Public License v3.0
