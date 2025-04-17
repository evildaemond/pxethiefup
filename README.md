# PXEThiefUp

PXEThief up is a modification of the original PXEThief by MWR-Cybersec to allow for a few new functions and fixing some existing issues. 


## Features
### Tested and verified features
- Works with offline media
    - `variables.dat`
    - `variables.dat` and `policy.xml`
    - `.iso` (when searching via folders)
- Parses all output into the working directory `/loot/`, structured per SCCM instance
- Blank and Weak Password validation testing
- Automatic identification of wrong type of variables
- Better hash output with specific commands and version required linked
- Slightly better text output
    - NAA Accounts mainly

### Need to verify
- Slightly better PXE server identification
- PXE Device Authorisation Detection
- Task Secret Scanning

### Todo
- WIM and virtual machine secret scanning
- Automatic validation of credentials
- SMB File Looting
- Automatic Machine Account addition for Policies extraction outside of SCCM

## Usage Instructions

### Coersion and Scanning

**Automatically scan across a network for PXE bootable devices and download the media variables file:**
```bash
python3 pxethiefup.py -a
python3 pxethiefup.py --auto
```

**Coerce a PXE boot against a specific MECM Distribution Point server:**
```bash
python3 pxethiefup.py -m -t 10.1.1.2
python3 pxethiefup.py --manual -target 10.1.1.2
```

### Decryption

**Search a folder for files and decrypt them (including ISO) and decrypt it:**
```bash
python pxethiefup.py -d -f "..\folder\"
python pxethiefup.py --decrypt -f "..\isoFolder\"
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

### Hashcat

**Display the hash corresponding to a media variables file for cracking in hashcat:**
```bash
python3 pxethiefup.py -c -vf variables.xml
python3 pxethiefup.py --crack --variables variables.xml
```

## Related work

- [Identifying and retrieving credentials from SCCM/MECM Task Sequences](https://www.mwrcybersec.com/research_items/identifying-and-retrieving-credentials-from-sccm-mecm-task-sequences) 
    - In this post, I explain the entire flow of how ConfigMgr policies are found, downloaded and decrypted after a valid OSD certificate is obtained. I also want to highlight the first two references in this post as they show very interesting offensive SCCM research that is ongoing at the moment.

- [DEF CON 30 Slides](https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Christopher%20Panayi%20-%20Pulling%20Passwords%20out%20of%20Configuration%20Manager%20Practical%20Attacks%20against%20Microsofts%20Endpoint%20Management%20Software.pdf) 
    - Link to the talk slides

## Original Source of the now modified tool

<https://github.com/MWR-CyberSec/PXEThief>




## Random future improvement notes

## SCCM service detection for Servers

- Domain: 53
- SMB: 
- MSSQL:
- HTTP:
- HTTPS: 

https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/sccm-mecm/recon
- 8530, 8531, 10123 - Site Server, Management Point
- 49152-49159 - Distribution Point
- UDP = 4011 - Operating System Deployment (OSD)

SCCM search
nmap -p 80,443,445,1433,10123,8530,8531 -sV [IP]

Search PXE
nmap -p 67,68,69,4011,547 -sV -sU [IP]


## Validation of credentials during processing
- NAA to LDAP or SMB on SCCM
    - Verify Permissions/Groups?
        - Domain Users
        - Interactive Login
        - DA - LMAO
    - Quick Enum?
- MSSQL
    - Can login?

## SMB Share

- REMINST
- SCCMCONTENTLIB$
- SMSPKG$
- SMSSIG$
- WSUSContent

- 

## HTTP

https://github.com/badsectorlabs/sccm-http-looter/blob/main/DEFCON32_RTV_How-Ludus-made-it-rain-creds-from-SCCM.pdf
- /SMS_DP_SMSPKG$/datalib

- https://github.com/badsectorlabs/sccm-http-looter/tree/main


## MNT Virtual Machine files

- /Windows/Windows/System32/Config
    - SAM/HIVE
        - impacket-seretsdump -system SYSTEM -sam SAM LOCAL

