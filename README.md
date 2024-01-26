# UAC_bypass
this python script is the implementation of the UAC (User Account Control) bypass by exploiting a vulnerability in the fodhelper.exe (a legitimate Windows binary responsible for handling Features on Demand).

supported windows versions: 7, 8, 2008, 2012, 10.

# Testing platform 
OS Name: Microsoft Windows 10 Pro
OS Version: 10.0.19045 N/A Build 19045
Windows Real-Time protection: Off

# How to use

```bash
git clone https://github.com/Nouri-redouane/UAC_bypass
cd UAC_bypass
python UAC_bypass_fodhelper.py "your command here"
```

# Usage example
Open cmd with administrator privilege:
python UAC_bypass_fodhelper.py "C:\Windows\System32\cmd.exe"

Execute commands that require administrator privilege directly:
python UAC_bypass_fodhelper.py "regedit"
