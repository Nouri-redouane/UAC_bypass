# UAC_bypass
This python script is the implementation of the UAC (User Account Control) bypass by exploiting a vulnerability in the fodhelper.exe (a legitimate Windows binary responsible for handling Features on Demand).

Supported windows versions: __7, 8, 2008, 2012, 10__.

# Testing platform 
OS Name: `Microsoft Windows 10 Pro`.  
OS Version: `10.0.19045 N/A Build 19045`.  
Windows Real-Time protection: `Off`.  
I tested it with the `On` option to open the command prompt as an administrator but the command prompt shows for less then 03 seconds and got closed by windows defender.

# How to use
```bash
git clone https://github.com/Nouri-redouane/UAC_bypass
cd UAC_bypass
python UAC_bypass_fodhelper.py "your command here"
python UAC_bypass_fodhelper_cleaner.py
```

> [!TIP]
> when you finish using the bypass script, run the cleaner script to remove any thing modified by the bypass script to prevent changing the behaviour of other legitime functions on windows that needs the modified settings.

# Usage examples
Open command prompt with administrator privilege:  
python UAC_bypass_fodhelper.py C:\Windows\System32\cmd.exe  
Or  
python UAC_bypass_fodhelper.py "PowerShell Start-Process -Verb RunAs cmd.exe"

# Disclaimer
> [!IMPORTANT]  
> This script is provided for educational, informational and ethical hacking purposes.  
> The intent of creating and sharing this script is to enhance knowledge and understanding of cybersecurity and ethical hacking.  
> Use this script responsibly and only on systems for which you have explicit permission.  
> The author is not responsible for any misuse, damage, or legal consequences that may arise from using this script.  
> By using this script, you agree to do so at your own risk.

