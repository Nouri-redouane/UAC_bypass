import subprocess

def clean_up():
    """Keys remover.

    Removes the regisry keys we added priviously in the bypass script in the exploit function to do not affect other ligitime behaviours on windows.
    """
    print("cleaning up...")
    subprocess.run("reg delete hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /f", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run('reg delete hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v "" /f', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("Done, cleaned successfully.")

if __name__ == "__main__":
    clean_up()