#!/usr/bin/python3

# Scannort - Multi-threader Port Scanner
# A project by L-yagami 
# v1.0.1


import socket
import os
import signal
import time
import threading
import sys
import re
import subprocess
from queue import Queue
from datetime import datetime

# Colors variables
CRED = '\33[91m'
CBLE = '\33[94m'
CGRN = '\033[32m'
CYLW = '\033[93m'
CRPL = '\033[0;35m'
PRPL = '\033[95m'
CYAN = '\033[36m'
CEND = '\033[0m'
TBLD = '\033[1m'
UDRL = '\033[4m'

# Which Function
def which(cmd, mode=os.F_OK | os.X_OK, path=None):
    use_bytes = isinstance(cmd, bytes)
    # If we're given a path with a directory part, look it up directly rather
    # than referring to PATH directories. This includes checking relative to
    # the current directory, e.g. ./script

    dirname, cmd = os.path.split(cmd)
    if dirname:
        path = [dirname]
    else:
        if path is None:
            path = os.environ.get("PATH", None)
            if path is None:
                try:
                    path = os.confstr("CS_PATH")
                except (AttributeError, ValueError):
                    path = os.defpath
            # Don't use os.defpath if the PATH environment variable
            # is set to an empty string

        # PATH='' doesn't match, whereas PATH=':' looks in the current
        # directory
        if not path:
            return None

        if use_bytes:
            path = os.fsencode(path)
            path = path.split(os.fsencode(os.pathsep))
        else:
            path = os.fsdecode(path)
            path = path.split(os.pathsep)

        if sys.platform == "win32" and _win_path_needs_curdir(cmd, mode):
            curdir = os.curdir
            if use_bytes:
                curdir = os.fsencode(curdir)
            path.insert(0, curdir)

    if sys.platform == "win32":
        pathext_source = os.getenv("PATHEXT") or _WIN_DEFAULT_PATHEXT
        pathext = [ext for ext in pathext_source.split(os.pathsep) if ext]

        if use_bytes:
            pathext = [os.fsencode(ext) for ext in pathext]

        files = ([cmd] + [cmd + ext for ext in pathext])

        suffix = os.path.splitext(files[0])[1].upper()
        if mode & os.X_OK and not any(suffix == ext.upper() for ext in pathext):
            files.append(files.pop(0))
    else:
        files = [cmd]

    seen = set()
    for dir in path:
        normdir = os.path.normcase(dir)
        if not normdir in seen:
            seen.add(normdir)
            for thefile in files:
                name = os.path.join(dir, thefile)
                if _access_check(name, mode):
                    return name
    return None

# Access check
def _access_check(fn, mode):
    return (os.path.exists(fn)
            and os.access(fn, mode)
            and not os.path.isdir(fn))

# Main Function
def main():
    scannort(True)

# Main Scannort
def scannort(first_run):
    def cbanner():
        
        bfont = """
{BANNER_C}
  ██████  ▄████▄   ▄▄▄       ███▄    █  ███▄    █  ▒█████   ██▀███  ▄▄▄█████▓
▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █  ██ ▀█   █ ▒██▒  ██▒▓██ ▒ ██▒▓  ██▒ ▓▒
░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒▓██  ▀█ ██▒▒██░  ██▒▓██ ░▄█ ▒▒ ▓██░ ▒░
  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒▓██▒  ▐▌██▒▒██   ██░▒██▀▀█▄  ░ ▓██▓ ░ 
▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░▒██░   ▓██░░ ████▓▒░░██▓ ▒██▒  ▒██▒ ░ 
▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░  ▒ ░░   
░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░░ ░░   ░ ▒░  ░ ▒ ▒░   ░▒ ░ ▒░    ░    
░  ░  ░  ░          ░   ▒      ░   ░ ░    ░   ░ ░ ░ ░ ░ ▒    ░░   ░   ░      
      ░  ░ ░            ░  ░         ░          ░     ░ ░     ░              
         ░                                                                   """.format(BANNER_C=CRED)
        bfont += CEND
        print(bfont)
        print(CYAN + "-" * 75)
        print("                {}Scannort{}{} - Multi-threaded Port Scanner ".format(TBLD, CEND, CYAN))
        print("                 __________ Version 1.0.1 __________")
        print("                           \\-------------/  ")
        print("-" * 75 + CEND)

    socket.setdefaulttimeout(0.50)
    print_lock = threading.Lock()
    discovered_ports = []

    # Welcome Banner
    print()
    if first_run:
        cbanner()
    else:
        print("-" * 75)
        print("-" * 75)

    utils = ["nmap"]
    neededU = []
    for util in utils:
        if which(util) is None:
            neededU.append(util)

    time.sleep(0.5)

    url_pattern = r"(?:(?:ftp|http|https)?://)?(([a-zA-Z0-9\-]+\.)+([a-zA-Z0-9])+)"
    ip_pattern = r"(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))\.(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))\.(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))\.(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))"

    error = (CYLW + TBLD + "["+ CRED + "!" + CYLW + "]" + CEND + CYLW + "Invalide input")
    while True:
        t_inpt = input("{}Enter The target IP address or URL here:{} ".format('\x1b[0;34;40m' ,CEND))

        try:
            target = re.search(url_pattern, t_inpt).group(1)
            t_ip = socket.gethostbyname(target)
            break
        except (AttributeError, UnboundLocalError, socket.gaierror):
            try:
                target = re.search(ip_pattern, t_inpt).group()
                t_ip = socket.gethostbyname(target)
                break
            except (AttributeError, UnboundLocalError, socket.gaierror):
                print("\n" + TBLD + CYLW + "[!]" + CEND + " Invalid format. Please use a correct IP or web address[-]\n")

    #Banner
    print("-" * 75)
    NOfThreads = 256
    print("Scanning target [ " + PRPL + TBLD + t_ip + CEND + " ]")
    print("{}Do you want to change the number of threads (Default is {}{}{}{}) ?{} (y, n) ".format(CBLE, TBLD,CGRN,NOfThreads,CEND,CEND), end='')
    NT_resp = input()
    #NT_resp = input("Default number of threads is <" + TBLD + CGRN + str(NOfThreads) + CEND + ">. {}Do you want to change it ?{} (y, n) ".format(CBLE, CEND))
    if 'y' in NT_resp.lower():
        try:
            NOfThreads = int(input("{}Enter number of threads:{} ".format(CBLE, CEND)))
        except:
            print(TBLD + CYLW + " !" + CEND + " Invalide Input. The script will continue with the default parameter.")

    
    print("Time started: "+ str(datetime.now()))
    print("-" * 75)
    t1 = datetime.now()

    def portscan(port):

       s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       
       try:
          portx = s.connect((t_ip, port))
          with print_lock:
             print("Port {COL}{T}{pt}{CFIN} is open".format(COL=CGRN, T=TBLD, pt=port, CFIN=CEND))
             discovered_ports.append(str(port))
          portx.close()

       except (ConnectionRefusedError, AttributeError, OSError):
          pass

    def tscanner():
       while True:
          worker = q.get()
          portscan(worker)
          q.task_done()
      
    q = Queue()
     
    for x in range(NOfThreads):
       t = threading.Thread(target = tscanner)
       t.daemon = True
       t.start()

    for worker in range(1, 65536):
       q.put(worker)

    q.join()

    t2 = datetime.now()
    total = t2 - t1
    print("Port scan completed in " + str(total))
    print("-" * 75)
    if neededU: 
        print(CYAN + "The following utils are needed to continue ", end=CRPL)
        print(", ".join(neededU), end=CYAN+'\n')
        print("Suggested solutions :", end=CEND+'\n')
        print("[+]>          {COL}sudo apt install [util]{CEND}".format(COL=CYLW, CEND=CEND))
        print("[+]>          {COL}pip3 install [util]{CEND}".format(COL=CYLW, CEND=CEND))
        sys.exit()
    
    print("-" * 75)
    print("{}Scannort recommends the following Nmap scan:{}".format(CYAN, CEND))
    print("*" * 75)
    nmap = "nmap -p{ports} -sV -sC -T4 -Pn -oN {ip}-{tm} {ip}".format(ports=",".join(discovered_ports), tm=datetime.now(), ip=target)
    print(CYLW + nmap + CEND)
    print("*" * 75)
    t3 = datetime.now()
    total1 = t3 - t1

#Nmap Integration (in progress)

    def automate(nmap):
        choice = '0'
        while choice =='0':
            print("What would you do next ?")
            print("-" * 75)
            print("{}{}1{} = Run The suggested nmap scan".format(CGRN, TBLD, CEND))
            print("{}{}2{} = Run with other parameters".format(CGRN, TBLD, CEND))
            print("{}{}3{} = Run another Scannort scan".format(CGRN, TBLD, CEND))
            print("{}{}4{} = Exit to terminal".format(CGRN, TBLD, CEND))
            print("-" * 75)
            choice = input(CBLE + "Select an option: " + CEND)
            if choice == "1":
                try:
                    print('\n' + CYLW + nmap, end=CEND+"\n\n")
                    os.mkdir(target)
                    os.chdir(target)
                    os.system(nmap)
                    t3 = datetime.now()
                    total1 = t3 - t1
                    print("-" * 75)
                    print("Scannort completed in {}{}{}{}".format(CYAN, TBLD, str(total1), CEND))
                    print("Press enter to quit...")
                    input()
                except FileExistsError as e:
                    print(e)
                    exit()
            elif choice =="2":
                print("Enter your nmap parameters: (e.g: {}-sS -sC -sV -T5{})".format(CYLW,CEND))
                param = input(CBLE + " --> " + CEND)
                param = param.replace("-oA", '')
                param = re.sub('^nmap ', '', param)
                ans = input(CBLE + "Do you want to scan all the discovered ports{e} [{c}{t}{ports}{e}]? (y, n) ".format(c=CGRN,t=TBLD,ports=",".join(discovered_ports), e=CEND))
                S_ports = []
                if 'n' in ans.lower():
                    invalide_in = True
                    while invalide_in:
                        print("Set your preferred ports (e.g: {}22 80 445{}): ".format(CGRN, CEND))
                        inpS_ports = input(CBLE + " --> " + CEND)
                        try:
                            S_ports = [str(int(i)) for i in inpS_ports.split()]
                            invalide_in = False
                        except:
                            invalide_in = True
                            print(CYLW + TBLD + "["+ CRED + "!" + CYLW + "]" + CEND + CYLW + "Invalide input")
    
                else:
                    S_ports = discovered_ports
    
                nmap = "nmap -p{ports} {param} -oA {ip} {ip}".format(ports=",".join(S_ports), param=param, ip=target)
                print("-" * 75)
                print("The following command will be executed")
                print("*" * 75)
                print(CYLW + nmap + CEND)
                print("*" * 75)
                automate(nmap)
 
            elif choice =="3":
                scannort(False)
            elif choice =="4":
                sys.exit()
            else:
                print(CYLW + TBLD + "[!]" + CEND + CYLW + " Please make a valid selection" + CEND)
                automate(nmap)
    automate(nmap)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n"+TBLD + CGRN + ">Goodbye!" + CEND)
        quit()

