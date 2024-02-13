<img src='./ico/icona.png' align=right style='border-radius:50%;width:40px;'>
<center>

# Scannort
<h5 align=center style='margin-right:35px'>A network port scanner</h5>
</center>


<pre style="color:red;text-align:center">
  ██████  ▄████▄   ▄▄▄       ███▄    █  ███▄    █  ▒█████   ██▀███  ▄▄▄█████▓
▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █  ██ ▀█   █ ▒██▒  ██▒▓██ ▒ ██▒▓  ██▒ ▓▒
░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒▓██  ▀█ ██▒▒██░  ██▒▓██ ░▄█ ▒▒ ▓██░ ▒░
  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒▓██▒  ▐▌██▒▒██   ██░▒██▀▀█▄  ░ ▓██▓ ░ 
▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░▒██░   ▓██░░ ████▓▒░░██▓ ▒██▒  ▒██▒ ░ 
▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░  ▒ ░░   
░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░░ ░░   ░ ▒░  ░ ▒ ▒░   ░▒ ░ ▒░    ░    
░  ░  ░  ░          ░   ▒      ░   ░ ░    ░   ░ ░ ░ ░ ░ ▒    ░░   ░   ░      
      ░  ░ ░            ░  ░         ░          ░     ░ ░     ░              
         ░                                                                   
</pre>

<br>
<br>

## Introduction

Scannort is an interactive Pyhton script that allow you To:
* Scan hosts for open ports fast using threads
* Suggest an **nmap** scan based on the results
* Customise you nmap arguments if needed
* Run the scan and store the results

## Requirements

Almost no requirements except Python3 must be installed on 	your system, the `` requirements.txt `` file says everything :)

## Install Options

#### install it via ```pip/pip3```:

```console
$ pip install git+https://github.com/0x00650a/Scannort.git
```
#### Clone it 
```console
$ git clone https://github.com/0x00650a/Scannort.git
$ cd Scannort
$ pip install .
```
#### Script Only
```console
$ git clone https://github.com/0x00650a/Scannort.git 
$ cd Scannort
$ [sudo] cp $(pwd)/src/Scannort.py /usr/local/bin/Scannort.py
```
## Uninstall
#### Uninstall it with pip
```console
$ pip uninstall Scannort
```
## How to use it
Just type the command:
```console
$ Scannort
```
And follow the prompts to enter the target IP address/url, and explore the suggested Nmap scans based on the initial port scan results.
## Issues
If you encounter any problems, please report them on our <a href="https://github.com/0x00650a/Scannort/issues">GitHub Issues</a> page.
## Contributions
Your contribution and feedback are highly appreciated! :)