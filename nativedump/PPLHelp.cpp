#include "PPLHelp.h"
#include <sstream>
#include <iomanip>

// ============================================================
// GetPPLProtectionLevel
// Query the kernel protection level of an existing process.
// Uses GetProcessInformation(ProcessProtectionLevelInfo).
// ============================================================
DWORD PPLProcessCreator::GetPPLProtectionLevel(DWORD processId)
{
    DWORD protectionLevel = PROTECTION_LEVEL_NONE;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess)
    {
        std::wcerr << L"[PPL] OpenProcess(" << processId << L") failed: "
            << GetLastError() << std::endl;
        return protectionLevel;
    }

    PROCESS_PROTECTION_LEVEL_INFORMATION info = { 0 };
    if (GetProcessInformation(hProcess, ProcessProtectionLevelInfo,
        &info, sizeof(info)))
    {
        protectionLevel = info.ProtectionLevel;
    }
    else
    {
        std::wcerr << L"[PPL] GetProcessInformation failed: "
            << GetLastError() << std::endl;
    }

    CloseHandle(hProcess);
    return protectionLevel;
}

// ============================================================
// GetPPLProtectionLevelName
// ============================================================
std::wstring PPLProcessCreator::GetPPLProtectionLevelName(DWORD protectionLevel)
{
    switch (protectionLevel)
    {
    case PROTECTION_LEVEL_WINTCB_LIGHT:
        return L"PROTECTION_LEVEL_WINTCB_LIGHT (0x49)";
    case PROTECTION_LEVEL_WINTCB:
        return L"PROTECTION_LEVEL_WINTCB (0x41)";
    case PROTECTION_LEVEL_WINDOWS:
        return L"PROTECTION_LEVEL_WINDOWS (0x40)";
    case PROTECTION_LEVEL_WINDOWS_LIGHT:
        return L"PROTECTION_LEVEL_WINDOWS_LIGHT (0x48)";
    case PROTECTION_LEVEL_ANTIMALWARE_LIGHT:
        return L"PROTECTION_LEVEL_ANTIMALWARE_LIGHT (0x23)";
    case PROTECTION_LEVEL_LSA_LIGHT:
        return L"PROTECTION_LEVEL_LSA_LIGHT (0x22)";
    case PROTECTION_LEVEL_NONE:
        return L"PROTECTION_LEVEL_NONE / Not Protected";
    default:
    {
        std::wostringstream oss;
        oss << L"Unknown (0x" << std::hex << std::uppercase << protectionLevel << L")";
        return oss.str();
    }
    }
}

// ============================================================
// CreatePPLProcess
//
// Creates a protected process (PPL) using the Win32 path:
//   CreateProcessW + EXTENDED_STARTUPINFO_PRESENT
//               + CREATE_PROTECTED_PROCESS
//               + PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL
//
// Parameters:
//   protectionLevel  - one of PROTECTION_LEVEL_* SDK constants
//   commandLine      - full command line (must be mutable wstring&)
//   inheritHandles   - true = inherit open handles (needed for
//                      WerFaultSecure /file /encfile /cancel)
//   waitForExit      - true = block until child exits
//   timeoutMs        - timeout for WaitForSingleObject (INFINITE ok)
// ============================================================
bool PPLProcessCreator::CreatePPLProcess(
    DWORD         protectionLevel,
    std::wstring& commandLine,
    bool          inheritHandles,
    bool          waitForExit,
    DWORD         timeoutMs)
{
    // ----------------------------------------------------------
    // 1. Build PROC_THREAD_ATTRIBUTE_LIST with protection level
    // ----------------------------------------------------------
    SIZE_T attrSize = 0;

    // First call: query required buffer size
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    if (attrSize == 0)
    {
        // The only acceptable failure here is ERROR_INSUFFICIENT_BUFFER
        DWORD err = GetLastError();
        if (err != ERROR_INSUFFICIENT_BUFFER)
        {
            std::wcerr << L"[PPL] InitializeProcThreadAttributeList (size query) "
                L"unexpected error: " << err << std::endl;
            return false;
        }
    }

    LPPROC_THREAD_ATTRIBUTE_LIST ptal =
        reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize));
    if (!ptal)
    {
        std::wcerr << L"[PPL] HeapAlloc for attribute list failed: "
            << GetLastError() << std::endl;
        return false;
    }

    // Second call: initialize
    if (!InitializeProcThreadAttributeList(ptal, 1, 0, &attrSize))
    {
        std::wcerr << L"[PPL] InitializeProcThreadAttributeList (init) failed: "
            << GetLastError() << std::endl;
        HeapFree(GetProcessHeap(), 0, ptal);
        return false;
    }

    // Set the protection level attribute
    // NOTE: protectionLevel must stay alive for the duration of CreateProcessW.
    // We take a local copy so its address is stable.
    DWORD localProtLevel = protectionLevel;
    if (!UpdateProcThreadAttribute(
        ptal, 0,
        PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
        &localProtLevel, sizeof(localProtLevel),
        nullptr, nullptr))
    {
        std::wcerr << L"[PPL] UpdateProcThreadAttribute failed: "
            << GetLastError() << std::endl;
        DeleteProcThreadAttributeList(ptal);
        HeapFree(GetProcessHeap(), 0, ptal);
        return false;
    }

    // ----------------------------------------------------------
    // 2. Set up STARTUPINFOEXW
    // ----------------------------------------------------------
    STARTUPINFOEXW siex = { 0 };
    siex.StartupInfo.cb = sizeof(siex);
    siex.lpAttributeList = ptal;

    PROCESS_INFORMATION pi = { 0 };

    // ----------------------------------------------------------
    // 3. CreateProcessW
    //    EXTENDED_STARTUPINFO_PRESENT  — use STARTUPINFOEXW
    //    CREATE_PROTECTED_PROCESS      — request PPL
    // ----------------------------------------------------------
    DWORD creationFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS;

    std::wcout << L"[PPL] Creating PPL process..." << std::endl;
    std::wcout << L"[PPL] Command line : " << commandLine << std::endl;
    std::wcout << L"[PPL] Prot level   : "
        << GetPPLProtectionLevelName(protectionLevel) << std::endl;
    std::wcout << L"[PPL] InheritHandles: "
        << (inheritHandles ? L"yes" : L"no") << std::endl;

    if (!CreateProcessW(
        nullptr,
        const_cast<LPWSTR>(commandLine.c_str()),
        nullptr,
        nullptr,
        inheritHandles ? TRUE : FALSE,
        creationFlags,
        nullptr,
        nullptr,
        &siex.StartupInfo,
        &pi))
    {
        DWORD err = GetLastError();
        std::wcerr << L"[PPL] CreateProcessW failed: " << err << std::endl;

        // Common failure reasons:
        if (err == ERROR_INVALID_PARAMETER)
            std::wcerr << L"      → Invalid parameter (check protection level / command line)" << std::endl;
        else if (err == ERROR_ACCESS_DENIED)
            std::wcerr << L"      → Access denied (caller must have matching or higher PPL,"
            L" or be running as System/TrustedInstaller)" << std::endl;
        else if (err == 0x520) // ERROR_PRIVILEGE_NOT_HELD
            std::wcerr << L"      → SeDebugPrivilege not held" << std::endl;
        else if (err == ERROR_BAD_EXE_FORMAT)
            std::wcerr << L"      → Target binary not a valid PE" << std::endl;

        DeleteProcThreadAttributeList(ptal);
        HeapFree(GetProcessHeap(), 0, ptal);
        return false;
    }

    // ----------------------------------------------------------
    // 4. Cleanup attribute list (must be done AFTER CreateProcessW)
    // ----------------------------------------------------------
    DeleteProcThreadAttributeList(ptal);
    HeapFree(GetProcessHeap(), 0, ptal);

    // Store handles
    m_hProcess = pi.hProcess;
    m_hThread = pi.hThread;

    DWORD actualLevel = GetPPLProtectionLevel(pi.dwProcessId);
    std::wcout << L"[PPL] Process created — PID: " << pi.dwProcessId << std::endl;
    std::wcout << L"[PPL] Actual prot level: "
        << GetPPLProtectionLevelName(actualLevel) << std::endl;

    // ----------------------------------------------------------
    // 5. Optionally wait for the process to exit
    // ----------------------------------------------------------
    if (waitForExit)
    {
        std::wcout << L"[PPL] Waiting for process to exit (timeout="
            << (timeoutMs == INFINITE ? L"INFINITE" :
                std::to_wstring(timeoutMs) + L"ms")
            << L")..." << std::endl;

        DWORD waitResult = WaitForSingleObject(m_hProcess, timeoutMs);
        if (waitResult == WAIT_OBJECT_0)
        {
            DWORD exitCode = 0;
            GetExitCodeProcess(m_hProcess, &exitCode);
            std::wcout << L"[PPL] Process exited with code: 0x"
                << std::hex << std::uppercase << exitCode << std::endl;
        }
        else if (waitResult == WAIT_TIMEOUT)
        {
            std::wcerr << L"[PPL] Wait timed out after " << std::dec
                << timeoutMs << L" ms" << std::endl;
        }
        else
        {
            std::wcerr << L"[PPL] WaitForSingleObject failed: "
                << GetLastError() << std::endl;
        }
    }

    return true;
}

// ============================================================
// CreateWerFaultSecureDump
//
// High-level helper that builds the full WerFaultSecure command
// line and calls CreatePPLProcess.
//
// The three handles MUST already be:
//   - Inheritable (SetHandleInformation HANDLE_FLAG_INHERIT)
//   - Open with appropriate access
//
// Typical call from main:
//   HANDLE hDump   = CreateFileW(..., CREATE_ALWAYS, ...);
//   HANDLE hEnc    = CreateFileW(..., CREATE_ALWAYS, ...);
//   HANDLE hCancel = CreateEventW(NULL, TRUE, FALSE, NULL);
//   SetHandleInformation(hDump,   HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
//   SetHandleInformation(hEnc,    HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
//   SetHandleInformation(hCancel, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
//   ppl.CreateWerFaultSecureDump(L".\\WerFaultSecure.exe",
//                                pid, tid, hDump, hEnc, hCancel);
// ============================================================
bool PPLProcessCreator::CreateWerFaultSecureDump(
    const std::wstring& werFaultPath,
    DWORD               targetPID,
    DWORD               targetTID,
    HANDLE              hDump,
    HANDLE              hEnc,
    HANDLE              hCancel,
    DWORD               protectionLevel,
    DWORD               dumpType,
    DWORD               timeoutMs)
{
    // Verify all handles are valid before building command line
    if (hDump == INVALID_HANDLE_VALUE || !hDump)
    {
        std::wcerr << L"[PPL] Invalid hDump handle" << std::endl;
        return false;
    }
    if (hEnc == INVALID_HANDLE_VALUE || !hEnc)
    {
        std::wcerr << L"[PPL] Invalid hEnc handle" << std::endl;
        return false;
    }
    if (hCancel == INVALID_HANDLE_VALUE || !hCancel)
    {
        std::wcerr << L"[PPL] Invalid hCancel handle" << std::endl;
        return false;
    }

    // WerFaultSecure expects numeric handle values (not paths) passed
    // via /file, /encfile, /cancel — handles are inherited from parent.
    std::wostringstream ss;
    ss << L"\"" << werFaultPath << L"\""
        << L" /h"
        << L" /pid " << targetPID
        << L" /tid " << targetTID
        << L" /file " << reinterpret_cast<UINT_PTR>(hDump)
        << L" /encfile " << reinterpret_cast<UINT_PTR>(hEnc)
        << L" /cancel " << reinterpret_cast<UINT_PTR>(hCancel)
        << L" /type " << dumpType;

    std::wstring cmdLine = ss.str();

    std::wcout << L"[PPL] WerFaultSecure cmdline: " << cmdLine << std::endl;

    return CreatePPLProcess(
        protectionLevel,
        cmdLine,
        true,        // inheritHandles = true (essential for file handles)
        true,        // waitForExit
        timeoutMs);
}

// ============================================================
// Accessors
// ============================================================
HANDLE PPLProcessCreator::GetProcessHandle() { return m_hProcess; }
HANDLE PPLProcessCreator::GetThreadHandle() { return m_hThread; }

DWORD PPLProcessCreator::GetExitCode()
{
    if (!m_hProcess) return STILL_ACTIVE;
    DWORD code = 0;
    GetExitCodeProcess(m_hProcess, &code);
    return code;
}