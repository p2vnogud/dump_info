/*
 * COM Deep Security Scanner v2
 * ─────────────────────────────────────────────────────────────────────────────
 * - Scans every ProgID in HKEY_CLASSES_ROOT
 * - For each instantiated COM object:
 *     • Enumerates ALL methods via ITypeInfo / ITypeLib
 *     • Recursively walks PROPERTIES that return sub-objects (IDispatch)
 *       to find nested sensitive methods (depth-limited)
 *     • Only METHODS are checked against sensitive patterns
 *     • Properties are only traversed, never flagged themselves
 * - Each ProgID scan runs in an isolated child PROCESS (not just a thread)
 *   so a crash/hang cannot kill the scanner
 * - Full structured error handling, no silent exits
 *
 * Build (MSVC):
 *   cl.exe /EHsc /W4 /O2 /MT comscan2.cpp ole32.lib oleaut32.lib advapi32.lib shell32.lib /Fe:comscan2.exe
 *
 * Build (MinGW g++):
 *   g++ -std=c++17 -O2 comscan2.cpp -lole32 -loleaut32 -ladvapi32 -lshell32 -o comscan2.exe
 */
#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX


#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <oaidl.h>
#include <comdef.h>
#include <shlwapi.h>

#include <string>
#include <vector>
#include <set>
#include <map>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <functional>
#include <stdexcept>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

 // ═══════════════════════════════════════════════════════════════════════════
 //  Configuration
 // ═══════════════════════════════════════════════════════════════════════════

static const DWORD   CHILD_TIMEOUT_MS = 5000;   // per-ProgID child process timeout
static const int     MAX_RECURSE_DEPTH = 4;       // max property recursion depth
static const int     MAX_PROPS_PER_OBJ = 64;      // cap properties expanded per object
static const size_t  MAX_PROGIDS = 60000;
static const wchar_t REPORT_FILE[] = L"COM_DeepScan_Report.txt";
static const wchar_t WORKER_FLAG[] = L"--worker";

// Sensitive method name patterns (case-insensitive substring)
static const wchar_t* SENSITIVE[] = {
    L"execute",  L"exec",     L"shell",    L"run",
    L"open",     L"navigate", L"launch",   L"create",
    L"spawn",    L"invoke",   L"start",    L"eval",
    L"download", L"write",    L"delete",   L"connect",
    L"send",     L"load",     L"inject",   L"register",
    L"activate", L"dispatch", L"trigger",  L"call",
    L"script",   L"command",  L"process",  nullptr
};

// ═══════════════════════════════════════════════════════════════════════════
//  String utilities
// ═══════════════════════════════════════════════════════════════════════════

static std::wstring BstrToWstr(BSTR b) {
    return (b && SysStringLen(b) > 0) ? std::wstring(b, SysStringLen(b)) : L"";
}

static std::string WstrToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, (char*)s.data(), n, nullptr, nullptr);
    return s;
}

static std::wstring Utf8ToWstr(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(n - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, (wchar_t*)w.data(), n);
    return w;
}

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

static bool IsSensitiveMethod(const std::wstring& name) {
    std::wstring lo = ToLower(name);
    for (int i = 0; SENSITIVE[i]; ++i)
        if (lo.find(SENSITIVE[i]) != std::wstring::npos)
            return true;
    return false;
}

static std::string HrToStr(HRESULT hr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setw(8)
        << std::setfill('0') << static_cast<unsigned long>(hr);
    return oss.str();
}

// ═══════════════════════════════════════════════════════════════════════════
//  COM TypeInfo helpers
// ═══════════════════════════════════════════════════════════════════════════

// Represents one discovered sensitive finding
struct Finding {
    std::wstring path;        // e.g. "Root -> .Documents -> .Execute"
    std::wstring methodName;
    std::wstring typeName;    // interface/coclass name if available
};

// Safely release a COM pointer
template<typename T>
static void SafeRelease(T*& p) {
    if (p) { p->Release(); p = nullptr; }
}

// Get display name of a TYPEKIND
static const wchar_t* TypeKindName(TYPEKIND tk) {
    switch (tk) {
    case TKIND_ENUM:      return L"enum";
    case TKIND_RECORD:    return L"struct";
    case TKIND_MODULE:    return L"module";
    case TKIND_INTERFACE: return L"interface";
    case TKIND_DISPATCH:  return L"dispinterface";
    case TKIND_COCLASS:   return L"coclass";
    case TKIND_ALIAS:     return L"alias";
    case TKIND_UNION:     return L"union";
    default:              return L"unknown";
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Enumerate methods (and property-get returns) from one ITypeInfo
//  Fills:
//    outMethods  – all method names
//    outPropGetIds – DISPID list of property-getters that return VT_DISPATCH
// ─────────────────────────────────────────────────────────────────────────
static void EnumTypeInfo(
    ITypeInfo* pTI,
    std::vector<std::wstring>& outMethods,
    std::vector<DISPID>& outPropGetIds,
    std::wstring& outTypeName)
{
    if (!pTI) return;

    TYPEATTR* pAttr = nullptr;
    if (FAILED(pTI->GetTypeAttr(&pAttr)) || !pAttr) return;

    // Grab type name
    BSTR bName = nullptr;
    if (SUCCEEDED(pTI->GetDocumentation(MEMBERID_NIL, &bName, nullptr, nullptr, nullptr)) && bName) {
        outTypeName = BstrToWstr(bName);
        SysFreeString(bName);
    }

    for (UINT i = 0; i < pAttr->cFuncs; ++i) {
        FUNCDESC* pFD = nullptr;
        if (FAILED(pTI->GetFuncDesc(i, &pFD)) || !pFD) continue;

        BSTR bMemberName = nullptr;
        UINT cNames = 0;
        if (SUCCEEDED(pTI->GetNames(pFD->memid, &bMemberName, 1, &cNames)) && bMemberName) {
            std::wstring fname = BstrToWstr(bMemberName);
            SysFreeString(bMemberName);

            bool isMethod = (pFD->invkind == INVOKE_FUNC);
            bool isPropGet = (pFD->invkind == INVOKE_PROPERTYGET);

            if (isMethod && !fname.empty()) {
                outMethods.push_back(fname);
            }

            // Track property-getters returning IDispatch/VT_UNKNOWN for recursion
            if (isPropGet) {
                VARTYPE vt = pFD->elemdescFunc.tdesc.vt;
                if (vt == VT_DISPATCH || vt == VT_UNKNOWN ||
                    vt == VT_PTR) {   // VT_PTR may wrap IDispatch
                    outPropGetIds.push_back(pFD->memid);
                }
            }
        }
        pTI->ReleaseFuncDesc(pFD);
    }

    pTI->ReleaseTypeAttr(pAttr);
}

// ─────────────────────────────────────────────────────────────────────────
//  Recursively walk IDispatch object:
//    1. Enumerate all methods from its type info → check for sensitive
//    2. For each property-getter returning IDispatch → recurse
//  visited: set of ITypeInfo pointers already processed (cycle guard)
// ─────────────────────────────────────────────────────────────────────────
static void WalkDispatch(
    IDispatch* pDisp,
    const std::wstring& path,
    int                     depth,
    std::set<ITypeInfo*>& visited,
    std::vector<Finding>& findings)
{
    if (!pDisp || depth > MAX_RECURSE_DEPTH) return;

    // ── Get ITypeInfo ──────────────────────────────────────────────────────
    ITypeInfo* pTI = nullptr;
    HRESULT hr = pDisp->GetTypeInfo(0, LOCALE_USER_DEFAULT, &pTI);
    if (FAILED(hr) || !pTI) {
        // Fallback: try GetTypeInfoCount
        UINT tc = 0;
        if (FAILED(pDisp->GetTypeInfoCount(&tc)) || tc == 0) return;
        hr = pDisp->GetTypeInfo(0, LOCALE_USER_DEFAULT, &pTI);
        if (FAILED(hr) || !pTI) return;
    }

    // Cycle guard: skip if we've already walked this exact type
    if (!visited.insert(pTI).second) {
        SafeRelease(pTI);
        return;
    }

    std::vector<std::wstring> methods;
    std::vector<DISPID>       propGetIds;
    std::wstring              typeName;

    EnumTypeInfo(pTI, methods, propGetIds, typeName);

    // ── Check methods for sensitive patterns ──────────────────────────────
    for (auto& m : methods) {
        if (IsSensitiveMethod(m)) {
            Finding f;
            f.methodName = m;
            f.path = path + L"." + m + L"()";
            f.typeName = typeName;
            findings.push_back(f);
        }
    }

    // ── Recurse into dispatchable properties ──────────────────────────────
    if (depth < MAX_RECURSE_DEPTH && (int)propGetIds.size() <= MAX_PROPS_PER_OBJ) {
        for (DISPID did : propGetIds) {
            DISPPARAMS dp = {};
            VARIANT vResult;
            VariantInit(&vResult);
            EXCEPINFO ei = {};
            UINT argErr = 0;

            hr = pDisp->Invoke(did, IID_NULL, LOCALE_USER_DEFAULT,
                DISPATCH_PROPERTYGET, &dp,
                &vResult, &ei, &argErr);

            if (SUCCEEDED(hr)) {
                // Resolve VT_PTR / VT_BYREF wrappers
                VARIANT* pV = &vResult;
                VARIANT  deref;
                VariantInit(&deref);
                if (pV->vt & VT_BYREF) {
                    VariantCopyInd(&deref, pV);
                    pV = &deref;
                }

                IDispatch* pChild = nullptr;
                if (pV->vt == VT_DISPATCH && pV->pdispVal) {
                    pChild = pV->pdispVal;
                    pChild->AddRef();
                }
                else if (pV->vt == VT_UNKNOWN && pV->punkVal) {
                    pV->punkVal->QueryInterface(IID_IDispatch,
                        reinterpret_cast<void**>(&pChild));
                }

                if (pChild) {
                    // Get property name for path label
                    BSTR bPropName = nullptr;
                    UINT cN = 0;
                    std::wstring propLabel = L"[prop]";
                    if (SUCCEEDED(pTI->GetNames(did, &bPropName, 1, &cN)) && bPropName) {
                        propLabel = BstrToWstr(bPropName);
                        SysFreeString(bPropName);
                    }

                    WalkDispatch(pChild, path + L"." + propLabel,
                        depth + 1, visited, findings);
                    SafeRelease(pChild);
                }

                VariantClear(&deref);
            }

            VariantClear(&vResult);
        }
    }

    SafeRelease(pTI);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Worker mode: scan ONE ProgID, print results to stdout, exit
//  Called as:  comscan2.exe --worker <ProgID>
// ═══════════════════════════════════════════════════════════════════════════

static int WorkerMain(const std::wstring& progID)
{
    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hrInit)) {
        std::wcout << L"COMERR\t" << progID << L"\tCoInit:" << HrToStr(hrInit).c_str() << L"\n";
        return 1;
    }

    CLSID clsid = {};
    HRESULT hr = CLSIDFromProgID(progID.c_str(), &clsid);
    if (FAILED(hr)) {
        std::wcout << L"COMERR\t" << progID << L"\tCLSID:" << HrToStr(hr).c_str() << L"\n";
        CoUninitialize();
        return 1;
    }

    IDispatch* pDisp = nullptr;
    hr = CoCreateInstance(clsid, nullptr,
        CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
        IID_IDispatch,
        reinterpret_cast<void**>(&pDisp));

    if (FAILED(hr) || !pDisp) {
        CoUninitialize();
        return 0;
    }

    std::vector<Finding> findings;
    std::set<ITypeInfo*> visited;

    LPOLESTR clsidStr = nullptr;
    std::wstring clsidW;
    if (SUCCEEDED(StringFromCLSID(clsid, &clsidStr))) {
        clsidW = clsidStr;
        CoTaskMemFree(clsidStr);
    }

    WalkDispatch(pDisp, progID, 0, visited, findings);
    SafeRelease(pDisp);

    for (auto& f : findings) {
        std::wcout << L"FOUND\t" << progID
            << L"\t" << clsidW
            << L"\t" << f.path
            << L"\t" << f.methodName
            << L"\t" << f.typeName
            << L"\n";
    }
    std::wcout.flush();

    CoUninitialize();
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Registry: collect all ProgIDs that have a CLSID subkey
// ═══════════════════════════════════════════════════════════════════════════

static std::vector<std::wstring> CollectProgIDs() {
    std::vector<std::wstring> ids;
    HKEY hkcr = nullptr;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"", 0, KEY_READ, &hkcr) != ERROR_SUCCESS)
        return ids;

    DWORD idx = 0;
    wchar_t name[512];
    while (ids.size() < MAX_PROGIDS) {
        DWORD nameLen = 512;
        LONG ret = RegEnumKeyExW(hkcr, idx++, name, &nameLen,
            nullptr, nullptr, nullptr, nullptr);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS) continue;
        if (!iswalpha(name[0])) continue;

        std::wstring sub = std::wstring(name) + L"\\CLSID";
        HKEY hSub = nullptr;
        if (RegOpenKeyExW(hkcr, sub.c_str(), 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            RegCloseKey(hSub);
            ids.emplace_back(name);
        }
    }
    RegCloseKey(hkcr);
    return ids;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Spawn child process for one ProgID, capture stdout, timeout-kill
// ═══════════════════════════════════════════════════════════════════════════

struct ScanResult {
    std::wstring progID;
    std::vector<Finding> findings;
    bool timedOut = false;
    bool crashed = false;
    bool comError = false;
    std::wstring errorDetail;
};

static ScanResult ScanOneProgID(const std::wstring& exePath,
    const std::wstring& progID)
{
    ScanResult res;
    res.progID = progID;

    // Build command line:  comscan2.exe --worker "ProgID"
    std::wstring cmdline = L"\"" + exePath + L"\" " +
        std::wstring(WORKER_FLAG) + L" \"" + progID + L"\"";

    // Pipe for stdout capture
    HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        res.comError = true;
        res.errorDetail = L"CreatePipe failed";
        return res;
    }
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(nullptr, (wchar_t*)cmdline.data(), nullptr, nullptr,
        TRUE, CREATE_NO_WINDOW, nullptr, nullptr,
        &si, &pi);
    CloseHandle(hWritePipe);  // must close our copy so ReadFile sees EOF

    if (!ok) {
        CloseHandle(hReadPipe);
        res.comError = true;
        res.errorDetail = L"CreateProcess failed: " +
            std::to_wstring(GetLastError());
        return res;
    }

    // Read stdout while waiting (non-blocking read loop)
    std::string rawOutput;
    rawOutput.reserve(4096);
    auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(CHILD_TIMEOUT_MS);

    for (;;) {
        char buf[4096];
        DWORD bytesRead = 0;
        DWORD avail = 0;

        // PeekNamedPipe so we don't block indefinitely
        if (PeekNamedPipe(hReadPipe, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
            DWORD toRead = std::min(avail, static_cast<DWORD>(sizeof buf));
            if (ReadFile(hReadPipe, buf, toRead, &bytesRead, nullptr) && bytesRead > 0)
                rawOutput.append(buf, bytesRead);
        }

        DWORD exitCode = 0;
        DWORD waitMs = 50;  // poll interval
        DWORD waitRet = WaitForSingleObject(pi.hProcess, waitMs);

        if (waitRet == WAIT_OBJECT_0) {
            // Process finished — drain remaining output
            DWORD n = 0;
            while (ReadFile(hReadPipe, buf, sizeof buf, &n, nullptr) && n > 0)
                rawOutput.append(buf, n);
            GetExitCodeProcess(pi.hProcess, &exitCode);
            if (exitCode == 2) res.crashed = true;
            break;
        }

        if (std::chrono::steady_clock::now() >= deadline) {
            TerminateProcess(pi.hProcess, 0xDEAD);
            WaitForSingleObject(pi.hProcess, 500);
            res.timedOut = true;
            break;
        }
    }

    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // ── Parse output lines ──────────────────────────────────────────────
    // Each line: FOUND\tProgID\tCLSID\tPath\tMethod\tTypeName
    //         or COMERR\tProgID\tDetail
    //         or CRASH\tProgID\tDetail
    std::istringstream ss(rawOutput);
    std::string line;
    while (std::getline(ss, line)) {
        // strip \r
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        // Split by \t
        std::vector<std::string> parts;
        std::string tok;
        for (char c : line) {
            if (c == '\t') { parts.push_back(tok); tok.clear(); }
            else tok += c;
        }
        parts.push_back(tok);

        if (parts.empty()) continue;
        std::string tag = parts[0];

        if (tag == "FOUND" && parts.size() >= 6) {
            Finding f;
            f.path = Utf8ToWstr(parts[3]);
            f.methodName = Utf8ToWstr(parts[4]);
            f.typeName = Utf8ToWstr(parts[5]);
            res.findings.push_back(f);
        }
        else if ((tag == "COMERR" || tag == "CRASH") && parts.size() >= 3) {
            res.comError = (tag == "COMERR");
            res.crashed = (tag == "CRASH");
            res.errorDetail = Utf8ToWstr(parts[2]);
        }
    }

    return res;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Console helpers
// ═══════════════════════════════════════════════════════════════════════════

static HANDLE g_hCon = nullptr;

static void SetColor(WORD c) {
    if (g_hCon) SetConsoleTextAttribute(g_hCon, c);
}

static void ResetColor() {
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

static void ClearLine() { std::wcout << L"\r" << std::wstring(100, L' ') << L"\r"; }

// ═══════════════════════════════════════════════════════════════════════════
//  Report writer (UTF-8 with BOM)
// ═══════════════════════════════════════════════════════════════════════════

class Report {
    std::ofstream f_;
    void L(const std::string& s) { f_ << s << "\r\n"; }
    void Sep(char c, int n = 80) { f_ << std::string(n, c) << "\r\n"; }
public:
    Report(const std::wstring& path) {
        f_.open(path, std::ios::out | std::ios::binary);
        f_ << "\xEF\xBB\xBF";
    }
    bool Ok() const { return f_.is_open(); }

    void Header(size_t total) {
        auto t = std::time(nullptr);
        char buf[64]; std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", std::localtime(&t));
        Sep('=');
        L("  COM DEEP SECURITY SCANNER  v2 – Recursive Property Walk");
        L("  Generated : " + std::string(buf));
        L("  Total IDs : " + std::to_string(total));
        L("  Max depth : " + std::to_string(MAX_RECURSE_DEPTH));
        L("  Timeout   : " + std::to_string(CHILD_TIMEOUT_MS) + " ms / ProgID");
        Sep('='); L("");
    }

    void Entry(const ScanResult& r) {
        Sep('-');
        L("[DANGEROUS] ProgID : " + WstrToUtf8(r.progID));

        // Deduplicate paths for display
        std::set<std::wstring> seen;
        for (auto& f : r.findings) {
            if (!seen.insert(f.path).second) continue;
            std::string pathLine = "  Path   : " + WstrToUtf8(f.path);
            std::string methodLine = "  Method : " + WstrToUtf8(f.methodName);
            if (!f.typeName.empty())
                methodLine += "  (in " + WstrToUtf8(f.typeName) + ")";
            L(pathLine);
            L(methodLine);
        }
        L("");
    }

    void Footer(size_t total, size_t found, size_t timeout,
        size_t crashed, double sec) {
        Sep('=');
        L("SUMMARY");
        Sep('-');
        L("  Total scanned  : " + std::to_string(total));
        L("  Dangerous      : " + std::to_string(found));
        L("  Timed out      : " + std::to_string(timeout));
        L("  Crashed/Error  : " + std::to_string(crashed));
        std::ostringstream oss; oss << std::fixed << std::setprecision(1) << sec;
        L("  Elapsed        : " + oss.str() + " s");
        Sep('=');
    }
};

// ═══════════════════════════════════════════════════════════════════════════
//  Scanner main
// ═══════════════════════════════════════════════════════════════════════════

static int ScannerMain() {
    // Get own executable path (for spawning worker)
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    g_hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(g_hCon, &mode);
    SetConsoleMode(g_hCon, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    SetConsoleOutputCP(CP_UTF8);

    std::wcout << L"\n";
    std::wcout << L"  ╔══════════════════════════════════════════════════════╗\n";
    std::wcout << L"  ║     COM DEEP SECURITY SCANNER  v2  (C++/WinAPI)     ║\n";
    std::wcout << L"  ║  Recursive property walk · Isolated child processes  ║\n";
    std::wcout << L"  ╚══════════════════════════════════════════════════════╝\n\n";

    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"  [*] Collecting ProgIDs from HKEY_CLASSES_ROOT...\n";
    ResetColor();

    auto progIDs = CollectProgIDs();
    size_t total = progIDs.size();

    SetColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::wcout << L"  [*] Found " << total << L" ProgIDs. Starting deep scan...\n";
    std::wcout << L"  [*] Report: " << REPORT_FILE << L"\n\n";
    ResetColor();

    Report report(REPORT_FILE);
    if (!report.Ok()) {
        std::wcerr << L"  [!] Cannot create report file.\n";
        return 1;
    }
    report.Header(total);

    size_t foundCount = 0;
    size_t timeoutCount = 0;
    size_t crashCount = 0;

    auto t0 = std::chrono::steady_clock::now();

    for (size_t i = 0; i < total; ++i) {
        double pct = total ? (100.0 * (i + 1) / total) : 0.0;

        // Progress line
        ClearLine();
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::wcout << L"  [" << std::fixed << std::setprecision(1) << pct << L"%] "
            << progIDs[i].substr(0, 52);
        std::wcout.flush();

        ScanResult res = ScanOneProgID(exePath, progIDs[i]);

        if (res.timedOut)  timeoutCount++;
        if (res.crashed)   crashCount++;

        if (!res.findings.empty()) {
            foundCount++;
            report.Entry(res);

            // Print finding to console immediately
            ClearLine();
            SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::wcout << L"  [DANGEROUS] " << res.progID << L"\n";

            std::set<std::wstring> seen;
            for (auto& f : res.findings) {
                if (!seen.insert(f.path).second) continue;
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                std::wcout << L"             ";
                SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::wcout << f.methodName;
                ResetColor();
                std::wcout << L"  at  " << f.path << L"\n";
            }
            ResetColor();
        }
        else if (res.timedOut) {
            ClearLine();
            SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::wcout << L"  [TIMEOUT]   " << res.progID << L"\n";
            ResetColor();
        }
        // Crashes and COM errors are silent — they're noise
    }

    double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();

    ClearLine();
    report.Footer(total, foundCount, timeoutCount, crashCount, elapsed);

    std::wcout << L"\n";
    std::wcout << L"  ┌─────────────────────────────────────────┐\n";
    std::wcout << L"  │  SCAN COMPLETE                          │\n";
    std::wcout << L"  │  Scanned   : " << std::setw(5) << total
        << L"                      │\n";
    std::wcout << L"  │  Dangerous : " << std::setw(5) << foundCount
        << L"                      │\n";
    std::wcout << L"  │  Timed out : " << std::setw(5) << timeoutCount
        << L"                      │\n";
    std::wcout << L"  │  Crashed   : " << std::setw(5) << crashCount
        << L"                      │\n";
    std::wcout << L"  └─────────────────────────────────────────┘\n";
    std::wcout << L"\n  Report saved: " << REPORT_FILE << L"\n\n";

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Entry point
// ═══════════════════════════════════════════════════════════════════════════

int wmain(int argc, wchar_t* argv[]) {
    // Worker mode: comscan2.exe --worker "<ProgID>"
    if (argc >= 3 && std::wstring(argv[1]) == WORKER_FLAG) {
        // Reconstruct ProgID (may contain spaces if quoted)
        std::wstring progID = argv[2];
        for (int i = 3; i < argc; ++i)
            progID += L" " + std::wstring(argv[i]);
        // Strip surrounding quotes if present
        if (progID.size() >= 2 && progID.front() == L'"' && progID.back() == L'"')
            progID = progID.substr(1, progID.size() - 2);
        return WorkerMain(progID);
    }

    return ScannerMain();
}