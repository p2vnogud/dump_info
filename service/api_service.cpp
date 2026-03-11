#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <wchar.h>
#include <stdio.h>
#include <sddl.h>
#include <string>
#include <map>
#include <vector>

#pragma comment(lib, "advapi32.lib")

// ============================================================
//  USAGE
// ============================================================
//
//  api_service.exe <action> <service_name> [options]
//
//  Actions:
//    create  <name> --path <binary> [--display <display_name>]
//    start   <name>
//    stop    <name>
//    delete  <name>
//    query   <name>
//    set     <name> [--owner <SID>] [--group <SID>]
//                   [--dacl  <D:(...)>]
//                   [--sacl  <S:(...)>]
//                   [--full  <O:..G:..D:..S:..>]
//
//  Notes for "set":
//    --owner / --group : just the SID string, e.g.  BA  or  S-1-5-32-544
//    --dacl            : the DACL part only, e.g.   D:(A;;FA;;;BA)
//    --sacl            : the SACL part only, e.g.   S:(AU;SA;FA;;;WD)
//    --full            : complete SDDL string (ignores other flags)
//
//  Examples:
//    api_service.exe create  MySvc --path C:\svc.exe --display "My Service"
//    api_service.exe query   MySvc
//    api_service.exe set     MySvc --dacl "D:(A;;FA;;;BA)(A;;FA;;;SY)"
//    api_service.exe set     MySvc --owner BA --group SY
//    api_service.exe set     MySvc --owner BA --dacl "D:(A;;FA;;;BA)" --sacl "S:(AU;SA;FA;;;WD)"
//    api_service.exe set     MySvc --full  "O:BAG:SYD:(A;;FA;;;BA)S:(AU;SA;FA;;;WD)"
//
// ============================================================

// ─────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────

void PrintLastError(const WCHAR* msg)
{
    DWORD err = GetLastError();
    WCHAR buffer[512] = {};
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buffer, 512, NULL);
    wprintf(L"[ERR] %s failed. Code %u: %s\n", msg, err, buffer);
}

// Parse argv into a map:  --key value   (flags without values are not supported here)
using ArgMap = std::map<std::wstring, std::wstring>;

ArgMap ParseArgs(int argc, wchar_t* argv[], int startIdx)
{
    ArgMap m;
    for (int i = startIdx; i < argc - 1; i += 2) {
        if (argv[i][0] == L'-' && argv[i][1] == L'-') {
            m[argv[i]] = argv[i + 1];
        }
    }
    return m;
}

std::wstring GetArg(const ArgMap& m, const wchar_t* key, const wchar_t* def = L"")
{
    auto it = m.find(key);
    return (it != m.end()) ? it->second : def;
}

// ─────────────────────────────────────────────────────────────
//  Privilege helpers
// ─────────────────────────────────────────────────────────────

bool EnablePrivileges()
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        PrintLastError(L"OpenProcessToken");
        return false;
    }

    const wchar_t* privs[] = {
        SE_TAKE_OWNERSHIP_NAME,   // needed to set Owner
        SE_RESTORE_NAME,          // needed when setting owner/group
        SE_SECURITY_NAME,         // needed to read/write SACL
        SE_AUDIT_NAME
    };

    bool ok = true;
    for (auto* p : privs) {
        TOKEN_PRIVILEGES tp = {};
        LUID luid;
        if (!LookupPrivilegeValueW(nullptr, p, &luid)) {
            wprintf(L"[WARN] LookupPrivilegeValue failed for %s\n", p);
            ok = false;
            continue;
        }
        tp.PrivilegeCount = 1;
        tp.Privileges[0] = { luid, SE_PRIVILEGE_ENABLED };
        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
            wprintf(L"[WARN] AdjustTokenPrivileges failed for %s\n", p);
            ok = false;
        }
        else {
            wprintf(L"[OK]  Enabled: %s\n", p);
        }
    }

    CloseHandle(hToken);
    return ok;
}

// ─────────────────────────────────────────────────────────────
//  SDDL analysis helpers
// ─────────────────────────────────────────────────────────────

std::wstring GetSidFriendlyName(const std::wstring& sid)
{
    // Well-known short aliases
    static const std::pair<const wchar_t*, const wchar_t*> table[] = {
        {L"SY", L"NT AUTHORITY\\SYSTEM"},
        {L"BA", L"BUILTIN\\Administrators"},
        {L"AU", L"Authenticated Users"},
        {L"WD", L"Everyone"},
        {L"IU", L"INTERACTIVE"},
        {L"SU", L"SERVICE"},
        {L"NS", L"NETWORK SERVICE"},
        {L"LS", L"LOCAL SERVICE"},
        {L"BU", L"BUILTIN\\Users"},
        {L"PU", L"BUILTIN\\Power Users"},
        {L"SO", L"BUILTIN\\Server Operators"},
    };
    for (auto& p : table)
        if (sid == p.first) return p.second;

    // Try to resolve a full SID string to account name
    if (sid.size() > 2 && sid[0] == L'S' && sid[1] == L'-') {
        PSID pSid = nullptr;
        if (ConvertStringSidToSidW(sid.c_str(), &pSid)) {
            WCHAR name[256] = {}, domain[256] = {};
            DWORD nLen = 256, dLen = 256;
            SID_NAME_USE use;
            if (LookupAccountSidW(nullptr, pSid, name, &nLen, domain, &dLen, &use)) {
                LocalFree(pSid);
                return std::wstring(domain) + L"\\" + name;
            }
            LocalFree(pSid);
        }
    }
    return std::wstring(L"Unknown SID: ") + sid;
}

std::wstring AceTypeStr(const std::wstring& t)
{
    if (t == L"A")  return L"Allow";
    if (t == L"D")  return L"Deny";
    if (t == L"AU") return L"Audit";
    if (t == L"AL") return L"Alarm";
    return L"Unknown(" + t + L")";
}

std::wstring AceFlagsStr(const std::wstring& f)
{
    std::wstring out;
    auto add = [&](const wchar_t* tok, const wchar_t* desc) {
        if (f.find(tok) != std::wstring::npos) out += desc;
        };
    add(L"CI", L"ContainerInherit ");
    add(L"OI", L"ObjectInherit ");
    add(L"NP", L"NoPropagateInherit ");
    add(L"IO", L"InheritOnly ");
    add(L"ID", L"Inherited ");
    add(L"SA", L"AuditSuccess ");
    add(L"FA", L"AuditFailure ");
    return out.empty() ? L"(none)" : out;
}

// Decode a rights string: handles both named (CCLCSW...) and hex (0x001F01FF)
std::wstring RightsStr(const std::wstring& r)
{
    // Hex mask  ──────────────────────────────────────────────
    if (r.size() > 2 && r[0] == L'0' && (r[1] == L'x' || r[1] == L'X')) {
        DWORD mask = (DWORD)wcstoul(r.c_str(), nullptr, 16);
        std::wstring out;
        // Generic rights
        if (mask & GENERIC_ALL)     out += L"GENERIC_ALL ";
        if (mask & GENERIC_READ)    out += L"GENERIC_READ ";
        if (mask & GENERIC_WRITE)   out += L"GENERIC_WRITE ";
        if (mask & GENERIC_EXECUTE) out += L"GENERIC_EXECUTE ";
        // Standard
        if (mask & DELETE)          out += L"DELETE ";
        if (mask & READ_CONTROL)    out += L"READ_CONTROL ";
        if (mask & WRITE_DAC)       out += L"WRITE_DAC ";
        if (mask & WRITE_OWNER)     out += L"WRITE_OWNER ";
        if (mask & SYNCHRONIZE)     out += L"SYNCHRONIZE ";
        // Service-specific (low 16 bits map to object rights)
        DWORD svc = mask & 0xFFFF;
        if (svc & 0x0001) out += L"QueryConfig ";
        if (svc & 0x0002) out += L"ChangeConfig ";
        if (svc & 0x0004) out += L"QueryStatus ";
        if (svc & 0x0008) out += L"EnumDependents ";
        if (svc & 0x0010) out += L"Start ";
        if (svc & 0x0020) out += L"Stop ";
        if (svc & 0x0040) out += L"PauseContinue ";
        if (svc & 0x0080) out += L"Interrogate ";
        if (svc & 0x0100) out += L"UserDefinedControl ";
        return out.empty() ? r : out;
    }

    // Named rights ───────────────────────────────────────────
    static const std::pair<const wchar_t*, const wchar_t*> named[] = {
        {L"FA",   L"FullAccess "},
        {L"CC",   L"QueryConfig/Start "},
        {L"DC",   L"ChangeConfig "},
        {L"LC",   L"QueryStatus "},
        {L"SW",   L"EnumDependents "},
        {L"RP",   L"Start "},
        {L"WP",   L"Stop "},
        {L"DT",   L"PauseContinue "},
        {L"LO",   L"Interrogate "},
        {L"CR",   L"UserDefinedControl "},
        {L"SD",   L"Delete "},
        {L"RC",   L"ReadControl "},
        {L"WD",   L"WriteDACL "},
        {L"WO",   L"WriteOwner "},
    };

    // Full-match shortcuts first
    if (r == L"CCDCLCSWRPWPDTLOCRSDRCWDWO") return L"FullControl";
    if (r == L"CCLCSWRPWPDTLOCRRC")         return L"ReadAndStart";
    if (r == L"CCLCSWLOCRRC")               return L"ReadOnly";

    std::wstring out;
    std::wstring rem = r;
    // Greedy match from left (longest token first — 2-char)
    while (!rem.empty()) {
        bool matched = false;
        for (auto& p : named) {
            std::wstring key = p.first;
            if (rem.substr(0, key.size()) == key) {
                out += p.second;
                rem = rem.substr(key.size());
                matched = true;
                break;
            }
        }
        if (!matched) {
            out += rem[0];  // keep unknown char
            rem = rem.substr(1);
        }
    }
    return out.empty() ? r : out;
}

// Parse and print one ACE list (DACL or SACL) from a SDDL substring
void PrintAceList(const std::wstring& part, bool isSacl)
{
    size_t pos = 0;
    int idx = 1;
    while ((pos = part.find(L'(', pos)) != std::wstring::npos) {
        size_t end = part.find(L')', pos);
        if (end == std::wstring::npos) break;

        std::wstring ace = part.substr(pos + 1, end - pos - 1);
        // Split by ';'
        std::vector<std::wstring> fields;
        size_t s = 0, f;
        while ((f = ace.find(L';', s)) != std::wstring::npos) {
            fields.push_back(ace.substr(s, f - s));
            s = f + 1;
        }
        fields.push_back(ace.substr(s));

        if (fields.size() >= 6) {
            wprintf(L"\n  ACE #%d : (%s)\n", idx++, ace.c_str());
            wprintf(L"    Type    : %s\n", AceTypeStr(fields[0]).c_str());
            wprintf(L"    Flags   : %s\n", AceFlagsStr(fields[1]).c_str());
            wprintf(L"    Rights  : %s  [%s]\n", fields[2].c_str(), RightsStr(fields[2]).c_str());
            wprintf(L"    Trustee : %s  (%s)\n", fields[5].c_str(), GetSidFriendlyName(fields[5]).c_str());
            if (isSacl)
                wprintf(L"    AuditOn : %s\n", AceFlagsStr(fields[1]).c_str());
        }
        else {
            wprintf(L"\n  ACE #%d (malformed): (%s)\n", idx++, ace.c_str());
        }
        pos = end + 1;
    }
}

void AnalyzeSDDL(const wchar_t* svcName, const wchar_t* pSddl)
{
    wprintf(L"\n  SDDL : %s\n\n", pSddl);
    wprintf(L"  ══════════════════════════════════════════════\n");

    std::wstring sddl = pSddl;

    // ── Owner ────────────────────────────────────────────────
    size_t posO = sddl.find(L"O:");
    if (posO != std::wstring::npos) {
        size_t end = sddl.find_first_of(L"GDS", posO + 2);
        // find "G:" "D:" "S:" after O:
        for (size_t i = posO + 2; i < sddl.size() - 1; i++) {
            if ((sddl[i] == L'G' || sddl[i] == L'D' || sddl[i] == L'S') && sddl[i + 1] == L':') {
                end = i; break;
            }
        }
        std::wstring owner = sddl.substr(posO + 2, end - posO - 2);
        wprintf(L"  Owner  : %-30s  %s\n", owner.c_str(), GetSidFriendlyName(owner).c_str());
    }

    // ── Group ────────────────────────────────────────────────
    size_t posG = sddl.find(L"G:");
    if (posG != std::wstring::npos) {
        size_t end = sddl.size();
        for (size_t i = posG + 2; i < sddl.size() - 1; i++) {
            if ((sddl[i] == L'D' || sddl[i] == L'S') && sddl[i + 1] == L':') {
                end = i; break;
            }
        }
        std::wstring grp = sddl.substr(posG + 2, end - posG - 2);
        wprintf(L"  Group  : %-30s  %s\n", grp.c_str(), GetSidFriendlyName(grp).c_str());
    }

    // ── DACL ─────────────────────────────────────────────────
    size_t posD = sddl.find(L"D:");
    if (posD != std::wstring::npos) {
        // Stop at S: if present
        size_t endD = sddl.size();
        for (size_t i = posD + 2; i < sddl.size() - 1; i++) {
            if (sddl[i] == L'S' && sddl[i + 1] == L':') { endD = i; break; }
        }
        std::wstring daclPart = sddl.substr(posD, endD - posD);
        wprintf(L"\n  ── DACL ─────────────────────────────────────\n");
        PrintAceList(daclPart, false);
    }
    else {
        wprintf(L"\n  DACL : (none)\n");
    }

    // ── SACL ─────────────────────────────────────────────────
    size_t posS = sddl.find(L"S:");
    if (posS != std::wstring::npos) {
        std::wstring saclPart = sddl.substr(posS);
        wprintf(L"\n  ── SACL (Audit) ─────────────────────────────\n");
        PrintAceList(saclPart, true);
    }
    else {
        wprintf(L"\n  SACL : (none / not retrieved)\n");
    }

    wprintf(L"\n  ══════════════════════════════════════════════\n");
}

// ─────────────────────────────────────────────────────────────
//  Query current SDDL from a service handle
//  Returns allocated pSddl (caller must LocalFree) or nullptr
// ─────────────────────────────────────────────────────────────

wchar_t* QueryServiceSddl(SC_HANDLE hService)
{
    SECURITY_INFORMATION secInfo =
        SACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;

    DWORD dwNeeded = 0;
    QueryServiceObjectSecurity(hService, secInfo, nullptr, 0, &dwNeeded);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER && dwNeeded == 0) {
        PrintLastError(L"QueryServiceObjectSecurity (size)");
        return nullptr;
    }

    auto* buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNeeded);
    if (!buf) return nullptr;

    if (!QueryServiceObjectSecurity(hService, secInfo, buf, dwNeeded, &dwNeeded)) {
        PrintLastError(L"QueryServiceObjectSecurity (read)");
        HeapFree(GetProcessHeap(), 0, buf);
        return nullptr;
    }

    wchar_t* pSddl = nullptr;
    ULONG sizeSddl = 0;
    auto* sd = (PSECURITY_DESCRIPTOR)buf;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
        sd, SDDL_REVISION_1, secInfo, &pSddl, &sizeSddl))
    {
        PrintLastError(L"ConvertSecurityDescriptorToStringSecurityDescriptorW");
        HeapFree(GetProcessHeap(), 0, buf);
        return nullptr;
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return pSddl;  // caller LocalFree
}

// ─────────────────────────────────────────────────────────────
//  Parse SDDL into components
// ─────────────────────────────────────────────────────────────

struct SddlParts {
    std::wstring owner;  // e.g. "SY"
    std::wstring group;  // e.g. "SY"
    std::wstring dacl;   // e.g. "D:(...)"
    std::wstring sacl;   // e.g. "S:(...)"
};

SddlParts SplitSddl(const std::wstring& sddl)
{
    SddlParts p;

    // Helper to find "X:" marker boundaries
    auto extractBetween = [&](const std::wstring& startTag,
        std::initializer_list<std::wstring> stopTags) -> std::wstring
        {
            size_t pos = sddl.find(startTag);
            if (pos == std::wstring::npos) return L"";
            size_t start = pos + startTag.size();
            size_t end = sddl.size();
            for (auto& tag : stopTags) {
                // Only look AFTER start
                for (size_t i = start; i + 1 < sddl.size(); i++) {
                    if (sddl.substr(i, tag.size()) == tag) {
                        if (i < end) end = i;
                        break;
                    }
                }
            }
            return sddl.substr(start, end - start);
        };

    p.owner = extractBetween(L"O:", { L"G:", L"D:", L"S:" });
    p.group = extractBetween(L"G:", { L"D:", L"S:" });

    // DACL and SACL include their tag
    size_t posD = sddl.find(L"D:");
    size_t posS = sddl.find(L"S:");

    if (posD != std::wstring::npos) {
        size_t endD = (posS != std::wstring::npos && posS > posD) ? posS : sddl.size();
        p.dacl = sddl.substr(posD, endD - posD);
    }
    if (posS != std::wstring::npos) {
        p.sacl = sddl.substr(posS);
    }

    return p;
}

std::wstring BuildSddl(const SddlParts& p)
{
    std::wstring s;
    if (!p.owner.empty()) s += L"O:" + p.owner;
    if (!p.group.empty()) s += L"G:" + p.group;
    if (!p.dacl.empty())  s += p.dacl;   // already contains "D:"
    if (!p.sacl.empty())  s += p.sacl;   // already contains "S:"
    return s;
}

// ─────────────────────────────────────────────────────────────
//  Service actions
// ─────────────────────────────────────────────────────────────

const wchar_t* CheckStatusService(const wchar_t* name)
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return L"(error)";
    SC_HANDLE hSvc = OpenServiceW(hSCM, name, SERVICE_QUERY_STATUS);
    if (!hSvc) { CloseServiceHandle(hSCM); return L"(error)"; }

    SERVICE_STATUS_PROCESS ssp = {};
    DWORD nb = 0;
    const wchar_t* ret = L"Unknown";
    if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &nb)) {
        switch (ssp.dwCurrentState) {
        case SERVICE_STOPPED:          ret = L"Stopped"; break;
        case SERVICE_START_PENDING:    ret = L"StartPending"; break;
        case SERVICE_STOP_PENDING:     ret = L"StopPending"; break;
        case SERVICE_RUNNING:          ret = L"Running"; break;
        case SERVICE_CONTINUE_PENDING: ret = L"ContinuePending"; break;
        case SERVICE_PAUSE_PENDING:    ret = L"PausePending"; break;
        case SERVICE_PAUSED:           ret = L"Paused"; break;
        }
    }
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return ret;
}

BOOL CreateMyService(const wchar_t* name, const wchar_t* display, const wchar_t* binPath)
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) { PrintLastError(L"OpenSCManager"); return FALSE; }

    SC_HANDLE hSvc = CreateServiceW(hSCM, name, display,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, binPath,
        nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!hSvc) { PrintLastError(L"CreateService"); CloseServiceHandle(hSCM); return FALSE; }

    wprintf(L"[OK] Created service '%s'  path=%s\n", name, binPath);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return TRUE;
}

BOOL StartMyService(const wchar_t* name)
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) { PrintLastError(L"OpenSCManager"); return FALSE; }
    SC_HANDLE hSvc = OpenServiceW(hSCM, name, SERVICE_START);
    if (!hSvc) { PrintLastError(L"OpenService"); CloseServiceHandle(hSCM); return FALSE; }

    if (!StartServiceW(hSvc, 0, nullptr)) { PrintLastError(L"StartService"); }
    else {
        Sleep(1500);
        auto* st = CheckStatusService(name);
        wprintf(L"[OK] Start requested. Status: %s\n", st);
    }
    CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
    return TRUE;
}

BOOL StopMyService(const wchar_t* name)
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) { PrintLastError(L"OpenSCManager"); return FALSE; }
    SC_HANDLE hSvc = OpenServiceW(hSCM, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) { PrintLastError(L"OpenService"); CloseServiceHandle(hSCM); return FALSE; }

    SERVICE_STATUS_PROCESS st = {};
    DWORD nb = 0;
    QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&st, sizeof(st), &nb);
    if (st.dwCurrentState == SERVICE_STOPPED) {
        wprintf(L"[OK] Service already stopped.\n");
    }
    else if (!ControlService(hSvc, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&st)) {
        PrintLastError(L"ControlService");
    }
    else {
        Sleep(1500);
        auto* s = CheckStatusService(name);
        wprintf(L"[OK] Stop requested. Status: %s\n", s);
    }
    CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
    return TRUE;
}

BOOL DeleteMyService(const wchar_t* name)
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) { PrintLastError(L"OpenSCManager"); return FALSE; }
    SC_HANDLE hSvc = OpenServiceW(hSCM, name, DELETE);
    if (!hSvc) { PrintLastError(L"OpenService"); CloseServiceHandle(hSCM); return FALSE; }

    BOOL ok = DeleteService(hSvc);
    if (!ok) PrintLastError(L"DeleteService");
    else     wprintf(L"[OK] Deleted service '%s'\n", name);

    CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
    return ok;
}

BOOL QueryMyServiceInfo(const wchar_t* name)
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) { PrintLastError(L"OpenSCManager"); return FALSE; }

    SC_HANDLE hSvc = OpenServiceW(hSCM, name,
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL | ACCESS_SYSTEM_SECURITY);
    if (!hSvc) { PrintLastError(L"OpenService"); CloseServiceHandle(hSCM); return FALSE; }

    wprintf(L"\n══════════  Service: %s  ══════════\n", name);

    // Status
    SERVICE_STATUS_PROCESS ssp = {};
    DWORD nb = 0;
    if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &nb)) {
        const wchar_t* st = CheckStatusService(name);
        wprintf(L"  Status       : %s\n", st);
        wprintf(L"  PID          : %u\n", ssp.dwProcessId);
        wprintf(L"  Win32 exit   : %u\n", ssp.dwWin32ExitCode);
    }

    // Config
    DWORD cfgSz = 8192;
    auto* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, cfgSz);
    if (buf) {
        if (QueryServiceConfig2W(hSvc, SERVICE_CONFIG_DESCRIPTION, buf, cfgSz, &nb)) {
            auto* d = (LPSERVICE_DESCRIPTIONW)buf;
            wprintf(L"  Description  : %s\n", d->lpDescription ? d->lpDescription : L"(none)");
        }
        if (QueryServiceConfigW(hSvc, (LPQUERY_SERVICE_CONFIGW)buf, cfgSz, &nb)) {
            auto* c = (LPQUERY_SERVICE_CONFIGW)buf;
            wprintf(L"  BinaryPath   : %s\n", c->lpBinaryPathName ? c->lpBinaryPathName : L"?");
            wprintf(L"  StartType    : %u\n", c->dwStartType);
            wprintf(L"  Account      : %s\n", c->lpServiceStartName ? c->lpServiceStartName : L"?");
            wprintf(L"  Display name : %s\n", c->lpDisplayName ? c->lpDisplayName : L"?");
        }
        HeapFree(GetProcessHeap(), 0, buf);
    }

    // SDDL
    wchar_t* pSddl = QueryServiceSddl(hSvc);
    if (pSddl) {
        AnalyzeSDDL(name, pSddl);
        LocalFree(pSddl);
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return TRUE;
}

// ─────────────────────────────────────────────────────────────
//  Set SDDL  (flexible: owner / group / dacl / sacl / full)
// ─────────────────────────────────────────────────────────────

BOOL SetMyServiceSecurity(const wchar_t* name, const ArgMap& args)
{
    // ── Open with all required access ────────────────────────
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) { PrintLastError(L"OpenSCManager"); return FALSE; }

    SC_HANDLE hSvc = OpenServiceW(hSCM, name,
        SERVICE_CHANGE_CONFIG | WRITE_DAC | READ_CONTROL |
        WRITE_OWNER | ACCESS_SYSTEM_SECURITY | SERVICE_QUERY_STATUS);
    if (!hSvc) { PrintLastError(L"OpenService"); CloseServiceHandle(hSCM); return FALSE; }

    // ── Read current SDDL so we can merge partial changes ────
    wchar_t* pCurrentSddl = QueryServiceSddl(hSvc);
    SddlParts current;
    if (pCurrentSddl) {
        current = SplitSddl(pCurrentSddl);
        LocalFree(pCurrentSddl);
    }

    // ── --full overrides everything ───────────────────────────
    std::wstring fullArg = GetArg(args, L"--full");
    std::wstring finalSddl;

    if (!fullArg.empty()) {
        finalSddl = fullArg;
        wprintf(L"[SET] Mode: full SDDL override\n");
    }
    else {
        // Merge individual parts
        std::wstring ownerArg = GetArg(args, L"--owner");
        std::wstring groupArg = GetArg(args, L"--group");
        std::wstring daclArg = GetArg(args, L"--dacl");
        std::wstring saclArg = GetArg(args, L"--sacl");

        SddlParts merged = current;

        if (!ownerArg.empty()) {
            merged.owner = ownerArg;
            wprintf(L"[SET] Owner  -> %s (%s)\n", ownerArg.c_str(), GetSidFriendlyName(ownerArg).c_str());
        }
        if (!groupArg.empty()) {
            merged.group = groupArg;
            wprintf(L"[SET] Group  -> %s (%s)\n", groupArg.c_str(), GetSidFriendlyName(groupArg).c_str());
        }
        if (!daclArg.empty()) {
            // Accept bare "(...)" or with "D:" prefix
            merged.dacl = (daclArg.find(L"D:") == 0) ? daclArg : L"D:" + daclArg;
            wprintf(L"[SET] DACL   -> %s\n", merged.dacl.c_str());
        }
        if (!saclArg.empty()) {
            merged.sacl = (saclArg.find(L"S:") == 0) ? saclArg : L"S:" + saclArg;
            wprintf(L"[SET] SACL   -> %s\n", merged.sacl.c_str());
        }

        if (ownerArg.empty() && groupArg.empty() && daclArg.empty() && saclArg.empty()) {
            wprintf(L"[ERR] set: no option specified. Use --owner/--group/--dacl/--sacl/--full\n");
            CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
            return FALSE;
        }

        finalSddl = BuildSddl(merged);
    }

    wprintf(L"[SET] Final SDDL: %s\n", finalSddl.c_str());

    // ── Convert SDDL string → SD ─────────────────────────────
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        finalSddl.c_str(), SDDL_REVISION_1, &pSD, nullptr))
    {
        PrintLastError(L"ConvertStringSecurityDescriptorToSecurityDescriptorW");
        CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
        return FALSE;
    }

    // ── Determine which info flags to set ────────────────────
    SECURITY_INFORMATION siFlags = 0;
    std::wstring ownerArg2 = GetArg(args, L"--owner");
    std::wstring groupArg2 = GetArg(args, L"--group");
    std::wstring daclArg2 = GetArg(args, L"--dacl");
    std::wstring saclArg2 = GetArg(args, L"--sacl");

    if (!fullArg.empty()) {
        siFlags = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;
    }
    else {
        if (!ownerArg2.empty()) siFlags |= OWNER_SECURITY_INFORMATION;
        if (!groupArg2.empty()) siFlags |= GROUP_SECURITY_INFORMATION;
        if (!daclArg2.empty())  siFlags |= DACL_SECURITY_INFORMATION;
        if (!saclArg2.empty())  siFlags |= SACL_SECURITY_INFORMATION;
    }

    // ── Apply ────────────────────────────────────────────────
    if (!SetServiceObjectSecurity(hSvc, siFlags, pSD)) {
        PrintLastError(L"SetServiceObjectSecurity");
        LocalFree(pSD);
        CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
        return FALSE;
    }

    LocalFree(pSD);
    wprintf(L"[OK] Security updated successfully.\n");

    // ── Show result ──────────────────────────────────────────
    wprintf(L"\n[INFO] New security descriptor:\n");
    wchar_t* pNew = QueryServiceSddl(hSvc);
    if (pNew) { AnalyzeSDDL(name, pNew); LocalFree(pNew); }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return TRUE;
}

// ─────────────────────────────────────────────────────────────
//  Usage
// ─────────────────────────────────────────────────────────────

void PrintUsage(const wchar_t* prog)
{
    wprintf(L"\nUsage:\n");
    wprintf(L"  %s create  <name> --path <binary> [--display <name>]\n", prog);
    wprintf(L"  %s start   <name>\n", prog);
    wprintf(L"  %s stop    <name>\n", prog);
    wprintf(L"  %s delete  <name>\n", prog);
    wprintf(L"  %s query   <name>\n", prog);
    wprintf(L"  %s set     <name> [--owner <SID>] [--group <SID>]\n", prog);
    wprintf(L"                          [--dacl  \"D:(...)\"]  [--sacl \"S:(...)\"]\n");
    wprintf(L"                          [--full  \"O:..G:..D:..S:..\"]  (overrides all)\n");
    wprintf(L"\nExamples:\n");
    wprintf(L"  %s create  MySvc --path C:\\svc.exe --display \"My Service\"\n", prog);
    wprintf(L"  %s query   MySvc\n", prog);
    wprintf(L"  %s set     MySvc --dacl \"D:(A;;FA;;;BA)(A;;FA;;;SY)\"\n", prog);
    wprintf(L"  %s set     MySvc --owner BA --group SY\n", prog);
    wprintf(L"  %s set     MySvc --owner BA --dacl \"D:(A;;FA;;;BA)\" --sacl \"S:(AU;SA;FA;;;WD)\"\n", prog);
    wprintf(L"  %s set     MySvc --full \"O:BAG:SYD:(A;;FA;;;BA)S:(AU;SA;FA;;;WD)\"\n", prog);
}

// ─────────────────────────────────────────────────────────────
//  Entry point
// ─────────────────────────────────────────────────────────────

int wmain(int argc, wchar_t* argv[])
{
    EnablePrivileges();
    wprintf(L"\n");

    if (argc < 3) {
        PrintUsage(argv[0]);
        return 1;
    }

    const wchar_t* action = argv[1];
    const wchar_t* svcName = argv[2];

    // Parse options starting from index 3
    ArgMap args = ParseArgs(argc, argv, 3);

    if (_wcsicmp(action, L"create") == 0) {
        std::wstring path = GetArg(args, L"--path");
        std::wstring display = GetArg(args, L"--display", svcName);
        if (path.empty()) {
            wprintf(L"[ERR] create requires --path <binary>\n");
            return 1;
        }
        return CreateMyService(svcName, display.c_str(), path.c_str()) ? 0 : 1;
    }
    else if (_wcsicmp(action, L"start") == 0) {
        return StartMyService(svcName) ? 0 : 1;
    }
    else if (_wcsicmp(action, L"stop") == 0) {
        return StopMyService(svcName) ? 0 : 1;
    }
    else if (_wcsicmp(action, L"delete") == 0) {
        return DeleteMyService(svcName) ? 0 : 1;
    }
    else if (_wcsicmp(action, L"query") == 0) {
        return QueryMyServiceInfo(svcName) ? 0 : 1;
    }
    else if (_wcsicmp(action, L"set") == 0) {
        return SetMyServiceSecurity(svcName, args) ? 0 : 1;
    }
    else {
        wprintf(L"[ERR] Unknown action: %s\n", action);
        PrintUsage(argv[0]);
        return 1;
    }
}