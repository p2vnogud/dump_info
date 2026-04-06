#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <winreg.h>
#include <oleauto.h>
#include <ocidl.h>
#include <comdef.h>
#include <objbase.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cstring>
#include <wintrust.h>
#include <Softpub.h>
#include <shlwapi.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shlwapi.lib")

// ============================================================
//  ANSI colour
// ============================================================
#define C_RST  L"\033[0m"
#define C_BOLD L"\033[1m"
#define C_DIM  L"\033[2m"
#define C_RED  L"\033[91m"
#define C_YEL  L"\033[93m"
#define C_GRN  L"\033[92m"
#define C_CYN  L"\033[96m"
#define C_MAG  L"\033[95m"
#define C_BLU  L"\033[94m"
#define C_WHT  L"\033[97m"
#define C_ORG  L"\033[38;5;208m"

static bool g_color = true;
#define CC(c) (g_color ? (c) : L"")

static void EnableVT()
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  m = 0;
    if (!GetConsoleMode(h, &m)) { g_color = false; return; }
    if (!SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        g_color = false;
}

// ============================================================
//  Exec-keyword classification engine
//  Classify a method/property name as potentially executable
// ============================================================
enum class ExecRisk { None, Low, Medium, High, Critical };

struct ExecKeyword {
    const wchar_t* word;
    ExecRisk        risk;
    const wchar_t* reason;
};

// Master keyword table — ordered from highest to lowest risk
static const ExecKeyword kExecKeywords[] = {
    // === CRITICAL: direct OS execution ===
    { L"shellexecute",       ExecRisk::Critical, L"ShellExecute — launch arbitrary process/URL" },
    { L"shellexecuteex",     ExecRisk::Critical, L"ShellExecuteEx — launch with elevated privs" },
    { L"createobject",       ExecRisk::Critical, L"CreateObject — instantiate arbitrary COM" },
    { L"wscript",            ExecRisk::Critical, L"WScript interface — scripting host execute" },
    { L"getobject",          ExecRisk::Critical, L"GetObject — bind moniker, WMI, ADSI exec" },
    { L"invoke",             ExecRisk::Critical, L"Invoke/InvokeVerb — shell verb execution" },
    { L"invokeverb",         ExecRisk::Critical, L"InvokeVerb — shell verb (open,runas,etc.)" },
    { L"execute",            ExecRisk::Critical, L"Execute — generic execute surface" },
    { L"execquery",          ExecRisk::Critical, L"ExecQuery — WMI query / command exec" },
    { L"execmethod",         ExecRisk::Critical, L"ExecMethod — WMI method invocation" },
    { L"execnotificationquery", ExecRisk::Critical, L"ExecNotificationQuery — WMI async exec" },
    { L"run",                ExecRisk::Critical, L"Run — process launch (WScript.Shell)" },
    { L"exec",               ExecRisk::Critical, L"Exec — child process with I/O pipes" },
    { L"createprocess",      ExecRisk::Critical, L"CreateProcess — direct process creation" },
    { L"winexec",            ExecRisk::Critical, L"WinExec — legacy process launch" },
    { L"spawn",              ExecRisk::Critical, L"Spawn — process spawn" },
    { L"launchapplication",  ExecRisk::Critical, L"LaunchApplication — app launch surface" },
    { L"startapplication",   ExecRisk::Critical, L"StartApplication — app launch surface" },
    { L"openapplication",    ExecRisk::Critical, L"OpenApplication — app launch surface" },

    // === HIGH: scripting / code injection ===
    { L"eval",               ExecRisk::High,     L"Eval — dynamic code evaluation" },
    { L"parseint",           ExecRisk::High,     L"ParseInt via script engine" },
    { L"addcode",            ExecRisk::High,     L"AddCode — inject script code" },
    { L"addtypelib",         ExecRisk::High,     L"AddTypeLib — load type library" },
    { L"parseScriptText",    ExecRisk::High,     L"ParseScriptText — inject script" },
    { L"executescripttext",  ExecRisk::High,     L"ExecuteScriptText — run injected script" },
    { L"loadtypelib",        ExecRisk::High,     L"LoadTypeLib — load arbitrary TLB" },
    { L"regsvr",             ExecRisk::High,     L"Regsvr* — DLL registration" },
    { L"runscript",          ExecRisk::High,     L"RunScript — run scripting code" },
    { L"runmacro",           ExecRisk::High,     L"RunMacro — macro execution" },
    { L"executemacro",       ExecRisk::High,     L"ExecuteMacro — macro execution" },
    { L"application",        ExecRisk::High,     L"Application property — COM app object access" },

    // === HIGH: file/DLL loading ===
    { L"loadlibrary",        ExecRisk::High,     L"LoadLibrary — load arbitrary DLL" },
    { L"loadmodule",         ExecRisk::High,     L"LoadModule — load executable module" },
    { L"loadfile",           ExecRisk::High,     L"LoadFile — arbitrary file load" },
    { L"loadurl",            ExecRisk::High,     L"LoadURL — remote code load" },
    { L"navigate",           ExecRisk::High,     L"Navigate — browser navigation (exec risk)" },
    { L"navigate2",          ExecRisk::High,     L"Navigate2 — browser navigation v2" },
    { L"open",               ExecRisk::High,     L"Open — file/process/url open" },
    { L"openfile",           ExecRisk::High,     L"OpenFile — open file by path" },
    { L"openurl",            ExecRisk::High,     L"OpenURL — open/execute URL" },
    { L"download",           ExecRisk::High,     L"Download — fetch and store file" },
    { L"downloadfile",       ExecRisk::High,     L"DownloadFile — remote file fetch" },

    // === MEDIUM: command/task scheduling ===
    { L"schedule",           ExecRisk::Medium,   L"Schedule — task scheduler interface" },
    { L"registertask",       ExecRisk::Medium,   L"RegisterTask — create scheduled task" },
    { L"createtask",         ExecRisk::Medium,   L"CreateTask — create task (older API)" },
    { L"runtask",            ExecRisk::Medium,   L"RunTask — run scheduled task" },
    { L"sendinput",          ExecRisk::Medium,   L"SendInput — synthesize keyboard/mouse" },
    { L"sendkeys",           ExecRisk::Medium,   L"SendKeys — inject keystrokes" },
    { L"postmessage",        ExecRisk::Medium,   L"PostMessage — inject window messages" },
    { L"sendmessage",        ExecRisk::Medium,   L"SendMessage — inject window messages" },
    { L"setclipboarddata",   ExecRisk::Medium,   L"SetClipboardData — clipboard manipulation" },
    { L"getclipboarddata",   ExecRisk::Medium,   L"GetClipboardData — clipboard read" },

    // === MEDIUM: registry / config write ===
    { L"regwrite",           ExecRisk::Medium,   L"RegWrite — registry write (persistence)" },
    { L"regread",            ExecRisk::Medium,   L"RegRead — registry read" },
    { L"regdelete",          ExecRisk::Medium,   L"RegDelete — registry delete" },
    { L"writefile",          ExecRisk::Medium,   L"WriteFile — arbitrary file write" },
    { L"copyfile",           ExecRisk::Medium,   L"CopyFile — file copy" },
    { L"movefile",           ExecRisk::Medium,   L"MoveFile — file move/rename" },
    { L"deletefile",         ExecRisk::Medium,   L"DeleteFile — file deletion" },
    { L"createfile",         ExecRisk::Medium,   L"CreateFile — create/open file handle" },

    // === MEDIUM: network / remote ===
    { L"connect",            ExecRisk::Medium,   L"Connect — network connection" },
    { L"send",               ExecRisk::Medium,   L"Send — data send (network/msg)" },
    { L"post",               ExecRisk::Medium,   L"Post — HTTP/data post" },
    { L"getresponse",        ExecRisk::Medium,   L"GetResponse — HTTP response" },
    { L"setheader",          ExecRisk::Medium,   L"SetHeader — HTTP header manipulation" },

    // === LOW: potentially dangerous properties ===
    { L"commandline",        ExecRisk::Low,      L"CommandLine property — process cmdline access" },
    { L"path",               ExecRisk::Low,      L"Path property — filesystem path" },
    { L"filename",           ExecRisk::Low,      L"FileName property — file path access" },
    { L"workingdirectory",   ExecRisk::Low,      L"WorkingDirectory — can affect process launch" },
    { L"environment",        ExecRisk::Low,      L"Environment — env variable access/set" },
    { L"stdin",              ExecRisk::Low,      L"StdIn — stdin pipe (with Exec)" },
    { L"stdout",             ExecRisk::Low,      L"StdOut — stdout pipe" },
    { L"stderr",             ExecRisk::Low,      L"StdErr — stderr pipe" },
};

static ExecRisk ClassifyName(const std::wstring& name)
{
    if (name.empty()) return ExecRisk::None;
    std::wstring low = name;
    std::transform(low.begin(), low.end(), low.begin(), ::towlower);

    ExecRisk best = ExecRisk::None;
    for (auto& kw : kExecKeywords) {
        if (low.find(kw.word) != std::wstring::npos) {
            if ((int)kw.risk > (int)best)
                best = kw.risk;
        }
    }
    return best;
}

static const wchar_t* ExecRiskStr(ExecRisk r) {
    switch (r) {
    case ExecRisk::Critical: return L"CRITICAL";
    case ExecRisk::High:     return L"HIGH    ";
    case ExecRisk::Medium:   return L"MEDIUM  ";
    case ExecRisk::Low:      return L"LOW     ";
    default:                 return L"NONE    ";
    }
}
static const wchar_t* ExecRiskColor(ExecRisk r) {
    switch (r) {
    case ExecRisk::Critical: return C_RED;
    case ExecRisk::High:     return C_RED;
    case ExecRisk::Medium:   return C_ORG;
    case ExecRisk::Low:      return C_YEL;
    default:                 return C_DIM;
    }
}

static const wchar_t* ExecRiskReason(const std::wstring& name)
{
    if (name.empty()) return L"";
    std::wstring low = name;
    std::transform(low.begin(), low.end(), low.begin(), ::towlower);
    for (auto& kw : kExecKeywords) {
        if (low.find(kw.word) != std::wstring::npos)
            return kw.reason;
    }
    return L"";
}

// ============================================================
//  VARTYPE → string
// ============================================================
static std::wstring VarTypeStr(VARTYPE vt)
{
    bool byref = !!(vt & VT_BYREF);
    bool arr = !!(vt & VT_ARRAY);
    vt &= VT_TYPEMASK;
    std::wstring s;
    switch (vt) {
    case VT_EMPTY:   s = L"void";       break;
    case VT_NULL:    s = L"null";       break;
    case VT_I1:      s = L"i8";         break;
    case VT_I2:      s = L"i16";        break;
    case VT_I4:      s = L"i32";        break;
    case VT_I8:      s = L"i64";        break;
    case VT_UI1:     s = L"u8";         break;
    case VT_UI2:     s = L"u16";        break;
    case VT_UI4:     s = L"u32";        break;
    case VT_UI8:     s = L"u64";        break;
    case VT_R4:      s = L"f32";        break;
    case VT_R8:      s = L"f64";        break;
    case VT_BOOL:    s = L"BOOL";       break;
    case VT_BSTR:    s = L"BSTR";       break;
    case VT_VARIANT: s = L"VARIANT";    break;
    case VT_DISPATCH:s = L"IDispatch";  break;
    case VT_UNKNOWN: s = L"IUnknown";   break;
    case VT_HRESULT: s = L"HRESULT";   break;
    case VT_PTR:     s = L"PTR";        break;
    case VT_SAFEARRAY: s = L"SAFEARRAY"; break;
    case VT_CARRAY:  s = L"CARRAY";    break;
    case VT_USERDEFINED: s = L"USERDEFINED"; break;
    case VT_LPSTR:   s = L"LPSTR";     break;
    case VT_LPWSTR:  s = L"LPWSTR";    break;
    case VT_DECIMAL: s = L"DECIMAL";   break;
    case VT_DATE:    s = L"DATE";       break;
    case VT_CY:      s = L"CURRENCY";  break;
    case VT_ERROR:   s = L"SCODE";      break;
    default: { wchar_t b[16]; swprintf_s(b, L"vt%u", vt); s = b; }
    }
    if (arr) s = L"SAFEARRAY(" + s + L")";
    if (byref) s = s + L"*";
    return s;
}

// ============================================================
//  INVOKEKIND → string
// ============================================================
static std::wstring InvokeKindStr(INVOKEKIND ik)
{
    switch (ik) {
    case INVOKE_FUNC:          return L"method  ";
    case INVOKE_PROPERTYGET:   return L"propget ";
    case INVOKE_PROPERTYPUT:   return L"propput ";
    case INVOKE_PROPERTYPUTREF:return L"propputref";
    default:                   return L"unknown ";
    }
}

// ============================================================
//  TYPEKIND → string
// ============================================================
static const wchar_t* TypeKindStr(TYPEKIND tk)
{
    switch (tk) {
    case TKIND_ENUM:       return L"enum";
    case TKIND_RECORD:     return L"struct";
    case TKIND_MODULE:     return L"module";
    case TKIND_INTERFACE:  return L"interface";
    case TKIND_DISPATCH:   return L"dispinterface";
    case TKIND_COCLASS:    return L"coclass";
    case TKIND_ALIAS:      return L"alias";
    case TKIND_UNION:      return L"union";
    default:               return L"unknown";
    }
}

// ============================================================
//  COM method/property descriptor
// ============================================================
struct MethodInfo {
    std::wstring  name;
    std::wstring  invokeKind;   // method / propget / propput
    std::wstring  retType;
    std::vector<std::pair<std::wstring, std::wstring>> params; // (type, name)
    MEMBERID      memid = 0;
    bool          isHidden = false;
    bool          isRestricted = false;
    ExecRisk      execRisk = ExecRisk::None;
    std::wstring  execReason;
};

struct InterfaceInfo {
    std::wstring            name;
    std::wstring            typeKind;
    std::wstring            iid;
    std::vector<MethodInfo> methods;
    int                     execMethodCount = 0;   // methods with risk >= Medium
    ExecRisk                worstRisk = ExecRisk::None;
};

struct TypeLibInfo {
    std::wstring              name;
    std::wstring              path;
    std::wstring              guid;
    std::vector<InterfaceInfo> interfaces;
    int                       totalMethods = 0;
    int                       execRiskMethods = 0;   // risk >= Medium
    ExecRisk                  worstRisk = ExecRisk::None;
    bool                      loadedOk = false;
    std::wstring              errorMsg;
};

// ============================================================
//  Forward declarations
// ============================================================
static bool IsMicrosoftSigned(const std::wstring& filePath);
static std::wstring RegReadString(HKEY root, const wchar_t* path, const wchar_t* name);
static DWORD RegReadDWORD(HKEY root, const wchar_t* path, const wchar_t* name, DWORD def = 0);
static bool RegReadBinary(HKEY root, const wchar_t* path, const wchar_t* name, std::vector<BYTE>& out);
static std::vector<std::wstring> RegEnumSubkeys(HKEY root, const wchar_t* path);
static bool RegKeyExists(HKEY root, const wchar_t* path);

// ============================================================
//  ITypeInfo → MethodInfo extraction
// ============================================================
static std::wstring GetTypeName(ITypeInfo* pti, const TYPEDESC& td)
{
    if (td.vt == VT_PTR && td.lptdesc)
        return GetTypeName(pti, *td.lptdesc) + L"*";
    if (td.vt == VT_SAFEARRAY && td.lptdesc)
        return L"SAFEARRAY(" + GetTypeName(pti, *td.lptdesc) + L")";
    if (td.vt == VT_USERDEFINED && pti) {
        ITypeInfo* pRef = nullptr;
        if (SUCCEEDED(pti->GetRefTypeInfo(td.hreftype, &pRef)) && pRef) {
            BSTR bName = nullptr;
            pRef->GetDocumentation(MEMBERID_NIL, &bName, nullptr, nullptr, nullptr);
            std::wstring r = bName ? bName : L"USERDEFINED";
            SysFreeString(bName);
            pRef->Release();
            return r;
        }
    }
    return VarTypeStr(td.vt);
}

static std::vector<MethodInfo> ExtractMethods(ITypeInfo* pti)
{
    std::vector<MethodInfo> out;
    if (!pti) return out;

    TYPEATTR* ta = nullptr;
    if (FAILED(pti->GetTypeAttr(&ta)) || !ta) return out;
    WORD cFuncs = ta->cFuncs;
    WORD cVars = ta->cVars;
    pti->ReleaseTypeAttr(ta);

    // --- Functions (methods + property accessors) ---
    for (WORD i = 0; i < cFuncs; i++) {
        FUNCDESC* fd = nullptr;
        if (FAILED(pti->GetFuncDesc(i, &fd)) || !fd) continue;

        MethodInfo mi;
        mi.memid = fd->memid;
        mi.isHidden = !!(fd->wFuncFlags & FUNCFLAG_FHIDDEN);
        mi.isRestricted = !!(fd->wFuncFlags & FUNCFLAG_FRESTRICTED);

        switch (fd->invkind) {
        case INVOKE_FUNC:           mi.invokeKind = L"method  "; break;
        case INVOKE_PROPERTYGET:    mi.invokeKind = L"propget "; break;
        case INVOKE_PROPERTYPUT:    mi.invokeKind = L"propput "; break;
        case INVOKE_PROPERTYPUTREF: mi.invokeKind = L"propputref"; break;
        default:                    mi.invokeKind = L"unknown "; break;
        }

        mi.retType = GetTypeName(pti, fd->elemdescFunc.tdesc);

        // Get names (index 0 = method name, rest = param names)
        UINT cNames = fd->cParams + 1;
        std::vector<BSTR> names(cNames, nullptr);
        UINT gotNames = 0;
        pti->GetNames(fd->memid, names.data(), cNames, &gotNames);
        if (gotNames > 0 && names[0]) mi.name = names[0];

        for (SHORT p = 0; p < fd->cParams; p++) {
            std::wstring pType = GetTypeName(pti, fd->lprgelemdescParam[p].tdesc);
            std::wstring pName;
            if ((UINT)(p + 1) < gotNames && names[p + 1])
                pName = names[p + 1];
            else { wchar_t buf[16]; swprintf_s(buf, L"p%d", p); pName = buf; }
            mi.params.emplace_back(pType, pName);
        }
        for (auto& b : names) SysFreeString(b);

        mi.execRisk = ClassifyName(mi.name);
        mi.execReason = ExecRiskReason(mi.name);

        pti->ReleaseFuncDesc(fd);
        out.push_back(std::move(mi));
    }

    // --- Variables / constants (may expose dangerous properties) ---
    for (WORD i = 0; i < cVars; i++) {
        VARDESC* vd = nullptr;
        if (FAILED(pti->GetVarDesc(i, &vd)) || !vd) continue;

        MethodInfo mi;
        mi.invokeKind = L"propget ";   // treat as readable property
        mi.retType = GetTypeName(pti, vd->elemdescVar.tdesc);
        mi.memid = vd->memid;

        BSTR bName = nullptr; UINT got = 0;
        pti->GetNames(vd->memid, &bName, 1, &got);
        if (got && bName) mi.name = bName;
        SysFreeString(bName);

        mi.execRisk = ClassifyName(mi.name);
        mi.execReason = ExecRiskReason(mi.name);

        pti->ReleaseVarDesc(vd);
        out.push_back(std::move(mi));
    }

    return out;
}

// ============================================================
//  Load ITypeLib from a path or from registry (TypeLib key)
// ============================================================
static std::wstring GetTypeLibPath(const std::wstring& clsid)
{
    // 1. Try CLSID -> Implemented Interfaces -> TypeLib
    wchar_t p[512];
    swprintf_s(p, L"CLSID\\%s\\TypeLib", clsid.c_str());
    std::wstring tlbid = RegReadString(HKEY_CLASSES_ROOT, p, L"");
    if (!tlbid.empty()) {
        // Find best version
        wchar_t tp[512]; swprintf_s(tp, L"TypeLib\\%s", tlbid.c_str());
        auto vers = RegEnumSubkeys(HKEY_CLASSES_ROOT, tp);
        for (auto& v : vers) {
            wchar_t vp[512]; swprintf_s(vp, L"TypeLib\\%s\\%s\\0\\win64", tlbid.c_str(), v.c_str());
            std::wstring path64 = RegReadString(HKEY_CLASSES_ROOT, vp, L"");
            if (!path64.empty()) return path64;
            swprintf_s(vp, L"TypeLib\\%s\\%s\\0\\win32", tlbid.c_str(), v.c_str());
            std::wstring path32 = RegReadString(HKEY_CLASSES_ROOT, vp, L"");
            if (!path32.empty()) return path32;
        }
    }
    // 2. InprocServer32 / LocalServer32 may be the typelib itself
    swprintf_s(p, L"CLSID\\%s\\InprocServer32", clsid.c_str());
    std::wstring ip = RegReadString(HKEY_CLASSES_ROOT, p, L"");
    if (!ip.empty()) return ip;
    swprintf_s(p, L"CLSID\\%s\\LocalServer32", clsid.c_str());
    std::wstring ls = RegReadString(HKEY_CLASSES_ROOT, p, L"");
    return ls;
}

// ============================================================
//  Core: analyse one ITypeLib
// ============================================================
static TypeLibInfo AnalyzeTypeLib(ITypeLib* pTL, const std::wstring& srcPath)
{
    TypeLibInfo info;
    info.path = srcPath;
    info.loadedOk = true;

    // Library name
    BSTR bLibName = nullptr;
    pTL->GetDocumentation(-1, &bLibName, nullptr, nullptr, nullptr);
    if (bLibName) { info.name = bLibName; SysFreeString(bLibName); }

    // GUID
    TLIBATTR* la = nullptr;
    if (SUCCEEDED(pTL->GetLibAttr(&la)) && la) {
        wchar_t guid[64];
        StringFromGUID2(la->guid, guid, 64);
        info.guid = guid;
        pTL->ReleaseTLibAttr(la);
    }

    UINT count = pTL->GetTypeInfoCount();
    for (UINT i = 0; i < count; i++) {
        ITypeInfo* pTI = nullptr;
        if (FAILED(pTL->GetTypeInfo(i, &pTI)) || !pTI) continue;

        TYPEATTR* ta = nullptr;
        if (FAILED(pTI->GetTypeAttr(&ta)) || !ta) { pTI->Release(); continue; }
        TYPEKIND tk = ta->typekind;
        GUID iid = ta->guid;
        pTI->ReleaseTypeAttr(ta);

        InterfaceInfo iface;
        iface.typeKind = TypeKindStr(tk);
        wchar_t iidStr[64]; StringFromGUID2(iid, iidStr, 64);
        iface.iid = iidStr;

        BSTR bName = nullptr;
        pTL->GetDocumentation(i, &bName, nullptr, nullptr, nullptr);
        if (bName) { iface.name = bName; SysFreeString(bName); }

        // Only dig into callable interfaces
        if (tk == TKIND_INTERFACE || tk == TKIND_DISPATCH || tk == TKIND_COCLASS) {
            iface.methods = ExtractMethods(pTI);

            for (auto& m : iface.methods) {
                info.totalMethods++;
                if (m.execRisk >= ExecRisk::Medium) {
                    info.execRiskMethods++;
                    iface.execMethodCount++;
                }
                if ((int)m.execRisk > (int)iface.worstRisk) iface.worstRisk = m.execRisk;
                if ((int)m.execRisk > (int)info.worstRisk)  info.worstRisk = m.execRisk;
            }
        }

        pTI->Release();
        info.interfaces.push_back(std::move(iface));
    }
    return info;
}

// ============================================================
//  Load typelib by file path (expand env vars first)
// ============================================================
static std::wstring ExpandEnv(const std::wstring& src)
{
    if (src.empty()) return src;
    DWORD size = ExpandEnvironmentStringsW(src.c_str(), NULL, 0);
    if (!size) return src;
    std::vector<wchar_t> buf(size);
    ExpandEnvironmentStringsW(src.c_str(), buf.data(), size);
    return std::wstring(buf.data(), size - 1);
}

static std::wstring GetExecutablePath(const std::wstring& cmdLine)
{
    if (cmdLine.empty()) return L"";
    std::wstring path;
    if (cmdLine[0] == L'"') {
        size_t end = cmdLine.find(L'"', 1);
        path = (end != std::wstring::npos) ? cmdLine.substr(1, end - 1) : cmdLine.substr(1);
    }
    else {
        size_t sp = cmdLine.find(L' ');
        path = (sp != std::wstring::npos) ? cmdLine.substr(0, sp) : cmdLine;
    }
    return ExpandEnv(path);
}

static TypeLibInfo LoadAndAnalyzeTypeLib(const std::wstring& path)
{
    TypeLibInfo info;
    info.path = path;
    if (path.empty()) {
        info.errorMsg = L"No path provided";
        return info;
    }

    std::wstring expanded = ExpandEnv(path);
    // Strip args
    std::wstring exe = GetExecutablePath(expanded);

    ITypeLib* pTL = nullptr;
    HRESULT hr = LoadTypeLib(exe.c_str(), &pTL);
    if (FAILED(hr) || !pTL) {
        // Try LoadTypeLibEx with REGKIND_NONE
        hr = LoadTypeLibEx(exe.c_str(), REGKIND_NONE, &pTL);
    }
    if (FAILED(hr) || !pTL) {
        wchar_t msg[128];
        swprintf_s(msg, L"LoadTypeLib failed: HRESULT 0x%08X", (unsigned)hr);
        info.errorMsg = msg;
        return info;
    }

    info = AnalyzeTypeLib(pTL, exe);
    pTL->Release();
    return info;
}

// ============================================================
//  IDispatch live probe — enumerate via GetTypeInfo + GetIDsOfNames
// ============================================================
struct DispatchProbe {
    bool         succeeded = false;
    std::wstring errorMsg;
    std::vector<MethodInfo> methods;  // methods discovered via ITypeInfo
    ExecRisk     worstRisk = ExecRisk::None;
};

static DispatchProbe ProbeViaDispatch(const std::wstring& clsid)
{
    DispatchProbe result;

    CLSID cls = {};
    if (FAILED(CLSIDFromString(clsid.c_str(), &cls))) {
        result.errorMsg = L"Invalid CLSID";
        return result;
    }

    IDispatch* pDisp = nullptr;
    // Try GetActiveObject first (existing instance)
    HRESULT hr = GetActiveObject(cls, nullptr, (IUnknown**)&pDisp);
    if (FAILED(hr) || !pDisp) {
        // Try CoCreateInstance
        hr = CoCreateInstance(cls, nullptr, CLSCTX_ALL,
            IID_IDispatch, (void**)&pDisp);
    }
    if (FAILED(hr) || !pDisp) {
        wchar_t msg[128];
        swprintf_s(msg, L"Cannot instantiate: 0x%08X", (unsigned)hr);
        result.errorMsg = msg;
        return result;
    }

    // Get ITypeInfo from the live object
    ITypeInfo* pTI = nullptr;
    hr = pDisp->GetTypeInfo(0, LOCALE_USER_DEFAULT, &pTI);
    if (SUCCEEDED(hr) && pTI) {
        result.methods = ExtractMethods(pTI);
        result.succeeded = true;
        for (auto& m : result.methods)
            if ((int)m.execRisk > (int)result.worstRisk)
                result.worstRisk = m.execRisk;
        pTI->Release();
    }
    else {
        result.errorMsg = L"IDispatch::GetTypeInfo failed (no type library attached)";
    }

    pDisp->Release();
    return result;
}

// ============================================================
//  Print typelib analysis
// ============================================================
static void PrintTypeLibInfo(const TypeLibInfo& tl, bool execOnly, int indent = 2)
{
    wchar_t pad[33] = {}; for (int i = 0; i < indent && i < 32; i++) pad[i] = L' ';

    if (!tl.loadedOk) {
        wprintf(L"%s%s[!] TypeLib load error: %s%s\n", pad, CC(C_RED), tl.errorMsg.c_str(), CC(C_RST));
        return;
    }

    wprintf(L"%s%sTypeLib%s: %s  (%s)\n", pad, CC(C_BOLD), CC(C_RST),
        tl.name.empty() ? L"(unnamed)" : tl.name.c_str(), tl.guid.c_str());
    wprintf(L"%sPath   : %s\n", pad, tl.path.c_str());
    wprintf(L"%sMethods: %d total,  %s%d with exec risk%s\n",
        pad, tl.totalMethods,
        tl.execRiskMethods > 0 ? CC(C_RED) : CC(C_GRN),
        tl.execRiskMethods, CC(C_RST));

    for (auto& iface : tl.interfaces) {
        if (execOnly && iface.execMethodCount == 0) continue;

        bool hasAny = !iface.methods.empty();
        if (execOnly && !hasAny) continue;

        wprintf(L"\n%s  %s[%s]%s %s%s%s",
            pad,
            CC(C_CYN), iface.typeKind.c_str(), CC(C_RST),
            CC(C_WHT), iface.name.empty() ? L"(unnamed)" : iface.name.c_str(), CC(C_RST));
        if (!iface.iid.empty() && iface.iid != L"{00000000-0000-0000-0000-000000000000}")
            wprintf(L"  %s%s%s", CC(C_DIM), iface.iid.c_str(), CC(C_RST));
        if (iface.execMethodCount > 0)
            wprintf(L"  %s<-- %d exec-capable method(s)>%s",
                CC(ExecRiskColor(iface.worstRisk)), iface.execMethodCount, CC(C_RST));
        wprintf(L"\n");

        wprintf(L"%s    %s%-12s %-12s %-24s  Signature%s\n",
            pad, CC(C_DIM), L"Kind", L"ExecRisk", L"Name", CC(C_RST));
        wprintf(L"%s    %s%s%s\n", pad, CC(C_DIM),
            L"-----------------------------------------------------------------------", CC(C_RST));

        for (auto& m : iface.methods) {
            if (execOnly && m.execRisk < ExecRisk::Medium) continue;
            if (m.isRestricted && m.execRisk == ExecRisk::None) continue;

            const wchar_t* rColor = ExecRiskColor(m.execRisk);
            const wchar_t* rStr = (m.execRisk == ExecRisk::None) ? L"       " : ExecRiskStr(m.execRisk);

            // Build signature
            std::wstring sig = m.retType + L" " + (m.name.empty() ? L"<unnamed>" : m.name) + L"(";
            for (size_t pi = 0; pi < m.params.size(); pi++) {
                if (pi) sig += L", ";
                sig += m.params[pi].first + L" " + m.params[pi].second;
            }
            sig += L")";

            wprintf(L"%s    %s%-12s%s %s%-12s%s %-24s  %s\n",
                pad,
                CC(C_DIM), m.invokeKind.c_str(), CC(C_RST),
                CC(rColor), rStr, CC(C_RST),
                (m.name.empty() ? L"<unnamed>" : m.name.c_str()),
                sig.c_str());

            if (m.execRisk >= ExecRisk::Low && !m.execReason.empty())
                wprintf(L"%s      %s-> %s%s\n", pad, CC(rColor), m.execReason.c_str(), CC(C_RST));
        }
    }
}

// ============================================================
//  Registry helpers
// ============================================================
static bool RegReadBinary(HKEY root, const wchar_t* path,
    const wchar_t* name, std::vector<BYTE>& out)
{
    HKEY hk = NULL;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &hk) != ERROR_SUCCESS) return false;
    DWORD type = 0, size = 0;
    LONG r = RegQueryValueExW(hk, name, NULL, &type, NULL, &size);
    if (r != ERROR_SUCCESS || type != REG_BINARY || size == 0) { RegCloseKey(hk); return false; }
    out.resize(size);
    r = RegQueryValueExW(hk, name, NULL, NULL, out.data(), &size);
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

static std::wstring RegReadString(HKEY root, const wchar_t* path, const wchar_t* name)
{
    HKEY hk = NULL;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &hk) != ERROR_SUCCESS) return L"";
    wchar_t buf[4096] = {};
    DWORD sz = sizeof(buf) - sizeof(wchar_t);
    LONG r = RegQueryValueExW(hk, name, NULL, NULL, (LPBYTE)buf, &sz);
    RegCloseKey(hk);
    if (r == ERROR_SUCCESS) {
        for (wchar_t* p = buf; *p; p++) if (*p < 0x20) *p = L'?';
        return buf;
    }
    return L"";
}

static DWORD RegReadDWORD(HKEY root, const wchar_t* path, const wchar_t* name, DWORD def)
{
    HKEY hk = NULL;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &hk) != ERROR_SUCCESS) return def;
    DWORD val = def, sz = sizeof(DWORD);
    RegQueryValueExW(hk, name, NULL, NULL, (LPBYTE)&val, &sz);
    RegCloseKey(hk);
    return val;
}

static std::vector<std::wstring> RegEnumSubkeys(HKEY root, const wchar_t* path)
{
    std::vector<std::wstring> keys;
    HKEY hk = NULL;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &hk) != ERROR_SUCCESS) return keys;
    wchar_t name[512]; DWORD idx = 0, sz;
    while (true) {
        sz = 512;
        if (RegEnumKeyExW(hk, idx++, name, &sz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        keys.push_back(name);
    }
    RegCloseKey(hk);
    return keys;
}

static bool RegKeyExists(HKEY root, const wchar_t* path)
{
    HKEY hk = NULL;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &hk) != ERROR_SUCCESS) return false;
    RegCloseKey(hk); return true;
}

// ============================================================
//  WinVerifyTrust
// ============================================================
static bool IsMicrosoftSigned(const std::wstring& filePath)
{
    if (filePath.empty() || !PathFileExistsW(filePath.c_str())) return false;
    WINTRUST_FILE_INFO fi = { sizeof(WINTRUST_FILE_INFO), filePath.c_str() };
    WINTRUST_DATA wd = { sizeof(WINTRUST_DATA) };
    wd.dwUIChoice = WTD_UI_NONE;
    wd.dwProvFlags = WTD_SAFER_FLAG | WTD_USE_DEFAULT_OSVER_CHECK;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    GUID pol = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    return (WinVerifyTrust(NULL, &pol, &wd) == ERROR_SUCCESS);
}

// ============================================================
//  Impersonation / Auth level decode
// ============================================================
static std::wstring ImpLevelDecode(const std::wstring& raw)
{
    if (raw.empty()) return L"2 - Identify (system default)";
    DWORD val = (raw[0] == L'0' && (raw[1] == L'x' || raw[1] == L'X'))
        ? (DWORD)wcstoul(raw.c_str(), nullptr, 16)
        : (DWORD)wcstoul(raw.c_str(), nullptr, 10);
    switch (val) {
    case 1: return L"1 - Anonymous";
    case 2: return L"2 - Identify (system default)";
    case 3: return L"3 - Impersonate";
    case 4: return L"4 - Delegate";
    default: return L"0 - Default (usually Identify)";
    }
}
static std::wstring AuthLevelDecode(const std::wstring& raw)
{
    if (raw.empty()) return L"0 - Default";
    DWORD val = (raw[0] == L'0' && (raw[1] == L'x' || raw[1] == L'X'))
        ? (DWORD)wcstoul(raw.c_str(), nullptr, 16)
        : (DWORD)wcstoul(raw.c_str(), nullptr, 10);
    switch (val) {
    case 1: return L"1 - None";
    case 2: return L"2 - Connect";
    case 3: return L"3 - Call";
    case 4: return L"4 - Packet";
    case 5: return L"5 - PacketIntegrity";
    case 6: return L"6 - PacketPrivacy";
    default: return L"0 - Default (usually Packet)";
    }
}

// ============================================================
//  ProgID / CLSID / AppID resolution chain
// ============================================================
static std::wstring ProgIDtoCLSID(const std::wstring& progid)
{
    wchar_t p[512]; swprintf_s(p, L"%s\\CLSID", progid.c_str());
    std::wstring r = RegReadString(HKEY_CLASSES_ROOT, p, L"");
    if (!r.empty()) return r;
    swprintf_s(p, L"SOFTWARE\\Classes\\%s\\CLSID", progid.c_str());
    return RegReadString(HKEY_LOCAL_MACHINE, p, L"");
}

static std::wstring CLSIDtoAppID(const std::wstring& clsid)
{
    wchar_t p[512]; swprintf_s(p, L"CLSID\\%s", clsid.c_str());
    std::wstring r = RegReadString(HKEY_CLASSES_ROOT, p, L"AppID");
    if (!r.empty()) return r;
    swprintf_s(p, L"SOFTWARE\\Classes\\CLSID\\%s", clsid.c_str());
    return RegReadString(HKEY_LOCAL_MACHINE, p, L"AppID");
}

struct ResolvedCOM {
    std::wstring appid, clsid, progid, note;
};

static ResolvedCOM Resolve(const std::wstring& input)
{
    ResolvedCOM r;
    if (input.size() >= 38 && input[0] == L'{') {
        wchar_t t1[512], t2[512];
        swprintf_s(t1, L"SOFTWARE\\Classes\\AppID\\%s", input.c_str());
        swprintf_s(t2, L"AppID\\%s", input.c_str());
        if (RegKeyExists(HKEY_LOCAL_MACHINE, t1) || RegKeyExists(HKEY_CLASSES_ROOT, t2)) {
            r.appid = input; r.note = L"GUID -> AppID key found"; return r;
        }
        std::wstring aid = CLSIDtoAppID(input);
        if (!aid.empty()) { r.clsid = input; r.appid = aid; r.note = L"CLSID -> AppID"; return r; }
        r.appid = input; r.note = L"GUID (trying anyway)"; return r;
    }
    std::wstring clsid = ProgIDtoCLSID(input);
    if (!clsid.empty()) {
        r.progid = input; r.clsid = clsid;
        r.appid = CLSIDtoAppID(clsid);
        r.note = L"ProgID -> CLSID -> AppID"; return r;
    }
    auto keys = RegEnumSubkeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\AppID");
    for (auto& k : keys) {
        wchar_t p2[512]; swprintf_s(p2, L"SOFTWARE\\Classes\\AppID\\%s", k.c_str());
        std::wstring fn = RegReadString(HKEY_LOCAL_MACHINE, p2, L"");
        if (_wcsicmp(fn.c_str(), input.c_str()) == 0) { r.appid = k; r.note = L"Friendly name"; return r; }
    }
    r.note = L"Could not resolve"; return r;
}

// ============================================================
//  SID / ACE / SD helpers (kept from v4)
// ============================================================
static std::wstring SidToName(PSID sid)
{
    if (!sid || !IsValidSid(sid)) return L"<invalid-SID>";
    wchar_t acct[256] = {}, dom[256] = {};
    DWORD as = 256, ds = 256; SID_NAME_USE use;
    if (LookupAccountSidW(NULL, sid, acct, &as, dom, &ds, &use)) {
        std::wstring r;
        if (ds > 1 && dom[0]) { r = dom; r += L"\\"; }
        r += acct; return r;
    }
    LPWSTR str = NULL; ConvertSidToStringSidW(sid, &str);
    std::wstring r = str ? str : L"<unknown>"; if (str) LocalFree(str); return r;
}
static std::wstring SidToStr(PSID sid)
{
    LPWSTR s = NULL; ConvertSidToStringSidW(sid, &s);
    std::wstring r = s ? s : L""; if (s) LocalFree(s); return r;
}
#define COM_RIGHTS_EXECUTE         0x01
#define COM_RIGHTS_EXECUTE_LOCAL   0x02
#define COM_RIGHTS_EXECUTE_REMOTE  0x04
#define COM_RIGHTS_ACTIVATE_LOCAL  0x08
#define COM_RIGHTS_ACTIVATE_REMOTE 0x10

static std::wstring ComMaskStr(DWORD mask)
{
    wchar_t buf[256] = {};
    if (mask & COM_RIGHTS_EXECUTE)         wcscat_s(buf, L"Execute ");
    if (mask & COM_RIGHTS_EXECUTE_LOCAL)   wcscat_s(buf, L"ExecLocal ");
    if (mask & COM_RIGHTS_EXECUTE_REMOTE)  wcscat_s(buf, L"ExecRemote ");
    if (mask & COM_RIGHTS_ACTIVATE_LOCAL)  wcscat_s(buf, L"ActLocal ");
    if (mask & COM_RIGHTS_ACTIVATE_REMOTE) wcscat_s(buf, L"ActRemote ");
    if (!buf[0]) swprintf_s(buf, L"0x%08X", mask);
    return buf;
}
static const wchar_t* AceTypeName(BYTE t)
{
    switch (t) {
    case ACCESS_ALLOWED_ACE_TYPE: return L"Allow";
    case ACCESS_DENIED_ACE_TYPE:  return L"Deny ";
    default:                      return L"Other";
    }
}
struct AceEntry { bool allow; DWORD mask; std::wstring sidStr, sidName; };

static std::vector<AceEntry> ExtractACEs(PACL acl)
{
    std::vector<AceEntry> out;
    if (!acl) return out;
    ACL_SIZE_INFORMATION asi = {}; GetAclInformation(acl, &asi, sizeof(asi), AclSizeInformation);
    for (DWORD i = 0; i < asi.AceCount; i++) {
        LPVOID p = NULL; if (!GetAce(acl, i, &p)) continue;
        ACE_HEADER* h = (ACE_HEADER*)p;
        if (h->AceType != ACCESS_ALLOWED_ACE_TYPE && h->AceType != ACCESS_DENIED_ACE_TYPE &&
            h->AceType != ACCESS_ALLOWED_OBJECT_ACE_TYPE && h->AceType != ACCESS_DENIED_OBJECT_ACE_TYPE) continue;
        ACCESS_ALLOWED_ACE* a = (ACCESS_ALLOWED_ACE*)p;
        PSID sid = (PSID)&a->SidStart;
        AceEntry e;
        e.allow = (h->AceType == ACCESS_ALLOWED_ACE_TYPE || h->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE);
        e.mask = a->Mask; e.sidStr = SidToStr(sid); e.sidName = SidToName(sid);
        out.push_back(e);
    }
    return out;
}
static std::vector<AceEntry> BinToACEs(const std::vector<BYTE>& bin)
{
    if (bin.empty()) return {};
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)(void*)bin.data();
    PACL acl = NULL; BOOL p = FALSE, d = FALSE;
    GetSecurityDescriptorDacl(sd, &p, &acl, &d);
    return ExtractACEs(acl);
}
static void PrintSD(BYTE* bin, DWORD, int indent)
{
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)bin;
    wchar_t pad[33] = {}; for (int i = 0; i < indent && i < 32; i++) pad[i] = L' ';
    LPWSTR sddl = NULL;
    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
        sd, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
        DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, &sddl, NULL))
    {
        wprintf(L"%s%sSDDL%s: %s\n", pad, CC(C_CYN), CC(C_RST), sddl); LocalFree(sddl);
    }
    PSID own = NULL; BOOL od = FALSE;
    if (GetSecurityDescriptorOwner(sd, &own, &od) && own)
        wprintf(L"%sOwner: %s\n", pad, SidToName(own).c_str());
    PACL dacl = NULL; BOOL dp = FALSE, dd = FALSE;
    GetSecurityDescriptorDacl(sd, &dp, &dacl, &dd);
    if (!dp) { wprintf(L"%s%sDACL: NULL (everyone granted)%s\n", pad, CC(C_YEL), CC(C_RST)); }
    else if (!dacl) { wprintf(L"%s%sDACL: Empty (everyone denied)%s\n", pad, CC(C_RED), CC(C_RST)); }
    else {
        ACL_SIZE_INFORMATION asi = {}; GetAclInformation(dacl, &asi, sizeof(asi), AclSizeInformation);
        wprintf(L"%sDACL: %lu ACE(s)%s\n", pad, asi.AceCount, dd ? L" [default]" : L"");
        for (DWORD i = 0; i < asi.AceCount; i++) {
            LPVOID p2 = NULL; if (!GetAce(dacl, i, &p2)) continue;
            ACE_HEADER* h = (ACE_HEADER*)p2;
            PSID sid = NULL; DWORD mask = 0;
            if (h->AceType == ACCESS_ALLOWED_ACE_TYPE || h->AceType == ACCESS_DENIED_ACE_TYPE) {
                ACCESS_ALLOWED_ACE* a = (ACCESS_ALLOWED_ACE*)p2; mask = a->Mask; sid = (PSID)&a->SidStart;
            }
            bool isA = (h->AceType == ACCESS_ALLOWED_ACE_TYPE || h->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE);
            std::wstring sn = sid ? SidToName(sid) : L"<no-SID>";
            wprintf(L"%s  [%lu] %s%s%s  %-40s  %s%s%s\n",
                pad, i, isA ? CC(C_GRN) : CC(C_RED), AceTypeName(h->AceType), CC(C_RST),
                sn.c_str(), CC(C_MAG), ComMaskStr(mask).c_str(), CC(C_RST));
        }
    }
}

// ============================================================
//  Server type detection
// ============================================================
enum class SrvType { Unknown, InProc, LocalServer, Service, Surrogate };
struct ServerInfo {
    SrvType      type = SrvType::Unknown;
    std::wstring imagePath, threadingModel, serviceName, serviceAccount, progID, typeLabel;
    bool         imgMissing = false, imgWritable = false, imgSigned = false;
};

static std::wstring ServiceAccount(const std::wstring& svcName)
{
    if (svcName.empty()) return L"";
    wchar_t p[512]; swprintf_s(p, L"SYSTEM\\CurrentControlSet\\Services\\%s", svcName.c_str());
    std::wstring acct = RegReadString(HKEY_LOCAL_MACHINE, p, L"ObjectName");
    if (acct.empty()) acct = RegReadString(HKEY_LOCAL_MACHINE, p, L"ServiceAccount");
    if (acct.empty()) {
        std::wstring img = RegReadString(HKEY_LOCAL_MACHINE, p, L"ImagePath");
        if (!img.empty()) acct = L"LocalSystem (default)";
    }
    return acct;
}

static void CheckImage(ServerInfo& si, const std::wstring& cmdLine)
{
    if (cmdLine.empty()) return;
    // Strip args
    std::wstring path;
    if (cmdLine[0] == L'"') {
        size_t en = cmdLine.find(L'"', 1);
        path = (en != std::wstring::npos) ? cmdLine.substr(1, en - 1) : cmdLine.substr(1);
    }
    else {
        size_t sp = cmdLine.find(L' ');
        path = (sp != std::wstring::npos) ? cmdLine.substr(0, sp) : cmdLine;
    }
    si.imagePath = ExpandEnv(path);
    if (si.imagePath.empty()) return;
    DWORD attr = GetFileAttributesW(si.imagePath.c_str());
    si.imgMissing = (attr == INVALID_FILE_ATTRIBUTES);
    if (!si.imgMissing) {
        si.imgSigned = IsMicrosoftSigned(si.imagePath);
        HANDLE hf = CreateFileW(si.imagePath.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) { CloseHandle(hf); si.imgWritable = true; }
    }
}

static ServerInfo DetectServerType(const std::wstring& clsid, const std::wstring& svcName, const std::wstring& dllSurrogate)
{
    ServerInfo si;
    wchar_t sub[600];
    if (!svcName.empty()) {
        si.type = SrvType::Service; si.serviceName = svcName;
        si.serviceAccount = ServiceAccount(svcName);
        if (si.serviceAccount.empty()) si.serviceAccount = L"LocalSystem (default)";
        si.typeLabel = L"Windows Service";
        if (!clsid.empty()) {
            swprintf_s(sub, L"CLSID\\%s\\LocalServer32", clsid.c_str());
            std::wstring img = RegReadString(HKEY_CLASSES_ROOT, sub, L"");
            if (!img.empty()) CheckImage(si, img);
        }
        return si;
    }
    if (clsid.empty()) { si.typeLabel = L"Unknown"; return si; }
    swprintf_s(sub, L"CLSID\\%s\\LocalServer32", clsid.c_str());
    std::wstring ls32 = RegReadString(HKEY_CLASSES_ROOT, sub, L"");
    if (!ls32.empty()) {
        si.type = SrvType::LocalServer; si.typeLabel = L"LocalServer32 (out-of-process EXE)";
        CheckImage(si, ls32); return si;
    }
    swprintf_s(sub, L"CLSID\\%s\\InprocServer32", clsid.c_str());
    std::wstring ip32 = RegReadString(HKEY_CLASSES_ROOT, sub, L"");
    std::wstring tm = RegReadString(HKEY_CLASSES_ROOT, sub, L"ThreadingModel");
    if (!ip32.empty()) {
        si.type = dllSurrogate.empty() ? SrvType::InProc : SrvType::Surrogate;
        si.typeLabel = dllSurrogate.empty()
            ? L"InprocServer32 (in-process DLL)"
            : L"DLL Surrogate (dllhost.exe)";
        si.threadingModel = tm; CheckImage(si, ip32); return si;
    }
    si.typeLabel = L"Unknown (no LocalServer32/InprocServer32)";
    return si;
}

static std::vector<std::wstring> FindCLSIDs(const std::wstring& appid, const std::wstring& hintCLSID)
{
    std::vector<std::wstring> result;
    if (!hintCLSID.empty()) result.push_back(hintCLSID);
    HKEY hc = NULL;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &hc) != ERROR_SUCCESS) return result;
    wchar_t cn[256]; DWORD idx = 0, sz;
    while (true) {
        sz = 256;
        if (RegEnumKeyExW(hc, idx++, cn, &sz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        bool already = false;
        for (auto& c : result) if (_wcsicmp(c.c_str(), cn) == 0) { already = true; break; }
        if (already) continue;
        wchar_t su[512]; swprintf_s(su, L"CLSID\\%s", cn);
        std::wstring aid = RegReadString(HKEY_CLASSES_ROOT, su, L"AppID");
        if (_wcsicmp(aid.c_str(), appid.c_str()) == 0) result.push_back(cn);
    }
    RegCloseKey(hc);
    return result;
}

// ============================================================
//  Identity / Surface / Risk (kept from v4, slightly trimmed)
// ============================================================
struct Identity {
    std::wstring account, resolved, remark;
    bool isPrivileged = false;
};
static Identity ResolveIdentity(const std::wstring& runas, const ServerInfo& sv)
{
    Identity id;
    if (!sv.serviceAccount.empty()) {
        id.account = L"(service) " + sv.serviceName;
        id.resolved = sv.serviceAccount;
        std::wstring low = sv.serviceAccount;
        std::transform(low.begin(), low.end(), low.begin(), ::towlower);
        id.isPrivileged = (low.find(L"localsystem") != std::wstring::npos || low == L"system");
        id.remark = id.isPrivileged ? L"SYSTEM service — PrivEsc risk if non-admin can launch"
            : L"Service: " + sv.serviceAccount;
        return id;
    }
    id.account = runas;
    if (runas.empty()) { id.resolved = L"Launching User"; id.remark = L"No privilege boundary"; return id; }
    std::wstring low = runas;
    std::transform(low.begin(), low.end(), low.begin(), ::towlower);
    if (low == L"interactive user") { id.resolved = L"Interactive User"; id.remark = L"No privilege boundary"; }
    else if (low == L"system" || low == L"nt authority\\system") {
        id.resolved = L"NT AUTHORITY\\SYSTEM"; id.isPrivileged = true;
        id.remark = L"SYSTEM — HIGH privilege escalation risk";
    }
    else { id.resolved = runas; id.remark = L"Specific account — verify manually"; }
    return id;
}

static const struct { const wchar_t* sid; const wchar_t* name; } kPrincipals[] = {
    { L"S-1-1-0",      L"Everyone"             },
    { L"S-1-5-11",     L"Authenticated Users"  },
    { L"S-1-5-7",      L"Anonymous Logon"      },
    { L"S-1-5-18",     L"SYSTEM"               },
    { L"S-1-5-32-544", L"Administrators"       },
    { L"S-1-5-32-562", L"Distributed COM Users"},
    { L"S-1-5-4",      L"Interactive"          },
    { L"S-1-5-2",      L"Network"              },
};

struct SurfaceRow { std::wstring principal; bool ll, rl, la, ra; };
static DWORD EffMask(const std::vector<AceEntry>& aces, const wchar_t* sid)
{
    DWORD allow = 0, deny = 0;
    for (auto& a : aces) if (_wcsicmp(a.sidStr.c_str(), sid) == 0) {
        if (a.allow) allow |= a.mask; else deny |= a.mask;
    }
    return allow & ~deny;
}
static std::vector<SurfaceRow> ComputeSurface(
    const std::vector<AceEntry>& la, const std::vector<AceEntry>& aa,
    const std::vector<AceEntry>& mlr, const std::vector<AceEntry>& mar)
{
    std::vector<SurfaceRow> rows;
    for (auto& pr : kPrincipals) {
        DWORD lm = EffMask(la, pr.sid), am = EffMask(aa, pr.sid);
        DWORD lrm = EffMask(mlr, pr.sid), arm = EffMask(mar, pr.sid);
        if (!lm && !am && !lrm && !arm) continue;
        DWORD effL = lrm ? (lm & lrm) : lm;
        DWORD effA = arm ? (am & arm) : am;
        SurfaceRow r;
        r.principal = pr.name;
        r.ll = !!(effL & (COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL | COM_RIGHTS_ACTIVATE_LOCAL));
        r.rl = !!(effL & (COM_RIGHTS_EXECUTE_REMOTE | COM_RIGHTS_ACTIVATE_REMOTE));
        r.la = !!(effA & (COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL));
        r.ra = !!(effA & COM_RIGHTS_EXECUTE_REMOTE);
        rows.push_back(r);
    }
    return rows;
}

enum class RiskLevel { None, Low, Medium, High, Critical };
struct RiskResult {
    RiskLevel level = RiskLevel::None;
    bool privesc = false, lateral = false, hijack = false, autoElev = false, dcomOpen = false;
    std::vector<std::wstring> reasons, mitigations;
};
static const wchar_t* RiskLevelStr(RiskLevel l)
{
    switch (l) {
    case RiskLevel::Critical: return L"CRITICAL"; case RiskLevel::High: return L"HIGH    ";
    case RiskLevel::Medium: return L"MEDIUM  "; case RiskLevel::Low: return L"LOW     "; default: return L"NONE    ";
    }
}
static const wchar_t* RiskLevelColor(RiskLevel l)
{
    switch (l) {
    case RiskLevel::Critical: case RiskLevel::High: return C_RED;
    case RiskLevel::Medium: return C_ORG; case RiskLevel::Low: return C_YEL; default: return C_GRN;
    }
}

static RiskResult EvaluateRisk(const Identity& id, const ServerInfo& sv,
    const std::vector<SurfaceRow>& surf, bool elevEnabled, const TypeLibInfo& tl)
{
    RiskResult r;
    bool anyRemote = false;
    for (auto& row : surf) if (row.rl || row.ra) { anyRemote = true; break; }
    r.dcomOpen = anyRemote;

    if (id.isPrivileged)
        for (auto& row : surf)
            if ((row.principal == L"Everyone" || row.principal == L"Authenticated Users" ||
                row.principal == L"Interactive" || row.principal == L"Network") && (row.ll || row.rl)) {
                r.privesc = true;
                r.reasons.push_back(L"Server runs as [" + id.resolved + L"] and [" + row.principal + L"] can launch");
            }
    for (auto& row : surf)
        if (row.principal == L"Everyone" || row.principal == L"Authenticated Users" || row.principal == L"Network") {
            if (row.rl) { r.lateral = true; r.reasons.push_back(L"Remote LAUNCH for " + row.principal); }
            if (row.ra) { r.lateral = true; r.reasons.push_back(L"Remote ACCESS for " + row.principal); }
        }
    if (sv.imgMissing) { r.hijack = true; r.reasons.push_back(L"Binary NOT FOUND: " + sv.imagePath); }
    if (sv.imgWritable) { r.hijack = true; r.reasons.push_back(L"Binary WRITABLE: " + sv.imagePath); }
    if (elevEnabled) { r.autoElev = true; r.reasons.push_back(L"Elevation\\Enabled=1 — UAC bypass surface"); }

    // --- NEW: typelib exec-capable method risk ---
    if (tl.loadedOk && tl.execRiskMethods > 0) {
        r.reasons.push_back(L"TypeLib exposes " + std::to_wstring(tl.execRiskMethods) +
            L" exec-capable method(s) — worst: " + ExecRiskStr(tl.worstRisk));
        // Bump overall risk if typelib has Critical/High exec methods
        if (tl.worstRisk == ExecRisk::Critical && id.isPrivileged)
            r.reasons.push_back(L"CRITICAL exec method on privileged server — direct PrivEsc/RCE surface");
    }

    if (!anyRemote)          r.mitigations.push_back(L"Remote activation blocked");
    if (!id.isPrivileged)    r.mitigations.push_back(L"Runs as calling user — no privilege gain");
    if (!sv.imgMissing && !sv.imgWritable && !sv.imagePath.empty())
        r.mitigations.push_back(L"Binary exists and not writable");
    if (sv.imgSigned && !sv.imgMissing)
        r.mitigations.push_back(L"Binary is Authenticode-signed");

    int score = 0;
    if (r.privesc)  score += 40;
    if (r.lateral)  score += 25;
    if (r.hijack)   score += 30;
    if (r.autoElev) score += 20;
    if (tl.loadedOk && tl.worstRisk >= ExecRisk::Critical) score += 20;
    else if (tl.loadedOk && tl.worstRisk >= ExecRisk::High) score += 10;

    if (score >= 60) r.level = RiskLevel::Critical;
    else if (score >= 40) r.level = RiskLevel::High;
    else if (score >= 20) r.level = RiskLevel::Medium;
    else if (score > 0)   r.level = RiskLevel::Low;
    else                  r.level = RiskLevel::None;
    return r;
}

// ============================================================
//  MAIN DUMP — one AppID (full detail)
// ============================================================
static void DumpAppID(const ResolvedCOM& res, bool brief,
    bool doTypelib, bool execOnly, bool doDispatch, bool scanMode = false)
{
    if (!scanMode) {
        wprintf(L"\n%s+===========================================================+%s\n", CC(C_YEL), CC(C_RST));
        if (!res.progid.empty()) wprintf(L"%s  Input : %s%s\n", CC(C_YEL), res.progid.c_str(), CC(C_RST));
        if (!res.clsid.empty())  wprintf(L"%s  CLSID : %s%s\n", CC(C_YEL), res.clsid.c_str(), CC(C_RST));
        wprintf(L"%s  AppID : %s%s\n", CC(C_YEL), res.appid.empty() ? L"(not resolved)" : res.appid.c_str(), CC(C_RST));
        wprintf(L"%s  Via   : %s%s\n", CC(C_YEL), res.note.c_str(), CC(C_RST));
        wprintf(L"%s+===========================================================+%s\n", CC(C_YEL), CC(C_RST));
    }
    if (res.appid.empty()) return;

    wchar_t hklmPath[512], hkcrPath[512];
    swprintf_s(hklmPath, L"SOFTWARE\\Classes\\AppID\\%s", res.appid.c_str());
    swprintf_s(hkcrPath, L"AppID\\%s", res.appid.c_str());
    HKEY hive = HKEY_LOCAL_MACHINE; const wchar_t* regPath = hklmPath;
    HKEY probe = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, hklmPath, 0, KEY_READ, &probe) == ERROR_SUCCESS) { RegCloseKey(probe); }
    else {
        if (probe) RegCloseKey(probe);
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, hkcrPath, 0, KEY_READ, &probe) == ERROR_SUCCESS) {
            RegCloseKey(probe); hive = HKEY_CLASSES_ROOT; regPath = hkcrPath;
        }
        else {
            if (probe) RegCloseKey(probe);
            if (!scanMode) wprintf(L"  %s[!] AppID key not found%s\n", CC(C_RED), CC(C_RST));
            return;
        }
    }

    auto Rs = [&](const wchar_t* v) { return RegReadString(hive, regPath, v); };
    auto Rb = [&](const wchar_t* v, std::vector<BYTE>& o) { return RegReadBinary(hive, regPath, v, o); };

    std::wstring friendly = Rs(L"");
    std::wstring runas = Rs(L"RunAs");
    std::wstring svc = Rs(L"LocalService");
    std::wstring dllsur = Rs(L"DllSurrogate");
    std::wstring remSvr = Rs(L"RemoteServerName");
    std::wstring authLvRaw = Rs(L"AuthenticationLevel");
    std::wstring impLvRaw = Rs(L"ImpersonationLevel");

    wchar_t elevPath[512]; swprintf_s(elevPath, L"%s\\Elevation", regPath);
    DWORD elevEnabled = RegReadDWORD(hive, elevPath, L"Enabled", 0);

    std::vector<std::wstring> clsids = FindCLSIDs(res.appid, res.clsid);
    std::wstring canonCLSID = clsids.empty() ? L"" : clsids[0];
    ServerInfo sv = DetectServerType(canonCLSID, svc, dllsur);
    Identity   id = ResolveIdentity(runas, sv);

    // Load permissions
    std::vector<BYTE> binLaunch, binAccess, binDefLaunch, binDefAccess, binMLR, binMAR;
    bool hasLaunch = Rb(L"LaunchPermission", binLaunch);
    bool hasAccess = Rb(L"AccessPermission", binAccess);
    const wchar_t* olePath = L"SOFTWARE\\Microsoft\\Ole";
    RegReadBinary(HKEY_LOCAL_MACHINE, olePath, L"DefaultLaunchPermission", binDefLaunch);
    RegReadBinary(HKEY_LOCAL_MACHINE, olePath, L"DefaultAccessPermission", binDefAccess);
    RegReadBinary(HKEY_LOCAL_MACHINE, olePath, L"MachineLaunchRestriction", binMLR);
    RegReadBinary(HKEY_LOCAL_MACHINE, olePath, L"MachineAccessRestriction", binMAR);

    auto launchACEs = hasLaunch ? BinToACEs(binLaunch) : BinToACEs(binDefLaunch);
    auto accessACEs = hasAccess ? BinToACEs(binAccess) : BinToACEs(binDefAccess);
    auto mlrACEs = BinToACEs(binMLR);
    auto marACEs = BinToACEs(binMAR);
    auto surf = ComputeSurface(launchACEs, accessACEs, mlrACEs, marACEs);

    // ---- TypeLib analysis ------------------------------------------------
    TypeLibInfo tlInfo;
    if (doTypelib && !canonCLSID.empty()) {
        std::wstring tlPath = GetTypeLibPath(canonCLSID);
        if (!tlPath.empty())
            tlInfo = LoadAndAnalyzeTypeLib(tlPath);
        // Also try via CLSID InprocServer32 directly
        if (!tlInfo.loadedOk && !sv.imagePath.empty())
            tlInfo = LoadAndAnalyzeTypeLib(sv.imagePath);
    }

    RiskResult risk = EvaluateRisk(id, sv, surf, elevEnabled != 0, tlInfo);

    // ---- Scan mode -------------------------------------------------------
    if (scanMode) {
        if (risk.level == RiskLevel::None && tlInfo.execRiskMethods == 0) return;
        wprintf(L"\n%s[%s]%s AppID: %s%s%s  (%s)\n",
            CC(RiskLevelColor(risk.level)), RiskLevelStr(risk.level), CC(C_RST),
            CC(C_CYN), res.appid.c_str(), CC(C_RST), friendly.c_str());
        if (!sv.imagePath.empty()) wprintf(L"  Image : %s\n", sv.imagePath.c_str());
        wprintf(L"  RunAs : %s\n", id.resolved.c_str());
        if (tlInfo.loadedOk && tlInfo.execRiskMethods > 0)
            wprintf(L"  %sExec methods: %d  worst: %s%s\n",
                CC(ExecRiskColor(tlInfo.worstRisk)), tlInfo.execRiskMethods,
                ExecRiskStr(tlInfo.worstRisk), CC(C_RST));
        for (auto& r2 : risk.reasons)
            wprintf(L"  %s-> %s%s\n", CC(RiskLevelColor(risk.level)), r2.c_str(), CC(C_RST));
        return;
    }

    if (brief) {
        if (!friendly.empty()) wprintf(L"    Name : %s\n", friendly.c_str());
        if (!runas.empty())    wprintf(L"    RunAs: %s\n", runas.c_str());
        return;
    }

    // ======== FULL OUTPUT ========

    // [Metadata]
    wprintf(L"\n  %s[Metadata]%s\n", CC(C_BOLD), CC(C_RST));
    if (!friendly.empty())  wprintf(L"    Name          : %s\n", friendly.c_str());
    if (!runas.empty())     wprintf(L"    %sRunAs%s         : %s\n", CC(C_GRN), CC(C_RST), runas.c_str());
    if (!svc.empty())       wprintf(L"    %sLocalService%s : %s\n", CC(C_GRN), CC(C_RST), svc.c_str());
    if (!dllsur.empty())    wprintf(L"    %sDllSurrogate%s : %s\n", CC(C_MAG), CC(C_RST), dllsur.c_str());
    if (!remSvr.empty())    wprintf(L"    %sRemoteServer%s : %s\n", CC(C_RED), CC(C_RST), remSvr.c_str());
    if (!authLvRaw.empty()) wprintf(L"    AuthLevel     : %s\n", AuthLevelDecode(authLvRaw).c_str());
    if (!impLvRaw.empty())  wprintf(L"    ImpLevel      : %s\n", ImpLevelDecode(impLvRaw).c_str());

    // [Server Type]
    wprintf(L"\n  %s[Server Type]%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"    %s%s%s\n", CC(C_WHT), sv.typeLabel.c_str(), CC(C_RST));
    if (!sv.imagePath.empty())
        wprintf(L"    Image         : %s%s%s\n",
            sv.imgMissing ? CC(C_RED) : (sv.imgWritable ? CC(C_YEL) : CC(C_RST)),
            sv.imagePath.c_str(), CC(C_RST));
    if (!sv.threadingModel.empty())
        wprintf(L"    ThreadingModel: %s\n", sv.threadingModel.c_str());
    if (!sv.serviceName.empty()) {
        wprintf(L"    Service Name  : %s\n", sv.serviceName.c_str());
        wprintf(L"    Service Acct  : %s%s%s\n",
            sv.serviceAccount.find(L"SYSTEM") != std::wstring::npos ? CC(C_RED) : CC(C_RST),
            sv.serviceAccount.c_str(), CC(C_RST));
    }
    if (sv.imgMissing)   wprintf(L"    %s[!] Binary NOT FOUND%s\n", CC(C_RED), CC(C_RST));
    if (sv.imgWritable)  wprintf(L"    %s[!] Binary WRITABLE%s\n", CC(C_YEL), CC(C_RST));
    if (!sv.imgMissing && sv.imgSigned) wprintf(L"    %s[+] Binary is signed%s\n", CC(C_GRN), CC(C_RST));

    // [Identity]
    wprintf(L"\n  %s[Identity]%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"    Resolved : %s%s%s\n", id.isPrivileged ? CC(C_RED) : CC(C_RST), id.resolved.c_str(), CC(C_RST));
    wprintf(L"    Remark   : %s\n", id.remark.c_str());

    // [UAC]
    wprintf(L"\n  %s[UAC Auto-Elevation]%s\n", CC(C_BOLD), CC(C_RST));
    if (elevEnabled)
        wprintf(L"    %s[!] Elevation\\Enabled = 1 — UAC bypass surface%s\n", CC(C_RED), CC(C_RST));
    else
        wprintf(L"    %s(not configured)%s\n", CC(C_DIM), CC(C_RST));

    // [CLSIDs]
    wprintf(L"\n  %s[Associated CLSIDs]%s\n", CC(C_BOLD), CC(C_RST));
    for (auto& cid : clsids) {
        wchar_t base[512]; swprintf_s(base, L"CLSID\\%s", cid.c_str());
        std::wstring fn = RegReadString(HKEY_CLASSES_ROOT, base, L"");
        wprintf(L"\n    %s%s%s  (%s)\n", CC(C_CYN), cid.c_str(), CC(C_RST), fn.c_str());
        struct { const wchar_t* sk; const wchar_t* v; const wchar_t* lbl; } subs[] = {
            {L"LocalServer32",   L"",               L"LocalServer32  "},
            {L"InprocServer32",  L"",               L"InprocServer32 "},
            {L"InprocServer32",  L"ThreadingModel", L"ThreadingModel "},
            {L"ProgID",          L"",               L"ProgID         "},
            {L"TypeLib",         L"",               L"TypeLib        "},
        };
        for (auto& se : subs) {
            wchar_t fs[600]; swprintf_s(fs, L"CLSID\\%s\\%s", cid.c_str(), se.sk);
            std::wstring v = RegReadString(HKEY_CLASSES_ROOT, fs, se.v);
            if (!v.empty()) wprintf(L"      %-16s: %s\n", se.lbl, v.c_str());
        }
    }

    // [LaunchPermission]
    wprintf(L"\n  %s[LaunchPermission]%s %s\n", CC(C_BOLD), CC(C_RST), hasLaunch ? L"" : L"(using system default)");
    if (hasLaunch) PrintSD(binLaunch.data(), (DWORD)binLaunch.size(), 4);
    else if (!binDefLaunch.empty()) PrintSD(binDefLaunch.data(), (DWORD)binDefLaunch.size(), 6);

    // [AccessPermission]
    wprintf(L"\n  %s[AccessPermission]%s %s\n", CC(C_BOLD), CC(C_RST), hasAccess ? L"" : L"(using system default)");
    if (hasAccess) PrintSD(binAccess.data(), (DWORD)binAccess.size(), 4);
    else if (!binDefAccess.empty()) PrintSD(binDefAccess.data(), (DWORD)binDefAccess.size(), 6);
    else wprintf(L"    %s(DefaultAccessPermission not set — server+SYSTEM only)%s\n", CC(C_YEL), CC(C_RST));

    // [Attack Surface]
    wprintf(L"\n  %s[Attack Surface Matrix]%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"    %-26s  LocLaunch  RemLaunch  LocAccess  RemAccess\n", L"Principal");
    wprintf(L"    %s-------------------------------------------------------------------%s\n", CC(C_DIM), CC(C_RST));
    for (auto& row : surf) {
        auto yn = [](bool v) { return v ? L"YES " : L"no  "; };
        auto col = [](bool v) { return v ? C_GRN : C_DIM; };
        wprintf(L"    %-26s  %s%s%s  %s%s%s  %s%s%s  %s%s%s\n",
            row.principal.c_str(),
            CC(col(row.ll)), yn(row.ll), CC(C_RST),
            CC(col(row.rl)), yn(row.rl), CC(C_RST),
            CC(col(row.la)), yn(row.la), CC(C_RST),
            CC(col(row.ra)), yn(row.ra), CC(C_RST));
    }

    // ================================================================
    //  [COM Interface & Method Analysis]  ← NEW SECTION
    // ================================================================
    wprintf(L"\n%s+===========================================================+%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"%s  COM Interface & Method Analysis%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"%s+===========================================================+%s\n", CC(C_BOLD), CC(C_RST));

    // --- TypeLib ---
    if (doTypelib) {
        wprintf(L"\n  %s[TypeLib — static analysis]%s\n", CC(C_BOLD), CC(C_RST));
        if (tlInfo.loadedOk) {
            PrintTypeLibInfo(tlInfo, execOnly, 4);
        }
        else if (!tlInfo.path.empty()) {
            wprintf(L"    %s[!] Load failed: %s%s\n", CC(C_YEL), tlInfo.errorMsg.c_str(), CC(C_RST));
            wprintf(L"    Path attempted: %s\n", tlInfo.path.c_str());
        }
        else {
            wprintf(L"    %s(no TypeLib path found for CLSID %s)%s\n",
                CC(C_DIM), canonCLSID.c_str(), CC(C_RST));
        }
    }

    // --- IDispatch live probe ---
    if (doDispatch && !canonCLSID.empty()) {
        wprintf(L"\n  %s[IDispatch — live object probe]%s\n", CC(C_BOLD), CC(C_RST));
        DispatchProbe dp = ProbeViaDispatch(canonCLSID);
        if (dp.succeeded) {
            wprintf(L"    %s[+] IDispatch instantiation succeeded%s\n", CC(C_GRN), CC(C_RST));
            wprintf(L"    %sMethods discovered via live ITypeInfo:%s\n", CC(C_BOLD), CC(C_RST));
            wprintf(L"    %-12s %-12s %-28s  Signature\n", L"Kind", L"ExecRisk", L"Name");
            wprintf(L"    %s---------------------------------------------------------------------------%s\n", CC(C_DIM), CC(C_RST));
            for (auto& m : dp.methods) {
                if (execOnly && m.execRisk < ExecRisk::Medium) continue;
                const wchar_t* rc = ExecRiskColor(m.execRisk);
                const wchar_t* rs = (m.execRisk == ExecRisk::None) ? L"       " : ExecRiskStr(m.execRisk);
                std::wstring sig = m.retType + L" " + (m.name.empty() ? L"<unnamed>" : m.name) + L"(";
                for (size_t pi = 0; pi < m.params.size(); pi++) {
                    if (pi) sig += L", ";
                    sig += m.params[pi].first + L" " + m.params[pi].second;
                }
                sig += L")";
                wprintf(L"    %-12s %s%-12s%s %-28s  %s\n",
                    m.invokeKind.c_str(), CC(rc), rs, CC(C_RST),
                    (m.name.empty() ? L"<unnamed>" : m.name.c_str()), sig.c_str());
                if (m.execRisk >= ExecRisk::Low && !m.execReason.empty())
                    wprintf(L"      %s-> %s%s\n", CC(rc), m.execReason.c_str(), CC(C_RST));
            }
        }
        else {
            wprintf(L"    %s[!] %s%s\n", CC(C_YEL), dp.errorMsg.c_str(), CC(C_RST));
        }
    }

    // ================================================================
    //  [Risk Assessment]
    // ================================================================
    wprintf(L"\n%s+===========================================================+%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"%s  RISK ASSESSMENT%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"%s+===========================================================+%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"  Overall Level : %s%s%s\n", CC(RiskLevelColor(risk.level)), RiskLevelStr(risk.level), CC(C_RST));
    if (tlInfo.loadedOk && tlInfo.execRiskMethods > 0)
        wprintf(L"  Exec Methods  : %s%d method(s) with exec risk  (worst: %s)%s\n",
            CC(ExecRiskColor(tlInfo.worstRisk)), tlInfo.execRiskMethods,
            ExecRiskStr(tlInfo.worstRisk), CC(C_RST));
    wprintf(L"\n");
    auto flag = [](bool v, const wchar_t* label, const wchar_t* tc) {
        wprintf(L"  %-22s: %s%-3s%s\n", label, v ? CC(tc) : CC(C_DIM), v ? L"YES" : L"NO", CC(C_RST));
        };
    flag(risk.privesc, L"PrivEsc", C_RED);
    flag(risk.lateral, L"LateralMove", C_ORG);
    flag(risk.hijack, L"Hijack", C_RED);
    flag(risk.autoElev, L"AutoElevate", C_YEL);
    flag(risk.dcomOpen, L"DCOM Exposed", C_YEL);
    if (!risk.reasons.empty()) {
        wprintf(L"\n  %sFindings:%s\n", CC(C_BOLD), CC(C_RST));
        for (auto& r2 : risk.reasons)
            wprintf(L"    %s[!]%s %s\n", CC(RiskLevelColor(risk.level)), CC(C_RST), r2.c_str());
    }
    if (!risk.mitigations.empty()) {
        wprintf(L"\n  %sMitigations:%s\n", CC(C_BOLD), CC(C_RST));
        for (auto& m : risk.mitigations)
            wprintf(L"    %s[+]%s %s\n", CC(C_GRN), CC(C_RST), m.c_str());
    }
    if (risk.level == RiskLevel::None && tlInfo.execRiskMethods == 0)
        wprintf(L"\n  %s[OK] No significant risk indicators found%s\n", CC(C_GRN), CC(C_RST));
    wprintf(L"%s+===========================================================+%s\n", CC(C_BOLD), CC(C_RST));
}

// ============================================================
//  --typelib <path>  (analyse arbitrary TLB/DLL/EXE)
// ============================================================
static void DumpTypeLibFile(const std::wstring& path, bool execOnly)
{
    wprintf(L"\n%s[TypeLib Analysis]%s  %s\n", CC(C_BOLD), CC(C_RST), path.c_str());
    TypeLibInfo tl = LoadAndAnalyzeTypeLib(path);
    if (!tl.loadedOk) {
        wprintf(L"  %s[!] %s%s\n", CC(C_RED), tl.errorMsg.c_str(), CC(C_RST));
        return;
    }
    PrintTypeLibInfo(tl, execOnly, 2);

    // Summary
    wprintf(L"\n%s[Summary]%s\n", CC(C_BOLD), CC(C_RST));
    wprintf(L"  Interfaces   : %zu\n", tl.interfaces.size());
    wprintf(L"  Total methods: %d\n", tl.totalMethods);
    wprintf(L"  Exec-risk    : %s%d%s  (worst: %s)\n",
        tl.execRiskMethods > 0 ? CC(ExecRiskColor(tl.worstRisk)) : CC(C_GRN),
        tl.execRiskMethods, CC(C_RST), ExecRiskStr(tl.worstRisk));
}

// ============================================================
//  --methods <CLSID|ProgID>  — deep method dump
// ============================================================
static void DumpMethods(const std::wstring& input, bool execOnly, bool doDispatch)
{
    ResolvedCOM r = Resolve(input);
    std::wstring clsid = r.clsid.empty() ? input : r.clsid;

    wprintf(L"\n%s[Method Analysis]%s  %s%s%s\n", CC(C_BOLD), CC(C_RST), CC(C_CYN), input.c_str(), CC(C_RST));
    if (!r.clsid.empty()) wprintf(L"  CLSID  : %s\n", r.clsid.c_str());
    if (!r.appid.empty()) wprintf(L"  AppID  : %s\n", r.appid.c_str());

    // TypeLib
    std::wstring tlPath = GetTypeLibPath(clsid);
    wprintf(L"\n  %s[TypeLib — static]%s\n", CC(C_BOLD), CC(C_RST));
    if (!tlPath.empty()) {
        TypeLibInfo tl = LoadAndAnalyzeTypeLib(tlPath);
        PrintTypeLibInfo(tl, execOnly, 4);
    }
    else {
        // Fallback: try InprocServer32 / LocalServer32
        wchar_t p[512];
        swprintf_s(p, L"CLSID\\%s\\InprocServer32", clsid.c_str());
        std::wstring ip = ExpandEnv(RegReadString(HKEY_CLASSES_ROOT, p, L""));
        if (ip.empty()) {
            swprintf_s(p, L"CLSID\\%s\\LocalServer32", clsid.c_str());
            ip = GetExecutablePath(RegReadString(HKEY_CLASSES_ROOT, p, L""));
        }
        if (!ip.empty()) {
            TypeLibInfo tl = LoadAndAnalyzeTypeLib(ip);
            PrintTypeLibInfo(tl, execOnly, 4);
        }
        else {
            wprintf(L"    %s(no TypeLib or binary path found)%s\n", CC(C_DIM), CC(C_RST));
        }
    }

    // IDispatch live
    if (doDispatch) {
        wprintf(L"\n  %s[IDispatch — live]%s\n", CC(C_BOLD), CC(C_RST));
        DispatchProbe dp = ProbeViaDispatch(clsid);
        if (dp.succeeded) {
            wprintf(L"    %s[+] Live probe OK — %zu methods%s\n",
                CC(C_GRN), dp.methods.size(), CC(C_RST));
            for (auto& m : dp.methods) {
                if (execOnly && m.execRisk < ExecRisk::Medium) continue;
                const wchar_t* rc = ExecRiskColor(m.execRisk);
                const wchar_t* rs = (m.execRisk == ExecRisk::None) ? L"       " : ExecRiskStr(m.execRisk);
                wprintf(L"    %s%-12s%s %s%-12s%s %s\n",
                    CC(C_DIM), m.invokeKind.c_str(), CC(C_RST),
                    CC(rc), rs, CC(C_RST),
                    m.name.empty() ? L"<unnamed>" : m.name.c_str());
                if (m.execRisk >= ExecRisk::Low && !m.execReason.empty())
                    wprintf(L"      %s-> %s%s\n", CC(rc), m.execReason.c_str(), CC(C_RST));
            }
        }
        else {
            wprintf(L"    %s[!] %s%s\n", CC(C_YEL), dp.errorMsg.c_str(), CC(C_RST));
        }
    }
}

// ============================================================
//  System defaults
// ============================================================
static void DumpDefaults()
{
    wprintf(L"\n%s+===========================================================+%s\n", CC(C_YEL), CC(C_RST));
    wprintf(L"%s  System-Wide Default COM/DCOM Permissions%s\n", CC(C_YEL), CC(C_RST));
    wprintf(L"%s+===========================================================+%s\n", CC(C_YEL), CC(C_RST));
    const wchar_t* olePath = L"SOFTWARE\\Microsoft\\Ole";
    const wchar_t* perms[] = { L"DefaultLaunchPermission",L"DefaultAccessPermission",
                                L"MachineLaunchRestriction",L"MachineAccessRestriction" };
    for (auto p : perms) {
        wprintf(L"\n  %s[%s]%s\n", CC(C_BOLD), p, CC(C_RST));
        std::vector<BYTE> bin;
        if (RegReadBinary(HKEY_LOCAL_MACHINE, olePath, p, bin) && !bin.empty())
            PrintSD(bin.data(), (DWORD)bin.size(), 4);
        else wprintf(L"    %s(not set)%s\n", CC(C_DIM), CC(C_RST));
    }
    const wchar_t* sv[] = { L"EnableDCOM",L"LegacyAuthenticationLevel",L"LegacyImpersonationLevel",
        L"DefaultAuthenticationLevel",L"DefaultImpersonationLevel" };
    wprintf(L"\n  %s[Global OLE/DCOM Settings]%s\n", CC(C_BOLD), CC(C_RST));
    for (auto v : sv) {
        std::wstring val = RegReadString(HKEY_LOCAL_MACHINE, olePath, v);
        if (!val.empty()) wprintf(L"    %-38s: %s\n", v, val.c_str());
    }
}

// ============================================================
//  Scan / Enum
// ============================================================
static void ScanAll(bool doTypelib, bool execOnly)
{
    wprintf(L"\n%s[SCAN MODE]%s Checking all AppIDs...\n", CC(C_BOLD), CC(C_RST));
    auto keys = RegEnumSubkeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\AppID");
    for (auto& k : keys) if (k.size() > 2 && k[0] == L'{') {
        ResolvedCOM r; r.appid = k; r.note = L"Scan";
        DumpAppID(r, false, doTypelib, execOnly, false, true);
    }
    wprintf(L"\n%s[*] Scan complete. %zu AppIDs checked.%s\n", CC(C_BOLD), keys.size(), CC(C_RST));
}

static void EnumAll(bool brief, bool doTypelib, bool execOnly)
{
    auto keys = RegEnumSubkeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\AppID");
    wprintf(L"\n%s[*] %zu AppID entries%s\n", CC(C_BOLD), keys.size(), CC(C_RST));
    for (auto& k : keys) if (k.size() > 2 && k[0] == L'{') {
        ResolvedCOM r; r.appid = k; r.note = L"Enumeration";
        DumpAppID(r, brief, doTypelib, execOnly, false);
    }
    DumpDefaults();
}

// ============================================================
//  Entry point
// ============================================================
int wmain(int argc, wchar_t* argv[])
{
    EnableVT();
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    wprintf(L"\n  COM Security Auditor v5.0\n");
    wprintf(L"  ProgID->CLSID->AppID | TypeLib Introspection | Method Exec Classifier\n");
    wprintf(L"  ======================================================================\n\n");
    fflush(stdout);

    if (argc < 2) {
        wprintf(
            L"Usage:\n"
            L"  comdump.exe <input>                  Audit AppID (ProgID / CLSID / AppID / name)\n"
            L"  comdump.exe <input> --methods        Also dump all methods (TypeLib + IDispatch)\n"
            L"  comdump.exe <input> --exec           Show only exec-capable methods\n"
            L"  comdump.exe <input> --live           Include live IDispatch probe\n"
            L"  comdump.exe <input> --methods --exec --live  Combined deep mode\n"
            L"\n"
            L"  comdump.exe --methods <input>        Deep method dump (no AppID audit)\n"
            L"  comdump.exe --typelib <path>         Analyse arbitrary TLB/DLL/EXE typelib\n"
            L"  comdump.exe --typelib <path> --exec  Exec methods only\n"
            L"\n"
            L"  comdump.exe --scan                   Scan all AppIDs for risk\n"
            L"  comdump.exe --scan --methods         Scan + include TypeLib analysis\n"
            L"  comdump.exe --all                    Dump every AppID\n"
            L"  comdump.exe --defaults               System-wide COM/DCOM defaults\n"
            L"\n"
            L"Examples:\n"
            L"  comdump.exe MMC20.Application --methods --exec --live\n"
            L"  comdump.exe Shell.Application --methods\n"
            L"  comdump.exe {72C24DD5-D70A-438B-8A42-98424B88AFB8} --methods --exec\n"
            L"  comdump.exe --typelib C:\\Windows\\System32\\wshom.ocx --exec\n"
            L"  comdump.exe --methods {72C24DD5-D70A-438B-8A42-98424B88AFB8} --live\n"
        );
        CoUninitialize();
        return 0;
    }

    // Parse flags
    std::wstring arg1 = argv[1];
    bool doMethods = false, execOnly = false, doDispatch = false;
    for (int i = 2; i < argc; i++) {
        std::wstring a = argv[i];
        if (a == L"--methods") doMethods = true;
        if (a == L"--exec")    execOnly = true;
        if (a == L"--live")    doDispatch = true;
        if (a == L"--brief") {}  // handled below
    }
    bool brief = (argc >= 3 && std::wstring(argv[2]) == L"--brief");

    if (arg1 == L"--defaults") {
        DumpDefaults();
    }
    else if (arg1 == L"--all") {
        EnumAll(brief, doMethods, execOnly);
    }
    else if (arg1 == L"--scan") {
        ScanAll(doMethods, execOnly);
    }
    else if (arg1 == L"--typelib") {
        if (argc < 3) { wprintf(L"Error: --typelib requires a path\n"); CoUninitialize(); return 1; }
        DumpTypeLibFile(argv[2], execOnly);
    }
    else if (arg1 == L"--methods") {
        if (argc < 3) { wprintf(L"Error: --methods requires a CLSID/ProgID\n"); CoUninitialize(); return 1; }
        DumpMethods(argv[2], execOnly, doDispatch);
    }
    else {
        // Normal audit
        ResolvedCOM r = Resolve(arg1);
        DumpAppID(r, false, doMethods, execOnly, doDispatch, false);
        DumpDefaults();
    }

    wprintf(L"\n%sDone.%s\n", CC(C_DIM), CC(C_RST));
    fflush(stdout);
    CoUninitialize();
    return 0;
}