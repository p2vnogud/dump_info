// =============================================================================
// ShellBrowserWindow DCOM – Final clean version
// =============================================================================
// Fix:
//   1. Bỏ Attempt 2 (không spawn process thứ 2)
//   2. Fix bug đọc UNC: wifstream không đọc được ANSI file trên UNC
//      → dùng CreateFileW + ReadFile (WinAPI thuần) thay vì wifstream
//   3. Retry đọc file 3 lần (process cần thời gian ghi xong)
//
// Usage: com_remote_dcom.exe <ip> <user> <pass> <shell_command>
//   shell_command = command kèm redirection, KHÔNG có "cmd.exe /c" ở đầu
//
// Example:
//   com_remote_dcom.exe 192.168.17.36 Administrator P@ssw0rd123
//     "whoami > c:\temp\dcom.txt"
// =============================================================================
// Compile: cl com_remote_dcom.cpp /link ole32.lib oleaut32.lib

#define _WIN32_DCOM
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <comdef.h>
#include <shldisp.h>
#include <shlobj.h>
#include <string>
#include <vector>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

void PrintErr(const wchar_t* msg, HRESULT hr) {
    _com_error e(hr);
    wprintf(L"[-] %s: 0x%08X (%s)\n", msg, hr, e.ErrorMessage());
}

SEC_WINNT_AUTH_IDENTITY_W g_auth = {};

void SP(IUnknown* p) {
    if (!p) return;
    CoSetProxyBlanket(p,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        &g_auth, EOAC_NONE);
}

IDispatch* GetProp(IDispatch* p, const wchar_t* name) {
    DISPID id;
    BSTR b = SysAllocString(name);
    HRESULT hr = p->GetIDsOfNames(IID_NULL, &b, 1, LOCALE_USER_DEFAULT, &id);
    SysFreeString(b);
    if (FAILED(hr)) { PrintErr(name, hr); return NULL; }

    DISPPARAMS dp = {};
    VARIANT v; VariantInit(&v);
    hr = p->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT,
        DISPATCH_PROPERTYGET, &dp, &v, NULL, NULL);
    if (FAILED(hr) || v.vt != VT_DISPATCH || !v.pdispVal) {
        if (FAILED(hr)) PrintErr(name, hr);
        VariantClear(&v); return NULL;
    }
    SP(v.pdispVal);
    return v.pdispVal; // caller must Release
}

// ── Đọc file text qua WinAPI (không dùng wifstream – unreliable trên UNC) ────
std::string ReadFileContent(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(),
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "";

    DWORD size = GetFileSize(hFile, NULL);
    if (size == 0 || size == INVALID_FILE_SIZE) { CloseHandle(hFile); return ""; }

    std::vector<char> buf(size + 1, 0);
    DWORD read = 0;
    ReadFile(hFile, buf.data(), size, &read, NULL);
    CloseHandle(hFile);
    return std::string(buf.data(), read);
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 5) {
        wprintf(L"Usage: com_remote_dcom <ip> <user> <pass> <shell_command>\n\n");
        wprintf(L"  shell_command = command kèm redirection, KHÔNG có cmd.exe ở đầu\n\n");
        wprintf(L"  Ví dụ:\n");
        wprintf(L"    com_remote_dcom 192.168.17.36 Administrator P@ssw0rd123\n");
        wprintf(L"      \"whoami > c:\\temp\\dcom.txt\"\n\n");
        wprintf(L"    com_remote_dcom 192.168.17.36 Administrator P@ssw0rd123\n");
        wprintf(L"      \"ipconfig /all > c:\\temp\\ipconfig.txt\"\n");
        return 1;
    }

    std::wstring ip = argv[1];
    std::wstring user = argv[2];
    std::wstring pass = argv[3];
    std::wstring shellCmd = argv[4]; // VD: "whoami > c:\temp\dcom.txt"

    // ── COM init ──────────────────────────────────────────────────────────────
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) { PrintErr(L"CoInitializeEx", hr); return 1; }

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY,
        NULL, EOAC_NONE, NULL);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE)
        PrintErr(L"CoInitializeSecurity (non-fatal)", hr);

    // ── Auth ──────────────────────────────────────────────────────────────────
    g_auth.User = (USHORT*)user.c_str();
    g_auth.UserLength = (ULONG)user.size();
    g_auth.Password = (USHORT*)pass.c_str();
    g_auth.PasswordLength = (ULONG)pass.size();
    g_auth.Domain = (USHORT*)L"";
    g_auth.DomainLength = 0;
    g_auth.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    COAUTHIDENTITY coAuth = {};
    coAuth.User = (USHORT*)user.c_str();
    coAuth.UserLength = (ULONG)user.size();
    coAuth.Password = (USHORT*)pass.c_str();
    coAuth.PasswordLength = (ULONG)pass.size();
    coAuth.Domain = (USHORT*)L"";
    coAuth.DomainLength = 0;
    coAuth.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    COAUTHINFO cai = {};
    cai.dwAuthnSvc = RPC_C_AUTHN_WINNT;
    cai.dwAuthzSvc = RPC_C_AUTHZ_NONE;
    cai.pwszServerPrincName = NULL;
    cai.dwAuthnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
    cai.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
    cai.pAuthIdentityData = &coAuth;
    cai.dwCapabilities = EOAC_NONE;

    COSERVERINFO srv = {};
    srv.pwszName = (LPWSTR)ip.c_str();
    srv.pAuthInfo = &cai;

    // ── Tạo ShellBrowserWindow trên target ────────────────────────────────────
    // CLSID_ShellBrowserWindow = {C08AFD90-F2A1-11D1-8455-00A0C91F3880}
    const CLSID CLSID_SBW = {
        0xC08AFD90, 0xF2A1, 0x11D1,
        {0x84, 0x55, 0x00, 0xA0, 0xC9, 0x1F, 0x38, 0x80}
    };
    MULTI_QI mqi = { &IID_IDispatch, NULL, S_OK };
    hr = CoCreateInstanceEx(CLSID_SBW, NULL, CLSCTX_REMOTE_SERVER, &srv, 1, &mqi);
    if (FAILED(hr) || FAILED(mqi.hr)) {
        PrintErr(L"CoCreateInstanceEx(ShellBrowserWindow)", FAILED(hr) ? hr : mqi.hr);
        CoUninitialize(); return 1;
    }
    IDispatch* pBrowser = (IDispatch*)mqi.pItf;
    SP(pBrowser);
    wprintf(L"[+] ShellBrowserWindow created on %s\n", ip.c_str());

    // ── Lấy Document.Application ──────────────────────────────────────────────
    IDispatch* pDoc = GetProp(pBrowser, L"Document");
    pBrowser->Release();
    if (!pDoc) { CoUninitialize(); return 1; }

    IDispatch* pApp = GetProp(pDoc, L"Application");
    pDoc->Release();
    if (!pApp) { CoUninitialize(); return 1; }
    wprintf(L"[+] Got Application\n");

    // ── Gọi ShellExecute ──────────────────────────────────────────────────────
    //
    // exe  = "cmd.exe"
    // args = /S /C "shellCmd"
    //
    // /S = cmd xử lý special chars (>, |, &) đúng cách
    // /C = chạy rồi exit
    // Toàn bộ shellCmd được wrap trong outer quotes cho /S parse
    //
    std::wstring exe = L"cmd.exe";
    std::wstring args = L"/S /C \"" + shellCmd + L"\"";

    wprintf(L"[*] Executing:\n");
    wprintf(L"    cmd.exe %s\n", args.c_str());

    DISPID dispSE;
    BSTR bSE = SysAllocString(L"ShellExecute");
    hr = pApp->GetIDsOfNames(IID_NULL, &bSE, 1, LOCALE_USER_DEFAULT, &dispSE);
    SysFreeString(bSE);
    if (FAILED(hr)) { PrintErr(L"GetIDsOfNames(ShellExecute)", hr); pApp->Release(); CoUninitialize(); return 1; }

    VARIANT a[5];
    for (int i = 0; i < 5; i++) VariantInit(&a[i]);
    a[4].vt = VT_BSTR; a[4].bstrVal = SysAllocString(exe.c_str());
    a[3].vt = VT_BSTR; a[3].bstrVal = SysAllocString(args.c_str());
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
    pApp->Release();

    if (FAILED(hr)) {
        PrintErr(L"ShellExecute", hr);
        CoUninitialize(); return 1;
    }
    wprintf(L"[+] ShellExecute OK\n");

    // ── Đọc output file nếu có redirection ───────────────────────────────────
    //
    // Tìm > trong shellCmd để lấy output file path
    // Retry 5 lần × 2 giây = chờ tối đa 10 giây
    //
    size_t redir = shellCmd.find(L'>');
    if (redir == std::wstring::npos) {
        wprintf(L"[*] No redirection in command, done.\n");
        CoUninitialize(); return 0;
    }

    std::wstring outFile = shellCmd.substr(redir + 1);
    while (!outFile.empty() && outFile.front() == L' ') outFile.erase(0, 1);
    while (!outFile.empty() && outFile.back() == L' ') outFile.pop_back();
    // Xóa trailing quote nếu có
    if (!outFile.empty() && outFile.back() == L'"') outFile.pop_back();

    // Convert C:\temp\file.txt → \\ip\C$\temp\file.txt
    std::wstring uncPath = L"\\\\" + ip + L"\\"
        + outFile.substr(0, 1) + L"$"
        + outFile.substr(2);

    wprintf(L"[*] Waiting for output: %s\n", uncPath.c_str());

    std::string content;
    for (int attempt = 1; attempt <= 5; attempt++) {
        Sleep(2000);
        content = ReadFileContent(uncPath);
        if (!content.empty()) break;
        wprintf(L"    [%d/5] Waiting...\n", attempt);
    }

    if (!content.empty()) {
        wprintf(L"\n[+] OUTPUT:\n");
        // In từng dòng
        size_t start = 0;
        for (size_t i = 0; i <= content.size(); i++) {
            if (i == content.size() || content[i] == '\n') {
                std::string line = content.substr(start, i - start);
                // Trim \r
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (!line.empty())
                    wprintf(L"    %S\n", line.c_str());
                start = i + 1;
            }
        }
    }
    else {
        wprintf(L"[-] Output file empty or not found after 10s\n");
        wprintf(L"    Possible causes:\n");
        wprintf(L"    1. c:\\temp does not exist on target\n");
        wprintf(L"       Fix: run 'mkdir c:\\temp' on target first\n");
        wprintf(L"    2. Process still running (try reading manually)\n");
        wprintf(L"       type %s\n", uncPath.c_str());
        wprintf(L"    3. ShellExecute runs as interactive user\n");
        wprintf(L"       (not SYSTEM) - check permissions\n");
    }

    CoUninitialize();
    return 0;
}