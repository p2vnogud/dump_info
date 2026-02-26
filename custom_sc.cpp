/*
 * remote_service_manager.cpp
 *
 * Quản lý service từ xa qua SMB/IPC$ + SCM (Service Control Manager)
 * Chỉ dùng WinAPI thuần
 *
 * Build:
 *   cl remote_service_manager.cpp /W3 /O2 /EHsc /link netapi32.lib advapi32.lib mpr.lib
 *
 * Usage:
 *   remote_service_manager.exe --host <IP/Hostname> --user <username> --pass <password>
 *                              --service <ServiceName> --binpath <"C:\path\to\exe">
 *                              --action <create|start|stop|delete|status|query>
 *                              [--domain <domain>]
 *
 * Examples:
 *   remote_service_manager.exe --host 192.168.47.136 --user Administrator --pass P@ssw0rd123
 *                              --service FakeService --binpath "C:\Users\wintest\Desktop\service.exe"
 *                              --action create
 *
 *   remote_service_manager.exe --host 192.168.47.136 --user Administrator --pass P@ssw0rd123
 *                              --service FakeService --action start
 *
 *   remote_service_manager.exe --host 192.168.47.136 --user Administrator --pass P@ssw0rd123
 *                              --service FakeService --action stop
 *
 *   remote_service_manager.exe --host 192.168.47.136 --user Administrator --pass P@ssw0rd123
 *                              --service FakeService --action delete
 *
 *   remote_service_manager.exe --host 192.168.47.136 --user Administrator --pass P@ssw0rd123
 *                              --service FakeService --action status
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <winnetwk.h>
#include <lm.h>
#include <tchar.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "netapi32.lib")

 // ---------------------------------------------------------------------------
 // Cấu trúc tham số
 // ---------------------------------------------------------------------------
struct Config {
    WCHAR host[256];
    WCHAR user[256];
    WCHAR pass[256];
    WCHAR domain[256];
    WCHAR serviceName[256];
    WCHAR binPath[1024];
    WCHAR action[64];          // create | start | stop | delete | status | query
    WCHAR startType[32];       // auto | manual | disabled  (default: auto)
};

// ---------------------------------------------------------------------------
// Hàm in lỗi Win32
// ---------------------------------------------------------------------------
static void PrintWin32Error(const wchar_t* msg, DWORD err)
{
    LPWSTR buf = NULL;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
        | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&buf, 0, NULL);
    wprintf(L"[-] %s (Error %lu): %s\n", msg, err, buf ? buf : L"Unknown error");
    if (buf) LocalFree(buf);
}

// ---------------------------------------------------------------------------
// Kiểm tra session IPC$ đến host đã tồn tại chưa
// Cách: thử NetSessionEnum hoặc WNetGetConnection hoặc đơn giản
// thử OpenSCManager - nếu thành công nghĩa là đã có xác thực
//
// Trả về TRUE nếu đã có session xác thực
// ---------------------------------------------------------------------------
static BOOL IsSessionEstablished(const WCHAR* host)
{
    // Thử kết nối SCM không cần thêm credential
    // Nếu thành công → đã có session / credential được cache
    WCHAR unc[300];
    swprintf_s(unc, 300, L"\\\\%s", host);

    SC_HANDLE hScm = OpenSCManagerW(unc, NULL, SC_MANAGER_CONNECT);
    if (hScm) {
        CloseServiceHandle(hScm);
        wprintf(L"[*] Session/auth to %s already established.\n", host);
        return TRUE;
    }
    // Nếu lỗi ACCESS_DENIED hoặc logon failure → chưa có session hợp lệ
    return FALSE;
}

// ---------------------------------------------------------------------------
// Tạo IPC$ session (net use \\host\IPC$ /user:domain\user pass)
// Dùng WNetAddConnection2W
// ---------------------------------------------------------------------------
static BOOL EstablishSession(const Config& cfg)
{
    if (IsSessionEstablished(cfg.host)) return TRUE;

    WCHAR remoteName[512];
    swprintf_s(remoteName, 512, L"\\\\%s\\IPC$", cfg.host);

    // Xây dựng username: domain\user hoặc chỉ user
    WCHAR fullUser[512];
    if (cfg.domain[0])
        swprintf_s(fullUser, 512, L"%s\\%s", cfg.domain, cfg.user);
    else
        wcscpy_s(fullUser, 512, cfg.user);

    NETRESOURCEW nr = {};
    nr.dwType = RESOURCETYPE_ANY;
    nr.lpRemoteName = remoteName;
    nr.lpLocalName = NULL;   // không map drive letter
    nr.lpProvider = NULL;

    wprintf(L"[*] Establishing IPC$ session to %s as %s ...\n", remoteName, fullUser);

    DWORD ret = WNetAddConnection2W(&nr, cfg.pass, fullUser,
        CONNECT_TEMPORARY);  // không lưu vào profile

    if (ret == NO_ERROR || ret == ERROR_ALREADY_ASSIGNED || ret == ERROR_SESSION_CREDENTIAL_CONFLICT) {
        wprintf(L"[+] Session established (or already existed).\n");
        return TRUE;
    }

    // ERROR_SESSION_CREDENTIAL_CONFLICT: đã có session với credential khác
    // → cần disconnect trước
    if (ret == ERROR_SESSION_CREDENTIAL_CONFLICT) {
        wprintf(L"[!] Credential conflict. Disconnecting old session...\n");
        WNetCancelConnection2W(remoteName, 0, TRUE);
        ret = WNetAddConnection2W(&nr, cfg.pass, fullUser, CONNECT_TEMPORARY);
        if (ret == NO_ERROR) {
            wprintf(L"[+] Session established after reconnect.\n");
            return TRUE;
        }
    }

    PrintWin32Error(L"WNetAddConnection2 failed", ret);
    return FALSE;
}

// ---------------------------------------------------------------------------
// Mở SCManager remote
// ---------------------------------------------------------------------------
static SC_HANDLE OpenRemoteSCM(const WCHAR* host, DWORD desiredAccess)
{
    WCHAR unc[300];
    swprintf_s(unc, 300, L"\\\\%s", host);

    SC_HANDLE hScm = OpenSCManagerW(unc, NULL, desiredAccess);
    if (!hScm)
        PrintWin32Error(L"OpenSCManagerW failed", GetLastError());
    return hScm;
}

// ---------------------------------------------------------------------------
// ACTION: Create service
// ---------------------------------------------------------------------------
static BOOL ActionCreate(const Config& cfg)
{
    wprintf(L"[*] Creating service '%s' on %s ...\n", cfg.serviceName, cfg.host);
    wprintf(L"    BinPath : %s\n", cfg.binPath);

    SC_HANDLE hScm = OpenRemoteSCM(cfg.host,
        SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!hScm) return FALSE;

    DWORD startType = SERVICE_AUTO_START;
    if (_wcsicmp(cfg.startType, L"manual") == 0)
        startType = SERVICE_DEMAND_START;
    else if (_wcsicmp(cfg.startType, L"disabled") == 0)
        startType = SERVICE_DISABLED;

    SC_HANDLE hSvc = CreateServiceW(
        hScm,
        cfg.serviceName,            // tên service (internal)
        cfg.serviceName,            // display name
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        startType,
        SERVICE_ERROR_NORMAL,
        cfg.binPath,
        NULL, NULL, NULL,
        NULL,                       // LocalSystem account
        NULL
    );

    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            wprintf(L"[!] Service already exists.\n");
        else
            PrintWin32Error(L"CreateServiceW failed", err);
        CloseServiceHandle(hScm);
        return FALSE;
    }

    wprintf(L"[+] Service '%s' created successfully.\n", cfg.serviceName);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return TRUE;
}

// ---------------------------------------------------------------------------
// ACTION: Start service
// ---------------------------------------------------------------------------
static BOOL ActionStart(const Config& cfg)
{
    wprintf(L"[*] Starting service '%s' on %s ...\n", cfg.serviceName, cfg.host);

    SC_HANDLE hScm = OpenRemoteSCM(cfg.host, SC_MANAGER_CONNECT);
    if (!hScm) return FALSE;

    SC_HANDLE hSvc = OpenServiceW(hScm, cfg.serviceName,
        SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        PrintWin32Error(L"OpenServiceW failed", GetLastError());
        CloseServiceHandle(hScm);
        return FALSE;
    }

    // Kiểm tra trạng thái trước
    SERVICE_STATUS ss = {};
    QueryServiceStatus(hSvc, &ss);
    if (ss.dwCurrentState == SERVICE_RUNNING) {
        wprintf(L"[!] Service is already running.\n");
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        return TRUE;
    }

    if (!StartServiceW(hSvc, 0, NULL)) {
        PrintWin32Error(L"StartServiceW failed", GetLastError());
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        return FALSE;
    }

    // Chờ service start
    wprintf(L"[*] Waiting for service to start");
    DWORD timeout = 30000, waited = 0, interval = 500;
    while (waited < timeout) {
        Sleep(interval);
        waited += interval;
        QueryServiceStatus(hSvc, &ss);
        wprintf(L".");
        if (ss.dwCurrentState == SERVICE_RUNNING) break;
        if (ss.dwCurrentState == SERVICE_STOPPED) break;
    }
    wprintf(L"\n");

    if (ss.dwCurrentState == SERVICE_RUNNING)
        wprintf(L"[+] Service '%s' started successfully.\n", cfg.serviceName);
    else
        wprintf(L"[-] Service did not reach RUNNING state (state=%lu).\n",
            ss.dwCurrentState);

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return (ss.dwCurrentState == SERVICE_RUNNING);
}

// ---------------------------------------------------------------------------
// ACTION: Stop service
// ---------------------------------------------------------------------------
static BOOL ActionStop(const Config& cfg)
{
    wprintf(L"[*] Stopping service '%s' on %s ...\n", cfg.serviceName, cfg.host);

    SC_HANDLE hScm = OpenRemoteSCM(cfg.host, SC_MANAGER_CONNECT);
    if (!hScm) return FALSE;

    SC_HANDLE hSvc = OpenServiceW(hScm, cfg.serviceName,
        SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        PrintWin32Error(L"OpenServiceW failed", GetLastError());
        CloseServiceHandle(hScm);
        return FALSE;
    }

    SERVICE_STATUS ss = {};
    if (!ControlService(hSvc, SERVICE_CONTROL_STOP, &ss)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE)
            wprintf(L"[!] Service is not running.\n");
        else
            PrintWin32Error(L"ControlService(STOP) failed", err);
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        return FALSE;
    }

    wprintf(L"[*] Waiting for service to stop");
    DWORD timeout = 30000, waited = 0, interval = 500;
    while (waited < timeout) {
        Sleep(interval);
        waited += interval;
        QueryServiceStatus(hSvc, &ss);
        wprintf(L".");
        if (ss.dwCurrentState == SERVICE_STOPPED) break;
    }
    wprintf(L"\n");

    if (ss.dwCurrentState == SERVICE_STOPPED)
        wprintf(L"[+] Service '%s' stopped.\n", cfg.serviceName);
    else
        wprintf(L"[-] Service did not stop (state=%lu).\n", ss.dwCurrentState);

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return (ss.dwCurrentState == SERVICE_STOPPED);
}

// ---------------------------------------------------------------------------
// ACTION: Delete service
// ---------------------------------------------------------------------------
static BOOL ActionDelete(const Config& cfg)
{
    wprintf(L"[*] Deleting service '%s' on %s ...\n", cfg.serviceName, cfg.host);

    SC_HANDLE hScm = OpenRemoteSCM(cfg.host, SC_MANAGER_CONNECT);
    if (!hScm) return FALSE;

    SC_HANDLE hSvc = OpenServiceW(hScm, cfg.serviceName, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        PrintWin32Error(L"OpenServiceW failed", GetLastError());
        CloseServiceHandle(hScm);
        return FALSE;
    }

    // Dừng trước nếu đang chạy
    SERVICE_STATUS ss = {};
    QueryServiceStatus(hSvc, &ss);
    if (ss.dwCurrentState != SERVICE_STOPPED) {
        wprintf(L"[*] Service is running. Stopping first...\n");
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        Sleep(2000);
    }

    BOOL ok = DeleteService(hSvc);
    if (!ok)
        PrintWin32Error(L"DeleteService failed", GetLastError());
    else
        wprintf(L"[+] Service '%s' deleted.\n", cfg.serviceName);

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return ok;
}

// ---------------------------------------------------------------------------
// ACTION: Query / Status
// ---------------------------------------------------------------------------
static BOOL ActionStatus(const Config& cfg)
{
    wprintf(L"[*] Querying service '%s' on %s ...\n", cfg.serviceName, cfg.host);

    SC_HANDLE hScm = OpenRemoteSCM(cfg.host, SC_MANAGER_CONNECT);
    if (!hScm) return FALSE;

    SC_HANDLE hSvc = OpenServiceW(hScm, cfg.serviceName,
        SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!hSvc) {
        PrintWin32Error(L"OpenServiceW failed", GetLastError());
        CloseServiceHandle(hScm);
        return FALSE;
    }

    // Status
    SERVICE_STATUS_PROCESS ssp = {};
    DWORD needed = 0;
    QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ssp, sizeof(ssp), &needed);

    auto StateStr = [](DWORD s) -> const wchar_t* {
        switch (s) {
        case SERVICE_STOPPED:          return L"STOPPED";
        case SERVICE_START_PENDING:    return L"START_PENDING";
        case SERVICE_STOP_PENDING:     return L"STOP_PENDING";
        case SERVICE_RUNNING:          return L"RUNNING";
        case SERVICE_CONTINUE_PENDING: return L"CONTINUE_PENDING";
        case SERVICE_PAUSE_PENDING:    return L"PAUSE_PENDING";
        case SERVICE_PAUSED:           return L"PAUSED";
        default:                       return L"UNKNOWN";
        }
        };

    wprintf(L"\n  Service Name : %s\n", cfg.serviceName);
    wprintf(L"  State        : %s (%lu)\n", StateStr(ssp.dwCurrentState), ssp.dwCurrentState);
    wprintf(L"  PID          : %lu\n", ssp.dwProcessId);

    // Config
    DWORD cbNeeded = 0;
    QueryServiceConfigW(hSvc, NULL, 0, &cbNeeded);
    if (cbNeeded > 0) {
        LPQUERY_SERVICE_CONFIGW pCfg = (LPQUERY_SERVICE_CONFIGW)HeapAlloc(
            GetProcessHeap(), 0, cbNeeded);
        if (pCfg && QueryServiceConfigW(hSvc, pCfg, cbNeeded, &cbNeeded)) {
            auto StartStr = [](DWORD t) -> const wchar_t* {
                switch (t) {
                case SERVICE_AUTO_START:   return L"AUTO_START";
                case SERVICE_DEMAND_START: return L"DEMAND_START";
                case SERVICE_DISABLED:     return L"DISABLED";
                case SERVICE_BOOT_START:   return L"BOOT_START";
                case SERVICE_SYSTEM_START: return L"SYSTEM_START";
                default:                   return L"UNKNOWN";
                }
                };
            wprintf(L"  Start Type   : %s\n", StartStr(pCfg->dwStartType));
            wprintf(L"  Binary Path  : %s\n", pCfg->lpBinaryPathName);
            wprintf(L"  Display Name : %s\n", pCfg->lpDisplayName);
        }
        if (pCfg) HeapFree(GetProcessHeap(), 0, pCfg);
    }
    wprintf(L"\n");

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Parse command-line (wide)
// ---------------------------------------------------------------------------
static void Usage(const wchar_t* prog)
{
    wprintf(L"\nUsage:\n");
    wprintf(L"  %s --host <IP/Host> --user <user> --pass <pass>\n", prog);
    wprintf(L"           --service <Name> --action <create|start|stop|delete|status>\n");
    wprintf(L"           [--binpath <path>]    (required for create)\n");
    wprintf(L"           [--domain <domain>]   (optional, default: empty)\n");
    wprintf(L"           [--starttype <auto|manual|disabled>]  (default: auto)\n");
    wprintf(L"\nActions:\n");
    wprintf(L"  create  - Create service (requires --binpath)\n");
    wprintf(L"  start   - Start service\n");
    wprintf(L"  stop    - Stop service\n");
    wprintf(L"  delete  - Delete service (stops first if running)\n");
    wprintf(L"  status  - Query service status and config\n");
    wprintf(L"\nExamples:\n");
    wprintf(L"  %s --host 192.168.47.136 --user Administrator --pass P@ssw0rd123\n"
        L"       --service FakeService --binpath \"C:\\Users\\wintest\\Desktop\\service.exe\"\n"
        L"       --action create\n\n", prog);
}

static bool ParseArgs(int argc, wchar_t** argv, Config& cfg)
{
    memset(&cfg, 0, sizeof(cfg));
    wcscpy_s(cfg.startType, L"auto"); // default

    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"--host") == 0 && i + 1 < argc)
            wcscpy_s(cfg.host, argv[++i]);
        else if (_wcsicmp(argv[i], L"--user") == 0 && i + 1 < argc)
            wcscpy_s(cfg.user, argv[++i]);
        else if (_wcsicmp(argv[i], L"--pass") == 0 && i + 1 < argc)
            wcscpy_s(cfg.pass, argv[++i]);
        else if (_wcsicmp(argv[i], L"--domain") == 0 && i + 1 < argc)
            wcscpy_s(cfg.domain, argv[++i]);
        else if (_wcsicmp(argv[i], L"--service") == 0 && i + 1 < argc)
            wcscpy_s(cfg.serviceName, argv[++i]);
        else if (_wcsicmp(argv[i], L"--binpath") == 0 && i + 1 < argc)
            wcscpy_s(cfg.binPath, argv[++i]);
        else if (_wcsicmp(argv[i], L"--action") == 0 && i + 1 < argc)
            wcscpy_s(cfg.action, argv[++i]);
        else if (_wcsicmp(argv[i], L"--starttype") == 0 && i + 1 < argc)
            wcscpy_s(cfg.startType, argv[++i]);
    }

    if (!cfg.host[0] || !cfg.user[0] || !cfg.action[0] || !cfg.serviceName[0]) {
        wprintf(L"[-] Missing required parameters.\n");
        return false;
    }
    if (_wcsicmp(cfg.action, L"create") == 0 && !cfg.binPath[0]) {
        wprintf(L"[-] --binpath is required for 'create' action.\n");
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Entry point (wmain for Unicode)
// ---------------------------------------------------------------------------
int wmain(int argc, wchar_t** argv)
{
    wprintf(L"=== Remote Service Manager (WinAPI) ===\n\n");

    Config cfg;
    if (!ParseArgs(argc, argv, cfg)) {
        Usage(argv[0]);
        return 1;
    }

    // --- Bước 1: Đảm bảo có session SMB/IPC$ xác thực ---
    if (!EstablishSession(cfg)) {
        wprintf(L"[-] Failed to establish authenticated session. Aborting.\n");
        return 2;
    }

    // --- Bước 2: Thực hiện action ---
    BOOL result = FALSE;

    if (_wcsicmp(cfg.action, L"create") == 0)
        result = ActionCreate(cfg);
    else if (_wcsicmp(cfg.action, L"start") == 0)
        result = ActionStart(cfg);
    else if (_wcsicmp(cfg.action, L"stop") == 0)
        result = ActionStop(cfg);
    else if (_wcsicmp(cfg.action, L"delete") == 0)
        result = ActionDelete(cfg);
    else if (_wcsicmp(cfg.action, L"status") == 0 ||
        _wcsicmp(cfg.action, L"query") == 0)
        result = ActionStatus(cfg);
    else {
        wprintf(L"[-] Unknown action: %s\n", cfg.action);
        Usage(argv[0]);
        return 3;
    }

    return result ? 0 : 4;
}