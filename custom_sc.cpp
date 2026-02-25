#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

 // ============================================================
 // Hàm trợ giúp: In lỗi WinAPI
 // ============================================================
void PrintLastError(const char* context) {
    DWORD err = GetLastError();
    LPSTR msg = NULL;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&msg, 0, NULL
    );
    printf("[LỖI] %s - Mã lỗi: %lu - %s", context, err, msg ? msg : "Không rõ\n");
    if (msg) LocalFree(msg);
}

// ============================================================
// Mở Service Control Manager
// ============================================================
SC_HANDLE OpenSCM(DWORD desiredAccess) {
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, desiredAccess);
    if (!hSCM) {
        PrintLastError("OpenSCManager");
    }
    return hSCM;
}

// ============================================================
// 1. Tạo Service (sc create)
// ============================================================
void CreateService_Cmd(int argc, char* argv[]) {
    // Usage: ServiceManager create <ServiceName> <BinaryPath> [DisplayName] [StartType]
    if (argc < 5) {
        printf("Cách dùng: ServiceManager create <TênService> <ĐườngDẫnExe> [TênHiển] [auto|demand|disabled]\n");
        printf("Ví dụ: ServiceManager create MyService \"C:\\path\\my.exe\" \"My Service\" auto\n");
        return;
    }

    const char* serviceName = argv[2];
    const char* binaryPath = argv[3];
    const char* displayName = (argc > 4) ? argv[4] : serviceName;
    DWORD startType = SERVICE_DEMAND_START; // mặc định là manual

    if (argc > 5) {
        if (_stricmp(argv[5], "auto") == 0)         startType = SERVICE_AUTO_START;
        else if (_stricmp(argv[5], "disabled") == 0) startType = SERVICE_DISABLED;
        else                                         startType = SERVICE_DEMAND_START;
    }

    SC_HANDLE hSCM = OpenSCM(SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) return;

    SC_HANDLE hService = CreateServiceA(
        hSCM,
        serviceName,              // Tên nội bộ
        displayName,              // Tên hiển thị
        SERVICE_ALL_ACCESS,       // Quyền truy cập
        SERVICE_WIN32_OWN_PROCESS,// Loại service
        startType,                // Kiểu khởi động
        SERVICE_ERROR_NORMAL,     // Xử lý lỗi
        binaryPath,               // Đường dẫn file exe
        NULL,                     // Load order group
        NULL,                     // Tag ID
        NULL,                     // Dependencies
        NULL,                     // Tài khoản chạy (NULL = LocalSystem)
        NULL                      // Mật khẩu
    );

    if (hService) {
        printf("[OK] Tạo service '%s' thành công!\n", serviceName);
        printf("     DisplayName : %s\n", displayName);
        printf("     BinaryPath  : %s\n", binaryPath);
        printf("     StartType   : %s\n", (startType == SERVICE_AUTO_START) ? "Automatic" :
            (startType == SERVICE_DISABLED) ? "Disabled" : "Manual");
        CloseServiceHandle(hService);
    }
    else {
        PrintLastError("CreateService");
    }

    CloseServiceHandle(hSCM);
}

// ============================================================
// 2. Xóa Service (sc delete)
// ============================================================
void DeleteService_Cmd(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Cách dùng: ServiceManager delete <TênService>\n");
        return;
    }
    const char* serviceName = argv[2];

    SC_HANDLE hSCM = OpenSCM(SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return;

    SC_HANDLE hService = OpenServiceA(hSCM, serviceName, DELETE);
    if (!hService) {
        PrintLastError("OpenService");
        CloseServiceHandle(hSCM);
        return;
    }

    if (DeleteService(hService)) {
        printf("[OK] Đã đánh dấu xóa service '%s'. Service sẽ bị xóa sau khi dừng hoàn toàn.\n", serviceName);
    }
    else {
        PrintLastError("DeleteService");
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
}

// ============================================================
// 3. Khởi động Service (sc start)
// ============================================================
void StartService_Cmd(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Cách dùng: ServiceManager start <TênService>\n");
        return;
    }
    const char* serviceName = argv[2];

    SC_HANDLE hSCM = OpenSCM(SC_MANAGER_CONNECT);
    if (!hSCM) return;

    SC_HANDLE hService = OpenServiceA(hSCM, serviceName, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        PrintLastError("OpenService");
        CloseServiceHandle(hSCM);
        return;
    }

    if (StartServiceA(hService, 0, NULL)) {
        printf("[OK] Đang khởi động service '%s'...\n", serviceName);

        // Chờ service chạy xong (tối đa 30 giây)
        SERVICE_STATUS_PROCESS ssp;
        DWORD bytesNeeded;
        DWORD startTick = GetTickCount();

        while (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded))
        {
            if (ssp.dwCurrentState == SERVICE_RUNNING) {
                printf("[OK] Service '%s' đã chạy! PID: %lu\n", serviceName, ssp.dwProcessId);
                break;
            }
            if (GetTickCount() - startTick > 30000) {
                printf("[CẢNH BÁO] Timeout chờ service khởi động.\n");
                break;
            }
            Sleep(500);
        }
    }
    else {
        PrintLastError("StartService");
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
}

// ============================================================
// 4. Dừng Service (sc stop)
// ============================================================
void StopService_Cmd(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Cách dùng: ServiceManager stop <TênService>\n");
        return;
    }
    const char* serviceName = argv[2];

    SC_HANDLE hSCM = OpenSCM(SC_MANAGER_CONNECT);
    if (!hSCM) return;

    SC_HANDLE hService = OpenServiceA(hSCM, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService) {
        PrintLastError("OpenService");
        CloseServiceHandle(hSCM);
        return;
    }

    SERVICE_STATUS ss;
    if (ControlService(hService, SERVICE_CONTROL_STOP, &ss)) {
        printf("[OK] Đang dừng service '%s'...\n", serviceName);

        // Chờ dừng hoàn toàn
        DWORD startTick = GetTickCount();
        while (ss.dwCurrentState != SERVICE_STOPPED) {
            Sleep(500);
            if (!QueryServiceStatus(hService, &ss)) break;
            if (GetTickCount() - startTick > 30000) {
                printf("[CẢNH BÁO] Timeout chờ service dừng.\n");
                break;
            }
        }
        if (ss.dwCurrentState == SERVICE_STOPPED)
            printf("[OK] Service '%s' đã dừng.\n", serviceName);
    }
    else {
        PrintLastError("ControlService (STOP)");
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
}

// ============================================================
// 5. Xem trạng thái Service (sc query)
// ============================================================
void QueryService_Cmd(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Cách dùng: ServiceManager query <TênService>\n");
        return;
    }
    const char* serviceName = argv[2];

    SC_HANDLE hSCM = OpenSCM(SC_MANAGER_CONNECT);
    if (!hSCM) return;

    SC_HANDLE hService = OpenServiceA(hSCM, serviceName,
        SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!hService) {
        PrintLastError("OpenService");
        CloseServiceHandle(hSCM);
        return;
    }

    // Lấy trạng thái
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded))
    {
        const char* stateStr;
        switch (ssp.dwCurrentState) {
        case SERVICE_STOPPED:          stateStr = "STOPPED";          break;
        case SERVICE_START_PENDING:    stateStr = "START_PENDING";    break;
        case SERVICE_STOP_PENDING:     stateStr = "STOP_PENDING";     break;
        case SERVICE_RUNNING:          stateStr = "RUNNING";          break;
        case SERVICE_CONTINUE_PENDING: stateStr = "CONTINUE_PENDING"; break;
        case SERVICE_PAUSE_PENDING:    stateStr = "PAUSE_PENDING";    break;
        case SERVICE_PAUSED:           stateStr = "PAUSED";           break;
        default:                       stateStr = "UNKNOWN";          break;
        }
        printf("\n[TRẠNG THÁI SERVICE]\n");
        printf("  Tên Service  : %s\n", serviceName);
        printf("  Trạng thái  : %s\n", stateStr);
        printf("  PID          : %lu\n", ssp.dwProcessId);
    }
    else {
        PrintLastError("QueryServiceStatusEx");
    }

    // Lấy cấu hình
    DWORD configSize = 0;
    QueryServiceConfigA(hService, NULL, 0, &configSize);
    if (configSize > 0) {
        LPQUERY_SERVICE_CONFIGA pConfig = (LPQUERY_SERVICE_CONFIGA)malloc(configSize);
        if (QueryServiceConfigA(hService, pConfig, configSize, &configSize)) {
            const char* startStr;
            switch (pConfig->dwStartType) {
            case SERVICE_AUTO_START:   startStr = "Auto";     break;
            case SERVICE_DEMAND_START: startStr = "Manual";   break;
            case SERVICE_DISABLED:     startStr = "Disabled"; break;
            default:                   startStr = "Unknown";  break;
            }
            printf("  Kiểu khởi động: %s\n", startStr);
            printf("  Đường dẫn EXE: %s\n", pConfig->lpBinaryPathName);
            printf("  Display Name : %s\n", pConfig->lpDisplayName);
        }
        free(pConfig);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
}

// ============================================================
// 6. Liệt kê tất cả Services (sc query type= all)
// ============================================================
void ListServices_Cmd() {
    SC_HANDLE hSCM = OpenSCM(SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return;

    DWORD bytesNeeded = 0, numServices = 0, resumeHandle = 0;

    // Gọi lần đầu để lấy kích thước buffer cần thiết
    EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &numServices, &resumeHandle, NULL);

    LPBYTE buffer = (LPBYTE)malloc(bytesNeeded);
    if (!buffer) { CloseServiceHandle(hSCM); return; }

    resumeHandle = 0;
    if (EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, buffer, bytesNeeded, &bytesNeeded,
        &numServices, &resumeHandle, NULL))
    {
        LPENUM_SERVICE_STATUS_PROCESSA services = (LPENUM_SERVICE_STATUS_PROCESSA)buffer;

        printf("\n%-40s %-12s %s\n", "TÊN SERVICE", "TRẠNG THÁI", "DISPLAY NAME");
        printf("%-40s %-12s %s\n",
            "----------------------------------------",
            "------------",
            "-------------------------------------------------------");

        for (DWORD i = 0; i < numServices; i++) {
            const char* stateStr;
            switch (services[i].ServiceStatusProcess.dwCurrentState) {
            case SERVICE_RUNNING: stateStr = "RUNNING";  break;
            case SERVICE_STOPPED: stateStr = "STOPPED";  break;
            case SERVICE_PAUSED:  stateStr = "PAUSED";   break;
            default:              stateStr = "PENDING";  break;
            }
            printf("%-40s %-12s %s\n",
                services[i].lpServiceName,
                stateStr,
                services[i].lpDisplayName);
        }
        printf("\nTổng cộng: %lu service(s)\n", numServices);
    }
    else {
        PrintLastError("EnumServicesStatusEx");
    }

    free(buffer);
    CloseServiceHandle(hSCM);
}

// ============================================================
// 7. Thay đổi cấu hình Service (sc config)
// ============================================================
void ConfigService_Cmd(int argc, char* argv[]) {
    // Usage: ServiceManager config <ServiceName> [start=auto|demand|disabled] [binpath=<path>] [displayname=<name>]
    if (argc < 4) {
        printf("Cách dùng: ServiceManager config <TênService> [start=auto|demand|disabled] [binpath=<đường_dẫn>]\n");
        printf("Ví dụ: ServiceManager config MyService start=auto\n");
        return;
    }
    const char* serviceName = argv[2];

    SC_HANDLE hSCM = OpenSCM(SC_MANAGER_CONNECT);
    if (!hSCM) return;

    SC_HANDLE hService = OpenServiceA(hSCM, serviceName, SERVICE_CHANGE_CONFIG);
    if (!hService) {
        PrintLastError("OpenService");
        CloseServiceHandle(hSCM);
        return;
    }

    DWORD startType = SERVICE_NO_CHANGE;
    const char* binPath = NULL;
    const char* dispName = NULL;

    for (int i = 3; i < argc; i++) {
        if (_strnicmp(argv[i], "start=", 6) == 0) {
            const char* val = argv[i] + 6;
            if (_stricmp(val, "auto") == 0)         startType = SERVICE_AUTO_START;
            else if (_stricmp(val, "demand") == 0)  startType = SERVICE_DEMAND_START;
            else if (_stricmp(val, "disabled") == 0) startType = SERVICE_DISABLED;
        }
        else if (_strnicmp(argv[i], "binpath=", 8) == 0) {
            binPath = argv[i] + 8;
        }
        else if (_strnicmp(argv[i], "displayname=", 12) == 0) {
            dispName = argv[i] + 12;
        }
    }

    if (ChangeServiceConfigA(
        hService,
        SERVICE_NO_CHANGE,  // ServiceType
        startType,          // StartType
        SERVICE_NO_CHANGE,  // ErrorControl
        binPath,            // BinaryPathName
        NULL,               // LoadOrderGroup
        NULL,               // TagId
        NULL,               // Dependencies
        NULL,               // ServiceStartName
        NULL,               // Password
        dispName            // DisplayName
    )) {
        printf("[OK] Đã cập nhật cấu hình service '%s'.\n", serviceName);
    }
    else {
        PrintLastError("ChangeServiceConfig");
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
}

// ============================================================
// In hướng dẫn sử dụng
// ============================================================
void PrintUsage(const char* progName) {
    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║         WINDOWS SERVICE MANAGER (WinAPI)                 ║\n");
    printf("║         Tương đương sc.exe - Viết bằng C++ & WinAPI      ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
    printf("Cách dùng: %s <lệnh> [tùy chọn]\n\n", progName);
    printf("Các lệnh:\n");
    printf("  create  <tên> <binpath> [displayname] [auto|demand|disabled]\n");
    printf("          Tạo service mới\n\n");
    printf("  delete  <tên>\n");
    printf("          Xóa service\n\n");
    printf("  start   <tên>\n");
    printf("          Khởi động service\n\n");
    printf("  stop    <tên>\n");
    printf("          Dừng service\n\n");
    printf("  query   <tên>\n");
    printf("          Xem trạng thái và cấu hình service\n\n");
    printf("  list\n");
    printf("          Liệt kê tất cả services\n\n");
    printf("  config  <tên> [start=auto|demand|disabled] [binpath=<đường_dẫn>]\n");
    printf("          Thay đổi cấu hình service\n\n");
    printf("Ghi chú: Cần chạy với quyền Administrator!\n\n");
}

// ============================================================
// MAIN
// ============================================================
int main(int argc, char* argv[]) {
    // Set console output to UTF-8 (cho tiếng Việt)
    SetConsoleOutputCP(65001);

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    const char* command = argv[1];

    if (_stricmp(command, "create") == 0) { CreateService_Cmd(argc, argv); }
    else if (_stricmp(command, "delete") == 0) { DeleteService_Cmd(argc, argv); }
    else if (_stricmp(command, "start") == 0) { StartService_Cmd(argc, argv); }
    else if (_stricmp(command, "stop") == 0) { StopService_Cmd(argc, argv); }
    else if (_stricmp(command, "query") == 0) { QueryService_Cmd(argc, argv); }
    else if (_stricmp(command, "list") == 0) { ListServices_Cmd(); }
    else if (_stricmp(command, "config") == 0) { ConfigService_Cmd(argc, argv); }
    else {
        printf("[LỖI] Lệnh không hợp lệ: '%s'\n", command);
        PrintUsage(argv[0]);
        return 1;
    }

    return 0;
}