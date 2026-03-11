// step2.cpp
// Mục tiêu: Kết nối → chạy lệnh "hostname" → in output thô → thoát
//
// Compile:
//   cl /EHsc /DUNICODE /D_UNICODE step2.cpp Wsmsvc.lib /Fe:step2.exe
//
// Chạy:
//   step2.exe 192.168.1.100 Administrator P@ssword

#define WSMAN_API_VERSION_1_1
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <wsman.h>
#include <stdio.h>
#include <stdlib.h>   // malloc, free

#pragma comment(lib, "Wsmsvc.lib")

// ─────────────────────────────────────────────────────────────
// CTX — mở rộng từ Bước 1, thêm field cho command & output
// ─────────────────────────────────────────────────────────────
typedef struct {
    HANDLE               hEvent;    // đèn đỏ/xanh
    HRESULT              hr;        // kết quả

    // Bước 1 dùng:
    WSMAN_SHELL_HANDLE   hShell;

    // Bước 2 thêm:
    WSMAN_COMMAND_HANDLE hCommand;  // handle lệnh đang chạy
    char* pOutput;   // buffer chứa output text
    DWORD                cbOutput;  // số bytes trong buffer
    BOOL                 bCmdDone;  // lệnh đã chạy xong chưa?
    DWORD                exitCode;  // exit code của lệnh
} CTX;

// ─────────────────────────────────────────────────────────────
// Helper: in lỗi ra stderr
// ─────────────────────────────────────────────────────────────
static void PrintError(LPCWSTR where, HRESULT hr)
{
    WCHAR msg[256] = {};
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, (DWORD)hr, 0, msg, ARRAYSIZE(msg), NULL);
    fwprintf(stderr, L"[!] %s that bai: 0x%08X — %s\n", where, (UINT)hr, msg);
}

// ─────────────────────────────────────────────────────────────
// Callback 1: Khi CreateShell xong
// (giống hệt Bước 1, không thay đổi gì)
// ─────────────────────────────────────────────────────────────
void CALLBACK OnShellCreated(
    PVOID pCtx, DWORD flags,
    WSMAN_ERROR* pErr,
    WSMAN_SHELL_HANDLE hShell,
    WSMAN_COMMAND_HANDLE, WSMAN_OPERATION_HANDLE,
    WSMAN_RESPONSE_DATA*)
{
    CTX* c = (CTX*)pCtx;
    c->hr = (pErr && pErr->code) ? HRESULT_FROM_WIN32(pErr->code) : S_OK;
    if (SUCCEEDED(c->hr)) c->hShell = hShell;
    SetEvent(c->hEvent);   // 🟢 đèn xanh
}

// ─────────────────────────────────────────────────────────────
// Callback 2: Khi RunShellCommand xong
// Windows gọi hàm này khi lệnh đã được gửi đến máy đích
// (lưu ý: lệnh mới BẮT ĐẦU chạy, chưa có output)
// ─────────────────────────────────────────────────────────────
void CALLBACK OnCommandSent(
    PVOID pCtx, DWORD flags,
    WSMAN_ERROR* pErr,
    WSMAN_SHELL_HANDLE,
    WSMAN_COMMAND_HANDLE hCommand,   // ← handle để track lệnh này
    WSMAN_OPERATION_HANDLE,
    WSMAN_RESPONSE_DATA*)
{
    CTX* c = (CTX*)pCtx;
    c->hr = (pErr && pErr->code) ? HRESULT_FROM_WIN32(pErr->code) : S_OK;

    if (SUCCEEDED(c->hr)) {
        c->hCommand = hCommand;  // lưu lại để dùng khi receive output
        wprintf(L"[Callback2] Lenh da duoc gui, dang chay tren may dich...\n");
    }

    SetEvent(c->hEvent);  // 🟢 đèn xanh
}

// ─────────────────────────────────────────────────────────────
// Callback 3: Khi ReceiveOutput có data
//
// Đây là callback QUAN TRỌNG NHẤT ở Bước 2
// Windows gọi hàm này khi có output từ lệnh trả về
// ─────────────────────────────────────────────────────────────
void CALLBACK OnOutputReceived(
    PVOID pCtx, DWORD flags,
    WSMAN_ERROR* pErr,
    WSMAN_SHELL_HANDLE,
    WSMAN_COMMAND_HANDLE,
    WSMAN_OPERATION_HANDLE,
    WSMAN_RESPONSE_DATA* pData)   // ← output nằm ở đây
{
    CTX* c = (CTX*)pCtx;

    if (pErr && pErr->code) {
        c->hr = HRESULT_FROM_WIN32(pErr->code);
        SetEvent(c->hEvent);
        return;
    }

    c->hr = S_OK;

    // ── Đọc output từ pData ───────────────────────────────────
    //
    // Cấu trúc pData:
    //   pData
    //     └── receiveData
    //           ├── commandState  → "Running" hoặc "Done"
    //           ├── exitCode      → exit code khi Done
    //           └── streamData
    //                 └── binaryData
    //                       ├── data         → bytes output thực sự
    //                       └── dataLength   → số bytes

    if (pData) {
        WSMAN_RECEIVE_DATA_RESULT* r = &pData->receiveData;

        // Kiểm tra lệnh đã xong chưa
        if (r->commandState &&
            wcscmp(r->commandState, WSMAN_COMMAND_STATE_DONE) == 0)
        {
            c->bCmdDone = TRUE;
            c->exitCode = r->exitCode;
            wprintf(L"[Callback3] Lenh chay xong! ExitCode = %lu\n", r->exitCode);
        }

        // Lấy output bytes
        DWORD len = r->streamData.binaryData.dataLength;
        BYTE* src = r->streamData.binaryData.data;

        if (len > 0 && src) {
            // realloc mở rộng buffer thêm len bytes
            char* tmp = (char*)realloc(c->pOutput, c->cbOutput + len + 1);
            if (tmp) {
                c->pOutput = tmp;
                memcpy(c->pOutput + c->cbOutput, src, len); // nối VÀO CUỐI
                c->cbOutput += len;                          // cộng dồn
                c->pOutput[c->cbOutput] = '\0';
            }
            wprintf(L"[Callback3] Nhan duoc %lu bytes (tong: %lu)\n",
                len, c->cbOutput);
        }
    }

    SetEvent(c->hEvent);  // 🟢 đèn xanh
}

// ─────────────────────────────────────────────────────────────
// Hàm tiện ích: Reset CTX giữa các lần dùng
// (giữ hEvent, hShell, hCommand — reset phần kết quả)
// ─────────────────────────────────────────────────────────────
static void CtxReset(CTX* c)
{
    c->hr = E_PENDING;
    c->pOutput = NULL;
    c->cbOutput = 0;
    c->bCmdDone = FALSE;
    c->exitCode = 0;
    ResetEvent(c->hEvent);  // 🔴 về đèn đỏ
}

// ─────────────────────────────────────────────────────────────
// wmain
// ─────────────────────────────────────────────────────────────
int wmain(int argc, WCHAR* argv[])
{
    if (argc < 4) {
        wprintf(L"Dung: step2.exe <IP> <user> <pass>\n");
        return 1;
    }

    LPCWSTR ip = argv[1];
    LPCWSTR user = argv[2];
    LPCWSTR pass = argv[3];

    // Lệnh cố định để test — Bước 4 sẽ nhận từ argv
    LPCWSTR TEST_CMD = L"ipconfig";

    HRESULT hr = S_OK;

    // ════════════════════════════════════════════════════════
    // PHẦN 1: Setup (giống hệt Bước 1)
    // ════════════════════════════════════════════════════════

    // Khởi động engine
    WSMAN_API_HANDLE hAPI = NULL;
    hr = WSManInitialize(WSMAN_FLAG_REQUESTED_API_VERSION_1_1, &hAPI);
    if (FAILED(hr)) { PrintError(L"WSManInitialize", hr); return 1; }

    // Tạo session
    WSMAN_USERNAME_PASSWORD_CREDS creds = { user, pass };
    WSMAN_AUTHENTICATION_CREDENTIALS auth = {};
    //auth.authenticationMechanism = WSMAN_FLAG_AUTH_BASIC;
    auth.authenticationMechanism = WSMAN_FLAG_AUTH_NEGOTIATE;
    auth.userAccount = creds;

    WCHAR endpoint[256];
    swprintf_s(endpoint, ARRAYSIZE(endpoint), L"http://%s:5985/wsman", ip);

    WSMAN_SESSION_HANDLE hSession = NULL;
    hr = WSManCreateSession(hAPI, endpoint, 0, &auth, NULL, &hSession);
    if (FAILED(hr)) { 
        PrintError(L"WSManCreateSession", hr); 
        return 1;
        //goto done; 
    }

    // Cho phép HTTP không mã hóa
    WSMAN_DATA opt = { WSMAN_DATA_TYPE_DWORD };
    opt.number = 1;
    WSManSetSessionOption(hSession, (WSManSessionOption)3, &opt);

    // ════════════════════════════════════════════════════════
    // PHẦN 2: Tạo CTX dùng chung cho cả 3 async operation
    // ════════════════════════════════════════════════════════
    CTX ctx = {};
    ctx.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ctx.hEvent) { wprintf(L"[!] CreateEvent that bai\n"); goto done; }

    // ════════════════════════════════════════════════════════
    // ASYNC OP 1: Tạo Shell
    // ════════════════════════════════════════════════════════
    wprintf(L"\n[1/3] Tao shell...\n");
    {
        WSMAN_SHELL_ASYNC a = { &ctx, OnShellCreated };
        WSMAN_SHELL_HANDLE hShell = NULL;

        WSManCreateShell(hSession, 0,
            L"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
            NULL, NULL, NULL, &a, &hShell);

        if (WaitForSingleObject(ctx.hEvent, 15000) == WAIT_TIMEOUT) {
            wprintf(L"[!] Timeout tao shell\n"); goto done;
        }
        if (FAILED(ctx.hr)) { PrintError(L"CreateShell", ctx.hr); goto done; }

        wprintf(L"[+] Shell OK — hShell = %p\n", ctx.hShell);
    }

    // ════════════════════════════════════════════════════════
    // ASYNC OP 2: Gửi lệnh
    //
    // Luồng:
    //   WSManRunShellCommand()  →  gửi lệnh tới cmd.exe trên máy đích
    //   OnCommandSent()         →  được gọi khi lệnh BẮT ĐẦU chạy
    //   ctx.hCommand            →  lưu lại để receive output
    // ════════════════════════════════════════════════════════
    wprintf(L"\n[2/3] Gui lenh: \"%s\"...\n", TEST_CMD);
    CtxReset(&ctx);  // 🔴 reset trước mỗi async op
    {
        WSMAN_SHELL_ASYNC a = { &ctx, OnCommandSent };
        WSMAN_COMMAND_HANDLE hCmd = NULL;

        WSManRunShellCommand(
            ctx.hShell,  // shell đã tạo ở Op 1
            0,           // flags
            TEST_CMD,    // lệnh cần chạy (L"hostname")
            NULL,        // arguments (NULL = không có)
            NULL,        // options
            &a,          // callback
            &hCmd        // [OUT] handle tạm (chưa dùng được ngay)
        );

        if (WaitForSingleObject(ctx.hEvent, 15000) == WAIT_TIMEOUT) {
            wprintf(L"[!] Timeout gui lenh\n"); goto done;
        }
        if (FAILED(ctx.hr)) { PrintError(L"RunShellCommand", ctx.hr); goto done; }

        wprintf(L"[+] Lenh da gui OK — hCommand = %p\n", ctx.hCommand);
    }

    // ════════════════════════════════════════════════════════
    // ASYNC OP 3: Nhận output
    //
    // Luồng:
    //   WSManReceiveShellOutput()  →  "hãy gửi output về cho tôi"
    //   OnOutputReceived()         →  được gọi khi có data
    //   ctx.pOutput                →  buffer chứa text output
    //   ctx.bCmdDone               →  TRUE khi lệnh xong hoàn toàn
    // ════════════════════════════════════════════════════════
    wprintf(L"\n[3/3] Nhan output...\n");
    CtxReset(&ctx);
    {
        // Chỉ định nhận stdout + stderr
        PCWSTR streamNames[2] = { L"stdout", L"stderr" };
        WSMAN_STREAM_ID_SET streams = { 2, streamNames };

        WSMAN_SHELL_ASYNC a = { &ctx, OnOutputReceived };
        WSMAN_OPERATION_HANDLE hOp = NULL;

        WSManReceiveShellOutput(
            ctx.hShell,    // shell
            ctx.hCommand,  // lệnh cần lấy output
            0,             // flags
            &streams,      // stdout + stderr
            &a,            // callback
            &hOp           // [OUT] operation handle
        );

        if (WaitForSingleObject(ctx.hEvent, 15000) == WAIT_TIMEOUT) {
            wprintf(L"[!] Timeout nhan output\n"); goto done;
        }
        if (FAILED(ctx.hr)) { PrintError(L"ReceiveOutput", ctx.hr); goto done; }

        // Đóng operation handle
        if (hOp) { WSManCloseOperation(hOp, 0); hOp = NULL; }
    }

    // ════════════════════════════════════════════════════════
    // IN KẾT QUẢ
    // ════════════════════════════════════════════════════════
    wprintf(L"\n");
    wprintf(L"╔══════════════════════════════════════╗\n");
    wprintf(L"║           OUTPUT TU MAY DICH         ║\n");
    wprintf(L"╚══════════════════════════════════════╝\n");

    if (ctx.pOutput && ctx.cbOutput > 0) {
        // Output là bytes OEM/CP850 → in thẳng ra console
        HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD  written = 0;
        WriteConsoleA(hCon, ctx.pOutput, ctx.cbOutput, &written, NULL);
    }
    else {
        wprintf(L"(Khong co output)\n");
    }

    wprintf(L"\n[*] ExitCode = %lu\n", ctx.exitCode);
    wprintf(L"[*] bCmdDone = %s\n", ctx.bCmdDone ? L"TRUE" : L"FALSE");

done:
    // Dọn dẹp theo thứ tự ngược
    if (ctx.pOutput) free(ctx.pOutput);
    if (ctx.hCommand) WSManCloseCommand(ctx.hCommand, 0, NULL);
    if (ctx.hShell)   WSManCloseShell(ctx.hShell, 0, NULL);
    if (hSession)     WSManCloseSession(hSession, 0);
    if (hAPI)         WSManDeinitialize(hAPI, 0);
    if (ctx.hEvent)   CloseHandle(ctx.hEvent);

    return SUCCEEDED(hr) ? 0 : 1;
}