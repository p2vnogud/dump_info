// step3.cpp
// Mục tiêu: Receive loop hoàn chỉnh — nhận đủ output dù lệnh dài
//
// Compile:
//   cl /EHsc /DUNICODE /D_UNICODE step3.cpp Wsmsvc.lib /Fe:step3.exe
//
// Chạy:
//   step3.exe 192.168.1.100 Administrator P@ssword "dir C:\"

#define WSMAN_API_VERSION_1_1
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <wsman.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "Wsmsvc.lib")

// ─────────────────────────────────────────────────────────────
// CTX — giống Bước 2, thêm field accumulatedOutput
// ─────────────────────────────────────────────────────────────
typedef struct {
    HANDLE               hEvent;
    HRESULT              hr;
    WSMAN_SHELL_HANDLE   hShell;
    WSMAN_COMMAND_HANDLE hCommand;

    // Output tích lũy qua nhiều chunk
    char* pChunk;      // chunk vừa nhận trong 1 lần receive
    DWORD  cbChunk;     // size của chunk đó

    BOOL   bCmdDone;    // TRUE khi lệnh xong hoàn toàn
    DWORD  exitCode;
} CTX;

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────
static void PrintError(LPCWSTR where, HRESULT hr)
{
    WCHAR msg[256] = {};
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, (DWORD)hr, 0, msg, ARRAYSIZE(msg), NULL);
    fwprintf(stderr, L"[!] %s: 0x%08X — %s\n", where, (UINT)hr, msg);
}

static void PrintBytes(const char* buf, DWORD cb)
{
    if (!buf || !cb) return;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD w = 0;
    if (!WriteConsoleA(h, buf, cb, &w, NULL) || !w)
        fwrite(buf, 1, cb, stdout);
}

// ─────────────────────────────────────────────────────────────
// Callback 1 & 2 — không đổi so với Bước 2
// ─────────────────────────────────────────────────────────────
void CALLBACK OnShellCreated(
    PVOID pCtx, DWORD,
    WSMAN_ERROR* pErr,
    WSMAN_SHELL_HANDLE hShell,
    WSMAN_COMMAND_HANDLE, WSMAN_OPERATION_HANDLE, WSMAN_RESPONSE_DATA*)
{
    CTX* c = (CTX*)pCtx;
    c->hr = (pErr && pErr->code) ? HRESULT_FROM_WIN32(pErr->code) : S_OK;
    if (SUCCEEDED(c->hr)) c->hShell = hShell;
    SetEvent(c->hEvent);
}

void CALLBACK OnCommandSent(
    PVOID pCtx, DWORD,
    WSMAN_ERROR* pErr,
    WSMAN_SHELL_HANDLE,
    WSMAN_COMMAND_HANDLE hCommand,
    WSMAN_OPERATION_HANDLE, WSMAN_RESPONSE_DATA*)
{
    CTX* c = (CTX*)pCtx;
    c->hr = (pErr && pErr->code) ? HRESULT_FROM_WIN32(pErr->code) : S_OK;
    if (SUCCEEDED(c->hr)) c->hCommand = hCommand;
    SetEvent(c->hEvent);
}

// ─────────────────────────────────────────────────────────────
// Callback 3 — THAY ĐỔI so với Bước 2:
//
// Bước 2: lưu tất cả vào pOutput (accumulate)
// Bước 3: chỉ lưu CHUNK HIỆN TẠI vào pChunk
//         → loop bên ngoài sẽ in ngay rồi gọi tiếp
//
// Lý do: lệnh dài có thể có output hàng MB
//        in ngay từng chunk → user thấy output realtime
//        không cần buffer toàn bộ trong RAM
// ─────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────
// Callback 3 — FIX: phân biệt DATA callback vs END callback
// ─────────────────────────────────────────────────────────────
void CALLBACK OnChunkReceived(
    PVOID pCtx, DWORD flags,
    WSMAN_ERROR* pErr,
    WSMAN_SHELL_HANDLE,
    WSMAN_COMMAND_HANDLE,
    WSMAN_OPERATION_HANDLE,
    WSMAN_RESPONSE_DATA* pData)
{
    CTX* c = (CTX*)pCtx;

    if (pErr && pErr->code) {
        c->hr = HRESULT_FROM_WIN32(pErr->code);
        // Vẫn SetEvent để loop biết có lỗi
        SetEvent(c->hEvent);
        return;
    }
    c->hr = S_OK;

    if (pData) {
        WSMAN_RECEIVE_DATA_RESULT* r = &pData->receiveData;

        // Lệnh xong?
        if (r->commandState &&
            wcscmp(r->commandState, WSMAN_COMMAND_STATE_DONE) == 0)
        {
            c->bCmdDone = TRUE;
            c->exitCode = r->exitCode;
        }

        DWORD len = r->streamData.binaryData.dataLength;
        BYTE* src = r->streamData.binaryData.data;

        // ✅ realloc tích lũy — KHÔNG ghi đè
        if (len > 0 && src) {
            char* tmp = (char*)realloc(c->pChunk, c->cbChunk + len + 1);
            if (tmp) {
                c->pChunk = tmp;
                memcpy(c->pChunk + c->cbChunk, src, len);
                c->cbChunk += len;
                c->pChunk[c->cbChunk] = '\0';
            }
        }
    }

    // ✅ SetEvent khi END_OF_OPERATION
    // Từ log: flag 0x8 và 0x9 đều có bit END (bit 3 = 0x8)
    if (flags & WSMAN_FLAG_CALLBACK_END_OF_OPERATION) {
        SetEvent(c->hEvent);
    }
}

// ─────────────────────────────────────────────────────────────
// ReceiveLoop — TRÁI TIM của Bước 3
//
// Sơ đồ:
//
//   bDone = FALSE
//   totalBytes = 0
//      │
//      ▼
//   ┌─────────────────────────────────────┐
//   │  Reset hEvent về đỏ                 │
//   │  Gọi WSManReceiveShellOutput()      │
//   │  WaitForSingleObject(hEvent, 5000)  │
//   │         │                           │
//   │    TIMEOUT?                         │
//   │      → chưa có data, thử lại        │
//   │         │                           │
//   │    CÓ DATA?                         │
//   │      → in pChunk ra console         │
//   │      → cộng vào totalBytes          │
//   │      → đóng hOp                     │
//   │         │                           │
//   │    bDone == TRUE?                   │
//   │      → thoát vòng lặp               │
//   └─────────────────────────────────────┘
//
// ─────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────
// ReceiveLoop — FIX: thêm xử lý lệnh interactive (cmd.exe)
// ─────────────────────────────────────────────────────────────
static HRESULT ReceiveLoop(CTX* ctx)
{
    PCWSTR streamNames[2] = { L"stdout", L"stderr" };
    WSMAN_STREAM_ID_SET streams = { 2, streamNames };

    DWORD totalBytes = 0;
    int   loopCount = 0;

    wprintf(L"\n──────────── OUTPUT ────────────\n");

    while (!ctx->bCmdDone)
    {
        loopCount++;

        // Dọn chunk cũ từ vòng trước
        if (ctx->pChunk) { free(ctx->pChunk); ctx->pChunk = NULL; ctx->cbChunk = 0; }
        ResetEvent(ctx->hEvent);

        // Gửi 1 request receive
        WSMAN_SHELL_ASYNC a = { ctx, OnChunkReceived };
        WSMAN_OPERATION_HANDLE hOp = NULL;

        WSManReceiveShellOutput(
            ctx->hShell, ctx->hCommand,
            0, &streams, &a, &hOp);

        // Chờ callback báo END_OF_OPERATION
        // Timeout dài hơn vì callback tích lũy nhiều chunk
        DWORD w = WaitForSingleObject(ctx->hEvent, 30000);

        if (hOp) { WSManCloseOperation(hOp, 0); hOp = NULL; }

        if (w == WAIT_TIMEOUT) {
            wprintf(L"\n[!] Timeout 30s\n");
            break;
        }

        // Lỗi ABORTED = lệnh interactive (cmd.exe) bị đóng → coi như xong
        if (ctx->hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) {
            if (ctx->pChunk && ctx->cbChunk > 0) {
                PrintBytes(ctx->pChunk, ctx->cbChunk);
                totalBytes += ctx->cbChunk;
            }
            break;
        }

        if (FAILED(ctx->hr)) {
            PrintError(L"ReceiveLoop", ctx->hr);
            return ctx->hr;
        }

        // In chunk đã tích lũy
        if (ctx->pChunk && ctx->cbChunk > 0) {
            PrintBytes(ctx->pChunk, ctx->cbChunk);
            totalBytes += ctx->cbChunk;
        }

        // bCmdDone được set trong callback → while tự thoát
    }

    wprintf(L"\n────────────────────────────────\n");
    wprintf(L"[+] Tong: %lu bytes, %d vong\n", totalBytes, loopCount);

    return S_OK;
}

// ─────────────────────────────────────────────────────────────
// wmain
// ─────────────────────────────────────────────────────────────
int wmain(int argc, WCHAR* argv[])
{
    if (argc < 5) {
        wprintf(L"Dung: step3.exe <IP> <user> <pass> <lenh>\n");
        wprintf(L"VD  : step3.exe 192.168.1.100 Administrator P@ss \"dir C:\\\"\n");
        return 1;
    }

    LPCWSTR ip = argv[1];
    LPCWSTR user = argv[2];
    LPCWSTR pass = argv[3];
    LPCWSTR cmd = argv[4];

    HRESULT hr = S_OK;

    // ── Setup ─────────────────────────────────────────────────
    WSMAN_API_HANDLE hAPI = NULL;
    hr = WSManInitialize(WSMAN_FLAG_REQUESTED_API_VERSION_1_1, &hAPI);
    if (FAILED(hr)) { PrintError(L"WSManInitialize", hr); return 1; }

    WSMAN_USERNAME_PASSWORD_CREDS creds = { user, pass };
    WSMAN_AUTHENTICATION_CREDENTIALS auth = {};
    auth.authenticationMechanism = WSMAN_FLAG_AUTH_NEGOTIATE;
    auth.userAccount = creds;

    WCHAR endpoint[256];
    swprintf_s(endpoint, ARRAYSIZE(endpoint), L"http://%s:5985/wsman", ip);

    WSMAN_SESSION_HANDLE hSession = NULL;
    hr = WSManCreateSession(hAPI, endpoint, 0, &auth, NULL, &hSession);
    if (FAILED(hr)) { PrintError(L"WSManCreateSession", hr); return 1; }

    WSMAN_DATA opt = { WSMAN_DATA_TYPE_DWORD };
    opt.number = 1;
    WSManSetSessionOption(hSession, (WSManSessionOption)3, &opt);

    // ── Tạo CTX ───────────────────────────────────────────────
    CTX ctx = {};
    ctx.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ctx.hEvent) { wprintf(L"[!] CreateEvent that bai\n"); goto done; }

    // ── ASYNC OP 1: Tạo Shell ────────────────────────────────
    wprintf(L"[1/3] Tao shell...\n");
    {
        WSMAN_SHELL_ASYNC a = { &ctx, OnShellCreated };
        WSMAN_SHELL_HANDLE hShell = NULL;
        WSManCreateShell(hSession, 0,
            L"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
            NULL, NULL, NULL, &a, &hShell);

        if (WaitForSingleObject(ctx.hEvent, 15000) == WAIT_TIMEOUT) {
            wprintf(L"[!] Timeout\n"); goto done;
        }
        if (FAILED(ctx.hr)) { PrintError(L"CreateShell", ctx.hr); goto done; }
        wprintf(L"[+] Shell OK\n");
    }

    // ── ASYNC OP 2: Gửi lệnh ────────────────────────────────
    wprintf(L"[2/3] Gui lenh: \"%s\"\n", cmd);
    ResetEvent(ctx.hEvent);
    {
        WSMAN_SHELL_ASYNC a = { &ctx, OnCommandSent };
        WSMAN_COMMAND_HANDLE hCmd = NULL;
        WSManRunShellCommand(ctx.hShell, 0, cmd, NULL, NULL, &a, &hCmd);

        if (WaitForSingleObject(ctx.hEvent, 15000) == WAIT_TIMEOUT) {
            wprintf(L"[!] Timeout\n"); goto done;
        }
        if (FAILED(ctx.hr)) { PrintError(L"RunShellCommand", ctx.hr); goto done; }
        wprintf(L"[+] Lenh da gui OK\n");
    }

    // ── ASYNC OP 3: Receive loop ─────────────────────────────
    wprintf(L"[3/3] Bat dau receive loop...\n");
    hr = ReceiveLoop(&ctx);

    wprintf(L"\n[*] ExitCode = %lu\n", ctx.exitCode);

done:
    if (ctx.pChunk)   free(ctx.pChunk);
    if (ctx.hCommand) WSManCloseCommand(ctx.hCommand, 0, NULL);
    if (ctx.hShell)   WSManCloseShell(ctx.hShell, 0, NULL);
    if (hSession)     WSManCloseSession(hSession, 0);
    if (hAPI)         WSManDeinitialize(hAPI, 0);
    if (ctx.hEvent)   CloseHandle(ctx.hEvent);

    return SUCCEEDED(hr) ? 0 : 1;
}