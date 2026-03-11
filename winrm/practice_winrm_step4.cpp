// step4.cpp
// Mục tiêu: ModeSingle hoàn chỉnh — nhận lệnh từ argv, chạy, in output, thoát
//
// Compile:
//   cl /EHsc /DUNICODE /D_UNICODE step4.cpp Wsmsvc.lib /Fe:step4.exe
//
// Chạy:
//   step4.exe 192.168.1.100 Administrator P@ss "ipconfig /all"
//   step4.exe 192.168.1.100 Administrator P@ss "dir C:\Users"

#define WSMAN_API_VERSION_1_1
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <wsman.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>

#pragma comment(lib, "Wsmsvc.lib")
#pragma comment(lib, "Strsafe.lib")

// ═════════════════════════════════════════════════════════════
// CTX — không đổi so với Bước 3
// ═════════════════════════════════════════════════════════════
typedef struct {
    HANDLE               hEvent;
    HRESULT              hr;
    WSMAN_SHELL_HANDLE   hShell;
    WSMAN_COMMAND_HANDLE hCommand;
    char* pChunk;
    DWORD                cbChunk;
    BOOL                 bCmdDone;
    DWORD                exitCode;
} CTX;

// ═════════════════════════════════════════════════════════════
// SESSION — gom hết handle vào 1 struct
// Mục đích: SessionOpen/SessionClose gọn hơn
// ═════════════════════════════════════════════════════════════
typedef struct {
    WSMAN_API_HANDLE     hAPI;
    WSMAN_SESSION_HANDLE hSession;
} SESSION;

// ═════════════════════════════════════════════════════════════
// Helpers
// ═════════════════════════════════════════════════════════════
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

// ═════════════════════════════════════════════════════════════
// 3 Callbacks — không đổi so với Bước 3
// ═════════════════════════════════════════════════════════════
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
        SetEvent(c->hEvent);
        return;
    }
    c->hr = S_OK;

    if (pData) {
        WSMAN_RECEIVE_DATA_RESULT* r = &pData->receiveData;

        if (r->commandState &&
            wcscmp(r->commandState, WSMAN_COMMAND_STATE_DONE) == 0)
        {
            c->bCmdDone = TRUE;
            c->exitCode = r->exitCode;
        }

        DWORD len = r->streamData.binaryData.dataLength;
        BYTE* src = r->streamData.binaryData.data;

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

    if (flags & WSMAN_FLAG_CALLBACK_END_OF_OPERATION)
        SetEvent(c->hEvent);
}

// ═════════════════════════════════════════════════════════════
// ReceiveLoop — không đổi so với Bước 3
// ═════════════════════════════════════════════════════════════
static HRESULT ReceiveLoop(CTX* ctx)
{
    PCWSTR streamNames[2] = { L"stdout", L"stderr" };
    WSMAN_STREAM_ID_SET streams = { 2, streamNames };
    DWORD totalBytes = 0;

    while (!ctx->bCmdDone)
    {
        if (ctx->pChunk) { free(ctx->pChunk); ctx->pChunk = NULL; ctx->cbChunk = 0; }
        ResetEvent(ctx->hEvent);

        WSMAN_SHELL_ASYNC a = { ctx, OnChunkReceived };
        WSMAN_OPERATION_HANDLE hOp = NULL;
        WSManReceiveShellOutput(ctx->hShell, ctx->hCommand, 0, &streams, &a, &hOp);

        DWORD w = WaitForSingleObject(ctx->hEvent, 30000);
        if (hOp) { WSManCloseOperation(hOp, 0); hOp = NULL; }

        if (w == WAIT_TIMEOUT) {
            wprintf(L"\n[!] Timeout\n");
            break;
        }

        if (ctx->hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) {
            if (ctx->pChunk && ctx->cbChunk > 0) {
                PrintBytes(ctx->pChunk, ctx->cbChunk);
                totalBytes += ctx->cbChunk;
            }
            break;
        }

        if (FAILED(ctx->hr)) { PrintError(L"ReceiveLoop", ctx->hr); return ctx->hr; }

        if (ctx->pChunk && ctx->cbChunk > 0) {
            PrintBytes(ctx->pChunk, ctx->cbChunk);
            totalBytes += ctx->cbChunk;
        }
    }

    return S_OK;
}

// ═════════════════════════════════════════════════════════════
// SessionOpen — MỚI ở Bước 4
//
// Tách riêng việc kết nối ra khỏi wmain
// Mục đích: RunCmd chỉ cần nhận SESSION*, không cần biết
//           cách kết nối được tạo như thế nào
// ═════════════════════════════════════════════════════════════
static HRESULT SessionOpen(SESSION* s, LPCWSTR ip,
    LPCWSTR user, LPCWSTR pass)
{
    ZeroMemory(s, sizeof(*s));

    // Khởi động engine
    HRESULT hr = WSManInitialize(WSMAN_FLAG_REQUESTED_API_VERSION_1_1, &s->hAPI);
    if (FAILED(hr)) { PrintError(L"WSManInitialize", hr); return hr; }

    // Thông tin đăng nhập
    WSMAN_USERNAME_PASSWORD_CREDS creds = { user, pass };
    WSMAN_AUTHENTICATION_CREDENTIALS auth = {};
    auth.authenticationMechanism = WSMAN_FLAG_AUTH_NEGOTIATE;
    auth.userAccount = creds;

    // Endpoint URL
    WCHAR endpoint[256];
    StringCchPrintfW(endpoint, ARRAYSIZE(endpoint),
        L"http://%s:5985/wsman", ip);

    // Tạo session
    hr = WSManCreateSession(s->hAPI, endpoint, 0, &auth, NULL, &s->hSession);
    if (FAILED(hr)) { PrintError(L"WSManCreateSession", hr); return hr; }

    // Cho phép HTTP không mã hóa
    WSMAN_DATA opt = { WSMAN_DATA_TYPE_DWORD };
    opt.number = 1;
    WSManSetSessionOption(s->hSession, (WSManSessionOption)3, &opt);

    wprintf(L"[+] Session OK → %s\n", endpoint);
    return S_OK;
}

// ═════════════════════════════════════════════════════════════
// SessionClose — MỚI ở Bước 4
// ═════════════════════════════════════════════════════════════
static void SessionClose(SESSION* s)
{
    if (s->hSession) { WSManCloseSession(s->hSession, 0); s->hSession = NULL; }
    if (s->hAPI) { WSManDeinitialize(s->hAPI, 0);     s->hAPI = NULL; }
}

// ═════════════════════════════════════════════════════════════
// RunCmd — TRÁI TIM của Bước 4
//
// Nhận vào:  SESSION* + lệnh cần chạy
// Trả về:    HRESULT + exitCode qua con trỏ
//
// Gom 3 async ops (CreateShell + RunCommand + ReceiveLoop)
// vào 1 hàm duy nhất, tái sử dụng được
//
// Sơ đồ:
//   RunCmd(session, "ipconfig /all")
//     │
//     ├─ tạo CTX + hEvent
//     ├─ [ASYNC 1] CreateShell    → ctx.hShell
//     ├─ [ASYNC 2] RunCommand     → ctx.hCommand
//     ├─ [ASYNC 3] ReceiveLoop    → in output
//     └─ dọn dẹp shell + trả về exitCode
// ═════════════════════════════════════════════════════════════
static HRESULT RunCmd(SESSION* s, LPCWSTR cmd, DWORD* pExitCode)
{
    HRESULT hr = S_OK;

    // ── Tạo CTX ───────────────────────────────────────────────
    CTX ctx = {};
    ctx.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ctx.hEvent) return E_OUTOFMEMORY;

    // ── ASYNC 1: Tạo Shell ────────────────────────────────────
    {
        WSMAN_SHELL_ASYNC a = { &ctx, OnShellCreated };
        WSMAN_SHELL_HANDLE hShell = NULL;
        WSManCreateShell(s->hSession, 0,
            L"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
            NULL, NULL, NULL, &a, &hShell);

        if (WaitForSingleObject(ctx.hEvent, 15000) == WAIT_TIMEOUT) {
            hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT);
            wprintf(L"[!] Timeout tao shell\n");
            goto cleanup;
        }
        if (FAILED(ctx.hr)) { hr = ctx.hr; PrintError(L"CreateShell", hr); goto cleanup; }
    }

    // ── ASYNC 2: Gửi lệnh ─────────────────────────────────────
    ResetEvent(ctx.hEvent);
    {
        WSMAN_SHELL_ASYNC a = { &ctx, OnCommandSent };
        WSMAN_COMMAND_HANDLE hCmd = NULL;
        WSManRunShellCommand(ctx.hShell, 0, cmd, NULL, NULL, &a, &hCmd);

        if (WaitForSingleObject(ctx.hEvent, 15000) == WAIT_TIMEOUT) {
            hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT);
            wprintf(L"[!] Timeout gui lenh\n");
            goto cleanup;
        }
        if (FAILED(ctx.hr)) { hr = ctx.hr; PrintError(L"RunCommand", hr); goto cleanup; }
    }

    // ── ASYNC 3: Receive loop ─────────────────────────────────
    hr = ReceiveLoop(&ctx);

    // Lấy exit code
    if (pExitCode) *pExitCode = ctx.exitCode;

cleanup:
    // Dọn theo thứ tự ngược: Command → Shell
    // (Session do SessionClose() lo — RunCmd không đóng session)
    if (ctx.pChunk) { free(ctx.pChunk); }
    if (ctx.hCommand) { WSManCloseCommand(ctx.hCommand, 0, NULL); }
    if (ctx.hShell) { WSManCloseShell(ctx.hShell, 0, NULL); }
    if (ctx.hEvent) { CloseHandle(ctx.hEvent); }

    return hr;
}

// ═════════════════════════════════════════════════════════════
// ModeSingle — MỚI ở Bước 4
//
// Gom SessionOpen + RunCmd + SessionClose thành 1 luồng
// wmain chỉ cần gọi ModeSingle(ip, user, pass, cmd)
// ═════════════════════════════════════════════════════════════
static void ModeSingle(LPCWSTR ip, LPCWSTR user,
    LPCWSTR pass, LPCWSTR cmd)
{
    wprintf(L"\n");
    wprintf(L"╔══════════════════════════════════════════╗\n");
    wprintf(L"║  TARGET : %-30s  ║\n", ip);
    wprintf(L"║  CMD    : %-30s  ║\n", cmd);
    wprintf(L"╚══════════════════════════════════════════╝\n\n");

    // Mở kết nối
    SESSION s;
    HRESULT hr = SessionOpen(&s, ip, user, pass);
    if (FAILED(hr)) return;

    // Chạy lệnh
    wprintf(L"\n──────────── OUTPUT ────────────\n");
    DWORD exitCode = 0;
    hr = RunCmd(&s, cmd, &exitCode);
    wprintf(L"────────────────────────────────\n");

    // Kết quả
    if (SUCCEEDED(hr))
        wprintf(L"[+] ExitCode: %lu\n", exitCode);
    else
        wprintf(L"[!] RunCmd that bai: 0x%08X\n", (UINT)hr);

    // Đóng kết nối
    SessionClose(&s);
}

// ═════════════════════════════════════════════════════════════
// wmain — MỚI ở Bước 4: nhận lệnh từ argv
//
// Xử lý lệnh có khoảng trắng:
//   step4.exe IP user pass ipconfig /all
//   argv[4]="ipconfig"  argv[5]="/all"
//   → ghép lại thành "ipconfig /all"
// ═════════════════════════════════════════════════════════════
int wmain(int argc, WCHAR* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    if (argc < 5) {
        wprintf(L"Dung: step4.exe <IP> <user> <pass> <lenh> [tham so...]\n");
        wprintf(L"\n");
        wprintf(L"VD 1: step4.exe 192.168.1.100 Administrator P@ss whoami\n");
        wprintf(L"VD 2: step4.exe 192.168.1.100 Administrator P@ss ipconfig /all\n");
        wprintf(L"VD 3: step4.exe 192.168.1.100 Administrator P@ss dir C:\\Users\n");
        return 1;
    }

    LPCWSTR ip = argv[1];
    LPCWSTR user = argv[2];
    LPCWSTR pass = argv[3];

    // Ghép argv[4], argv[5], ... thành 1 chuỗi lệnh
    // VD: argv[4]="ipconfig" argv[5]="/all" → "ipconfig /all"
    WCHAR cmd[2048] = {};
    for (int i = 4; i < argc; i++) {
        if (i > 4)
            StringCchCatW(cmd, ARRAYSIZE(cmd), L" ");
        StringCchCatW(cmd, ARRAYSIZE(cmd), argv[i]);
    }

    ModeSingle(ip, user, pass, cmd);
    return 0;
}