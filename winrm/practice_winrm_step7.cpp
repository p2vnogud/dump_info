// winrm_exec.cpp — Final version
// Gom Single + Shell + Batch vào 1 file
//
// Compile:
//   cl /EHsc /DUNICODE /D_UNICODE winrm_exec.cpp Wsmsvc.lib ws2_32.lib /Fe:winrm_exec.exe
//
// Chạy:
//   winrm_exec.exe single 192.168.1.100 Administrator P@ss "ipconfig"
//   winrm_exec.exe shell  192.168.1.100 Administrator P@ss
//   winrm_exec.exe batch  192.168.1 1 50 Administrator P@ss "hostname"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WSMAN_API_VERSION_1_1
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <winsock2.h>
#include <wsman.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>

#pragma comment(lib, "Wsmsvc.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Strsafe.lib")

// ═════════════════════════════════════════════════════════════
// PHẦN 1 — Cấu hình + Structs
// ═════════════════════════════════════════════════════════════
#define WINRM_PORT      5985
#define MAX_HISTORY     20
#define TIMEOUT_SHELL   15000
#define TIMEOUT_CMD     30000
#define MAX_RECONNECT   3

// Màu console
#define COLOR_NORMAL    0x0007
#define COLOR_GREEN     0x000A
#define COLOR_YELLOW    0x000E
#define COLOR_CYAN      0x000B
#define COLOR_RED       0x000C
#define COLOR_GRAY      0x0008

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

typedef struct {
    WSMAN_API_HANDLE     hAPI;
    WSMAN_SESSION_HANDLE hSession;
    LPCWSTR              ip;
    LPCWSTR              user;
    LPCWSTR              pass;
} SESSION;

typedef struct {
    WCHAR  ip[64];
    BOOL   online;
    BOOL   success;
    DWORD  exitCode;
    char* output;
    DWORD  outputLen;
    DWORD  elapsedMs;
} BATCH_RESULT;

typedef struct {
    WCHAR  hostname[64];
    WCHAR  cwd[512];
    WCHAR  history[MAX_HISTORY][512];
    int    historyCount;
    int    historyPos;
    int    cmdCount;
    DWORD  lastExitCode;
} SHELL_STATE;

// ═════════════════════════════════════════════════════════════
// PHẦN 2 — Helpers
// ═════════════════════════════════════════════════════════════
static void SetColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

static void PrintError(LPCWSTR where, HRESULT hr)
{
    WCHAR msg[256] = {};
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, (DWORD)hr, 0, msg, ARRAYSIZE(msg), NULL);
    SetColor(COLOR_RED);
    fwprintf(stderr, L"[!] %s: 0x%08X — %s\n", where, (UINT)hr, msg);
    SetColor(COLOR_NORMAL);
}

static void PrintBytes(const char* buf, DWORD cb)
{
    if (!buf || !cb) return;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD w = 0;
    if (!WriteConsoleA(h, buf, cb, &w, NULL) || !w)
        fwrite(buf, 1, cb, stdout);
}

static void TrimOutput(char* buf, DWORD* pLen)
{
    if (!buf || !*pLen) return;
    DWORD start = 0;
    while (start < *pLen &&
        (buf[start] == '\r' || buf[start] == '\n' || buf[start] == ' '))
        start++;
    DWORD end = *pLen;
    while (end > start &&
        (buf[end - 1] == '\r' || buf[end - 1] == '\n' || buf[end - 1] == ' '))
        end--;
    DWORD newLen = end - start;
    memmove(buf, buf + start, newLen);
    buf[newLen] = '\0';
    *pLen = newLen;
}

// ═════════════════════════════════════════════════════════════
// PHẦN 3 — Callbacks
// ═════════════════════════════════════════════════════════════
void CALLBACK OnShellCreated(
    PVOID pCtx, DWORD, WSMAN_ERROR* pErr,
    WSMAN_SHELL_HANDLE hShell,
    WSMAN_COMMAND_HANDLE, WSMAN_OPERATION_HANDLE, WSMAN_RESPONSE_DATA*)
{
    CTX* c = (CTX*)pCtx;
    c->hr = (pErr && pErr->code) ? HRESULT_FROM_WIN32(pErr->code) : S_OK;
    if (SUCCEEDED(c->hr)) c->hShell = hShell;
    SetEvent(c->hEvent);
}

void CALLBACK OnCommandSent(
    PVOID pCtx, DWORD, WSMAN_ERROR* pErr,
    WSMAN_SHELL_HANDLE, WSMAN_COMMAND_HANDLE hCommand,
    WSMAN_OPERATION_HANDLE, WSMAN_RESPONSE_DATA*)
{
    CTX* c = (CTX*)pCtx;
    c->hr = (pErr && pErr->code) ? HRESULT_FROM_WIN32(pErr->code) : S_OK;
    if (SUCCEEDED(c->hr)) c->hCommand = hCommand;
    SetEvent(c->hEvent);
}

void CALLBACK OnChunkReceived(
    PVOID pCtx, DWORD flags, WSMAN_ERROR* pErr,
    WSMAN_SHELL_HANDLE, WSMAN_COMMAND_HANDLE,
    WSMAN_OPERATION_HANDLE, WSMAN_RESPONSE_DATA* pData)
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
            wcscmp(r->commandState, WSMAN_COMMAND_STATE_DONE) == 0) {
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
// PHẦN 4 — Engine (ReceiveLoop + Session + RunCmd)
// ═════════════════════════════════════════════════════════════
static HRESULT ReceiveLoop(CTX* ctx)
{
    PCWSTR streamNames[2] = { L"stdout", L"stderr" };
    WSMAN_STREAM_ID_SET streams = { 2, streamNames };

    while (!ctx->bCmdDone) {
        if (ctx->pChunk) { free(ctx->pChunk); ctx->pChunk = NULL; ctx->cbChunk = 0; }
        ResetEvent(ctx->hEvent);

        WSMAN_SHELL_ASYNC a = { ctx, OnChunkReceived };
        WSMAN_OPERATION_HANDLE hOp = NULL;
        WSManReceiveShellOutput(ctx->hShell, ctx->hCommand,
            0, &streams, &a, &hOp);

        DWORD w = WaitForSingleObject(ctx->hEvent, TIMEOUT_CMD);
        if (hOp) { WSManCloseOperation(hOp, 0); hOp = NULL; }

        if (w == WAIT_TIMEOUT) { wprintf(L"\n[!] Timeout\n"); break; }
        if (ctx->hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) break;
        if (FAILED(ctx->hr)) { PrintError(L"ReceiveLoop", ctx->hr); return ctx->hr; }
        if (ctx->pChunk && ctx->cbChunk > 0)
            PrintBytes(ctx->pChunk, ctx->cbChunk);
    }
    return S_OK;
}

static HRESULT SessionOpen(SESSION* s)
{
    s->hAPI = NULL; s->hSession = NULL;

    HRESULT hr = WSManInitialize(WSMAN_FLAG_REQUESTED_API_VERSION_1_1, &s->hAPI);
    if (FAILED(hr)) { PrintError(L"WSManInitialize", hr); return hr; }

    WSMAN_USERNAME_PASSWORD_CREDS creds = { s->user, s->pass };
    WSMAN_AUTHENTICATION_CREDENTIALS auth = {};
    auth.authenticationMechanism = WSMAN_FLAG_AUTH_NEGOTIATE;
    auth.userAccount = creds;

    WCHAR endpoint[256];
    StringCchPrintfW(endpoint, ARRAYSIZE(endpoint),
        L"http://%s:%d/wsman", s->ip, WINRM_PORT);

    hr = WSManCreateSession(s->hAPI, endpoint, 0, &auth, NULL, &s->hSession);
    if (FAILED(hr)) { PrintError(L"WSManCreateSession", hr); return hr; }

    WSMAN_DATA opt = { WSMAN_DATA_TYPE_DWORD };
    opt.number = 1;
    WSManSetSessionOption(s->hSession, (WSManSessionOption)3, &opt);
    return S_OK;
}

static void SessionClose(SESSION* s)
{
    if (s->hSession) { WSManCloseSession(s->hSession, 0); s->hSession = NULL; }
    if (s->hAPI) { WSManDeinitialize(s->hAPI, 0);     s->hAPI = NULL; }
}

static HRESULT RunCmd(SESSION* s, LPCWSTR cmd,
    DWORD* pExitCode,
    char** ppOutBuf, DWORD* pOutLen)
{
    HRESULT hr = S_OK;
    CTX ctx = {};
    ctx.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ctx.hEvent) return E_OUTOFMEMORY;

    // Shell
    {
        WSMAN_SHELL_ASYNC a = { &ctx, OnShellCreated };
        WSMAN_SHELL_HANDLE hShell = NULL;
        WSManCreateShell(s->hSession, 0,
            L"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
            NULL, NULL, NULL, &a, &hShell);
        if (WaitForSingleObject(ctx.hEvent, TIMEOUT_SHELL) == WAIT_TIMEOUT) {
            hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT); goto cleanup;
        }
        if (FAILED(ctx.hr)) { hr = ctx.hr; goto cleanup; }
    }

    // Command
    ResetEvent(ctx.hEvent);
    {
        WSMAN_SHELL_ASYNC a = { &ctx, OnCommandSent };
        WSMAN_COMMAND_HANDLE hCmd = NULL;
        WSManRunShellCommand(ctx.hShell, 0, cmd, NULL, NULL, &a, &hCmd);
        if (WaitForSingleObject(ctx.hEvent, TIMEOUT_SHELL) == WAIT_TIMEOUT) {
            hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT); goto cleanup;
        }
        if (FAILED(ctx.hr)) { hr = ctx.hr; goto cleanup; }
    }

    // Receive
    // Nếu ppOutBuf != NULL → tắt in console, chỉ lưu vào buffer
    if (ppOutBuf) {
        // Receive silent — lưu vào ctx, không in
        PCWSTR streamNames[2] = { L"stdout", L"stderr" };
        WSMAN_STREAM_ID_SET streams = { 2, streamNames };

        while (!ctx.bCmdDone) {
            if (ctx.pChunk) { free(ctx.pChunk); ctx.pChunk = NULL; ctx.cbChunk = 0; }
            ResetEvent(ctx.hEvent);
            WSMAN_SHELL_ASYNC a = { &ctx, OnChunkReceived };
            WSMAN_OPERATION_HANDLE hOp = NULL;
            WSManReceiveShellOutput(ctx.hShell, ctx.hCommand,
                0, &streams, &a, &hOp);
            DWORD w = WaitForSingleObject(ctx.hEvent, TIMEOUT_CMD);
            if (hOp) { WSManCloseOperation(hOp, 0); hOp = NULL; }
            if (w == WAIT_TIMEOUT) break;
            if (ctx.hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) break;
            if (FAILED(ctx.hr)) { hr = ctx.hr; break; }
        }

        if (ctx.pChunk && ctx.cbChunk > 0) {
            *ppOutBuf = ctx.pChunk;
            *pOutLen = ctx.cbChunk;
            ctx.pChunk = NULL;
        }
    }
    else {
        hr = ReceiveLoop(&ctx);
    }

    if (pExitCode) *pExitCode = ctx.exitCode;

cleanup:
    if (ctx.pChunk)   free(ctx.pChunk);
    if (ctx.hCommand) WSManCloseCommand(ctx.hCommand, 0, NULL);
    if (ctx.hShell)   WSManCloseShell(ctx.hShell, 0, NULL);
    if (ctx.hEvent)   CloseHandle(ctx.hEvent);
    return hr;
}

// ═════════════════════════════════════════════════════════════
// PHẦN 5 — ModeSingle
// ═════════════════════════════════════════════════════════════
static void ModeSingle(LPCWSTR ip, LPCWSTR user,
    LPCWSTR pass, LPCWSTR cmd)
{
    SetColor(COLOR_CYAN);
    wprintf(L"\n╔══════════════════════════════════════════╗\n");
    wprintf(L"║  [SINGLE]                                ║\n");
    wprintf(L"║  TARGET : %-30s║\n", ip);
    wprintf(L"║  CMD    : %-30s║\n", cmd);
    wprintf(L"╚══════════════════════════════════════════╝\n\n");
    SetColor(COLOR_NORMAL);

    //SESSION s = { .ip = ip, .user = user, .pass = pass };
    SESSION s = {};
    s.ip = ip;
    s.user = user;
    s.pass = pass;

    HRESULT hr = SessionOpen(&s);
    if (FAILED(hr)) return;

    SetColor(COLOR_YELLOW);
    wprintf(L"──────────── OUTPUT ────────────\n");
    SetColor(COLOR_NORMAL);

    DWORD exitCode = 0;
    hr = RunCmd(&s, cmd, &exitCode, NULL, NULL);

    SetColor(COLOR_YELLOW);
    wprintf(L"────────────────────────────────\n");
    SetColor(COLOR_NORMAL);

    if (SUCCEEDED(hr)) {
        SetColor(exitCode == 0 ? COLOR_GREEN : COLOR_RED);
        wprintf(L"[+] ExitCode: %lu\n", exitCode);
        SetColor(COLOR_NORMAL);
    }

    SessionClose(&s);
}

// ═════════════════════════════════════════════════════════════
// PHẦN 6 — ModeShell
// ═════════════════════════════════════════════════════════════

// ── History ──────────────────────────────────────────────────
static void HistoryAdd(SHELL_STATE* st, LPCWSTR cmd)
{
    if (!cmd || !cmd[0]) return;
    if (st->historyCount > 0 &&
        wcscmp(st->history[st->historyCount - 1], cmd) == 0) return;

    if (st->historyCount < MAX_HISTORY) {
        StringCchCopyW(st->history[st->historyCount++], 512, cmd);
    }
    else {
        for (int i = 0; i < MAX_HISTORY - 1; i++)
            StringCchCopyW(st->history[i], 512, st->history[i + 1]);
        StringCchCopyW(st->history[MAX_HISTORY - 1], 512, cmd);
    }
    st->historyPos = st->historyCount;
}

// ── ReadLine với History ──────────────────────────────────────
static BOOL ReadLineWithHistory(SHELL_STATE* st,
    WCHAR* buf, int maxLen)
{
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD oldMode;
    GetConsoleMode(hIn, &oldMode);
    SetConsoleMode(hIn, ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT);

    int  len = 0, cursor = 0;
    BOOL done = FALSE, eof = FALSE;
    ZeroMemory(buf, maxLen * sizeof(WCHAR));

    auto Redraw = [&]() {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hOut, &csbi);
        COORD pos = { 0, csbi.dwCursorPosition.Y };
        SetConsoleCursorPosition(hOut, pos);
        DWORD w;
        FillConsoleOutputCharacterW(hOut, L' ', csbi.dwSize.X, pos, &w);
        SetConsoleCursorPosition(hOut, pos);

        // Reprint prompt
        SetColor(COLOR_YELLOW);
        wprintf(L"[%d] ", st->cmdCount + 1);
        SetColor(COLOR_CYAN);
        wprintf(L"%s", st->hostname);
        SetColor(COLOR_NORMAL);
        wprintf(L" | ");
        SetColor(COLOR_GREEN);
        wprintf(L"%s", st->cwd[0] ? st->cwd : L"?");
        SetColor(COLOR_NORMAL);
        wprintf(L"> ");

        WriteConsoleW(hOut, buf, len, &w, NULL);
        GetConsoleScreenBufferInfo(hOut, &csbi);
        COORD cur = csbi.dwCursorPosition;
        cur.X = (SHORT)(cur.X - (len - cursor));
        SetConsoleCursorPosition(hOut, cur);
        };

    while (!done) {
        INPUT_RECORD rec; DWORD nRead;
        ReadConsoleInputW(hIn, &rec, 1, &nRead);
        if (rec.EventType != KEY_EVENT || !rec.Event.KeyEvent.bKeyDown)
            continue;

        WORD  vk = rec.Event.KeyEvent.wVirtualKeyCode;
        WCHAR ch = rec.Event.KeyEvent.uChar.UnicodeChar;

        if (vk == VK_RETURN) { buf[len] = L'\0'; wprintf(L"\n"); done = TRUE; }
        else if (vk == VK_BACK && cursor > 0) {
            memmove(buf + cursor - 1, buf + cursor, (len - cursor) * sizeof(WCHAR));
            cursor--; len--; buf[len] = L'\0'; Redraw();
        }
        else if (vk == VK_DELETE && cursor < len) {
            memmove(buf + cursor, buf + cursor + 1, (len - cursor - 1) * sizeof(WCHAR));
            len--; buf[len] = L'\0'; Redraw();
        }
        else if (vk == VK_LEFT && cursor > 0) { cursor--; Redraw(); }
        else if (vk == VK_RIGHT && cursor < len) { cursor++; Redraw(); }
        else if (vk == VK_HOME) { cursor = 0;   Redraw(); }
        else if (vk == VK_END) { cursor = len; Redraw(); }
        else if (vk == VK_UP && st->historyPos > 0) {
            st->historyPos--;
            StringCchCopyW(buf, maxLen, st->history[st->historyPos]);
            len = cursor = (int)wcslen(buf); Redraw();
        }
        else if (vk == VK_DOWN) {
            if (st->historyPos < st->historyCount - 1) {
                st->historyPos++;
                StringCchCopyW(buf, maxLen, st->history[st->historyPos]);
                len = cursor = (int)wcslen(buf);
            }
            else {
                st->historyPos = st->historyCount;
                ZeroMemory(buf, maxLen * sizeof(WCHAR));
                len = cursor = 0;
            }
            Redraw();
        }
        else if (vk == VK_ESCAPE) { ZeroMemory(buf, maxLen * sizeof(WCHAR)); len = cursor = 0; Redraw(); }
        else if (ch == 0x03) { eof = TRUE; done = TRUE; }
        else if (ch >= 0x20 && len < maxLen - 1) {
            memmove(buf + cursor + 1, buf + cursor, (len - cursor) * sizeof(WCHAR));
            buf[cursor++] = ch; len++; buf[len] = L'\0'; Redraw();
        }
    }

    SetConsoleMode(hIn, oldMode);
    return !eof;
}

// ── GetCwd ────────────────────────────────────────────────────
static void GetCwd(SESSION* s, SHELL_STATE* st)
{
    char* buf = NULL; DWORD len = 0;
    if (SUCCEEDED(RunCmd(s, L"cd", NULL, &buf, &len)) && buf) {
        WCHAR wide[512] = {};
        MultiByteToWideChar(CP_OEMCP, 0, buf, len, wide, ARRAYSIZE(wide));
        for (int i = (int)wcslen(wide) - 1; i >= 0; i--) {
            if (wide[i] == L'\r' || wide[i] == L'\n') wide[i] = L'\0'; else break;
        }
        StringCchCopyW(st->cwd, ARRAYSIZE(st->cwd), wide);
        free(buf);
    }
}

// ── PrintPrompt ───────────────────────────────────────────────
static void PrintPrompt(const SHELL_STATE* st)
{
    SetColor(COLOR_YELLOW); wprintf(L"[%d] ", st->cmdCount + 1);
    SetColor(COLOR_CYAN);   wprintf(L"%s", st->hostname);
    SetColor(COLOR_NORMAL); wprintf(L" | ");
    SetColor(COLOR_GREEN);  wprintf(L"%s", st->cwd[0] ? st->cwd : L"?");
    SetColor(COLOR_NORMAL); wprintf(L"> ");
}

// ── Builtin commands ──────────────────────────────────────────
static BOOL HandleBuiltin(LPCWSTR cmd, SHELL_STATE* st, BOOL* pExit)
{
    *pExit = FALSE;
    if (_wcsicmp(cmd, L"exit") == 0 || _wcsicmp(cmd, L"quit") == 0) { *pExit = TRUE; return TRUE; }
    if (_wcsicmp(cmd, L"clear") == 0 || _wcsicmp(cmd, L"cls") == 0) { system("cls"); return TRUE; }
    if (_wcsicmp(cmd, L"history") == 0) {
        SetColor(COLOR_YELLOW); wprintf(L"\n  Lich su lenh:\n"); SetColor(COLOR_NORMAL);
        for (int i = 0; i < st->historyCount; i++)
            wprintf(L"  %3d  %s\n", i + 1, st->history[i]);
        wprintf(L"\n");
        return TRUE;
    }
    if (_wcsicmp(cmd, L"help") == 0) {
        SetColor(COLOR_CYAN);
        wprintf(L"\n  ┌──────────────────────────────────────────┐\n");
        wprintf(L"  │  Lenh dac biet                           │\n");
        wprintf(L"  ├──────────────────────────────────────────┤\n");
        wprintf(L"  │  help      in trang nay                  │\n");
        wprintf(L"  │  history   xem lich su lenh              │\n");
        wprintf(L"  │  clear     xoa man hinh                  │\n");
        wprintf(L"  │  exit      thoat shell                   │\n");
        wprintf(L"  ├──────────────────────────────────────────┤\n");
        wprintf(L"  │  ↑ ↓   duyet history  │  Esc  xoa dong  │\n");
        wprintf(L"  │  ← →   di chuyen      │  Del  xoa char  │\n");
        wprintf(L"  │  Ctrl+C  thoat                           │\n");
        wprintf(L"  └──────────────────────────────────────────┘\n\n");
        SetColor(COLOR_NORMAL);
        return TRUE;
    }
    return FALSE;
}

// ── TryReconnect ──────────────────────────────────────────────
static BOOL TryReconnect(SESSION* s)
{
    SessionClose(s);
    for (int i = 1; i <= MAX_RECONNECT; i++) {
        SetColor(COLOR_YELLOW);
        wprintf(L"\n[*] Reconnect %d/%d...\n", i, MAX_RECONNECT);
        SetColor(COLOR_NORMAL);
        Sleep(1000 * i);
        if (SUCCEEDED(SessionOpen(s))) {
            SetColor(COLOR_GREEN); wprintf(L"[+] OK!\n\n"); SetColor(COLOR_NORMAL);
            return TRUE;
        }
    }
    return FALSE;
}

// ── ModeShell ─────────────────────────────────────────────────
static void ModeShell(LPCWSTR ip, LPCWSTR user, LPCWSTR pass)
{
    //SESSION s = { .ip = ip, .user = user, .pass = pass };
    SESSION s = {};
    s.ip = ip;
    s.user = user;
    s.pass = pass;


    SetColor(COLOR_CYAN);
    wprintf(L"\n[*] Dang ket noi %s...\n", ip);
    SetColor(COLOR_NORMAL);

    if (FAILED(SessionOpen(&s))) return;

    SHELL_STATE st = {};

    // Lấy hostname
    {
        char* b = NULL; DWORD l = 0;
        if (SUCCEEDED(RunCmd(&s, L"hostname", NULL, &b, &l)) && b) {
            WCHAR w[64] = {};
            MultiByteToWideChar(CP_OEMCP, 0, b, l, w, ARRAYSIZE(w));
            for (int i = (int)wcslen(w) - 1; i >= 0; i--) { if (w[i] == L'\r' || w[i] == L'\n')w[i] = L'\0'; else break; }
            StringCchCopyW(st.hostname, ARRAYSIZE(st.hostname), w);
            free(b);
        }
    }
    if (!st.hostname[0]) StringCchCopyW(st.hostname, ARRAYSIZE(st.hostname), ip);
    GetCwd(&s, &st);

    SetColor(COLOR_CYAN);
    wprintf(L"\n╔══════════════════════════════════════════════════╗\n");
    wprintf(L"║  [SHELL]  %-38s║\n", st.hostname);
    wprintf(L"║  'help' = lenh dac biet  |  'exit' = thoat      ║\n");
    wprintf(L"╚══════════════════════════════════════════════════╝\n\n");
    SetColor(COLOR_NORMAL);

    WCHAR cmdBuf[512];
    while (TRUE) {
        PrintPrompt(&st);
        if (!ReadLineWithHistory(&st, cmdBuf, ARRAYSIZE(cmdBuf))) break;
        if (!cmdBuf[0]) continue;

        HistoryAdd(&st, cmdBuf);

        BOOL shouldExit = FALSE;
        if (HandleBuiltin(cmdBuf, &st, &shouldExit)) {
            if (shouldExit) break;
            continue;
        }

        wprintf(L"\n");
        DWORD exitCode = 0;
        ULONGLONG t0 = GetTickCount64();
        HRESULT hr = RunCmd(&s, cmdBuf, &exitCode, NULL, NULL);
        ULONGLONG ms = GetTickCount64() - t0;

        if (FAILED(hr)) {
            SetColor(COLOR_RED);
            wprintf(L"\n[!] Loi: 0x%08X\n", (UINT)hr);
            SetColor(COLOR_NORMAL);
            if (!TryReconnect(&s)) { wprintf(L"[!] Thoat.\n"); break; }
            GetCwd(&s, &st);
            continue;
        }

        st.cmdCount++;
        st.lastExitCode = exitCode;
        if (_wcsnicmp(cmdBuf, L"cd", 2) == 0) GetCwd(&s, &st);

        wprintf(L"\n");
        SetColor(exitCode == 0 ? COLOR_GREEN : COLOR_RED);
        wprintf(L"  [exit:%lu | %llums]", exitCode, ms);
        SetColor(COLOR_NORMAL);
        wprintf(L"\n\n");
    }

    SetColor(COLOR_YELLOW);
    wprintf(L"\n[*] Thoat. Tam biet!\n");
    SetColor(COLOR_NORMAL);
    SessionClose(&s);
}

// ═════════════════════════════════════════════════════════════
// PHẦN 7 — ModeBatch
// ═════════════════════════════════════════════════════════════
static BOOL PingHost(LPCWSTR ip, int port)
{
    static BOOL wsStarted = FALSE;
    if (!wsStarted) { WSADATA wd; WSAStartup(MAKEWORD(2, 2), &wd); wsStarted = TRUE; }

    char ipA[64] = {};
    WideCharToMultiByte(CP_ACP, 0, ip, -1, ipA, sizeof(ipA), NULL, NULL);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return FALSE;

    u_long nb = 1; ioctlsocket(sock, FIONBIO, &nb);

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    addr.sin_addr.s_addr = inet_addr(ipA);
    connect(sock, (sockaddr*)&addr, sizeof(addr));

    fd_set fds; FD_ZERO(&fds); FD_SET(sock, &fds);
    timeval tv = { 0,800000 };
    BOOL ok = (select(0, NULL, &fds, NULL, &tv) > 0);
    closesocket(sock);
    return ok;
}

static void PrintBatchProgress(const BATCH_RESULT* r, int idx, int total)
{
    int bw = 20, filled = (idx * bw) / total;
    SetColor(COLOR_YELLOW); wprintf(L"  [");
    SetColor(COLOR_GREEN);  for (int i = 0; i < filled; i++) wprintf(L"=");
    SetColor(COLOR_NORMAL); for (int i = filled; i < bw; i++) wprintf(L" ");
    SetColor(COLOR_YELLOW); wprintf(L"] %d/%d  ", idx, total);
    SetColor(COLOR_NORMAL); wprintf(L"%-18s ", r->ip);

    if (!r->online) { SetColor(COLOR_GRAY); wprintf(L"[offline]\n"); SetColor(COLOR_NORMAL); return; }
    if (!r->success) { SetColor(COLOR_RED);  wprintf(L"[FAIL]\n");    SetColor(COLOR_NORMAL); return; }

    SetColor(COLOR_GREEN); wprintf(L"[OK] "); SetColor(COLOR_NORMAL);
    if (r->output && r->outputLen > 0) {
        char line[128] = {}; DWORD n = 0;
        for (DWORD i = 0; i < r->outputLen && i < 127; i++) {
            if (r->output[i] == '\r' || r->output[i] == '\n') break;
            line[n++] = r->output[i];
        }
        if (n) printf("%s", line);
    }
    SetColor(COLOR_GRAY); wprintf(L"  (%lums)\n", r->elapsedMs);
    SetColor(COLOR_NORMAL);
}

static void PrintBatchSummary(BATCH_RESULT* results, int count, LPCWSTR cmd)
{
    int nOnline = 0, nOK = 0, nFail = 0; DWORD ms = 0;
    for (int i = 0; i < count; i++) {
        if (!results[i].online) continue;
        nOnline++;
        if (results[i].success) { nOK++; ms += results[i].elapsedMs; }
        else nFail++;
    }

    SetColor(COLOR_CYAN);
    wprintf(L"\n╔══════════════════════════════════════════════════╗\n");
    wprintf(L"║                  BATCH SUMMARY                  ║\n");
    wprintf(L"╠══════════════════════════════════════════════════╣\n");
    SetColor(COLOR_NORMAL);
    wprintf(L"║  CMD      : %-36s║\n", cmd);
    wprintf(L"║  Quet     : %-3d may                             ║\n", count);
    SetColor(COLOR_GREEN);
    wprintf(L"║  Online   : %-3d may co WinRM                    ║\n", nOnline);
    SetColor(COLOR_NORMAL);
    wprintf(L"║  Thanh cong: %-3d                                ║\n", nOK);
    if (nFail > 0) { SetColor(COLOR_RED); wprintf(L"║  That bai : %-3d                                ║\n", nFail); SetColor(COLOR_NORMAL); }
    wprintf(L"║  TB       : %lums/may                            ║\n", nOK > 0 ? ms / nOK : 0);
    SetColor(COLOR_CYAN);
    wprintf(L"╚══════════════════════════════════════════════════╝\n\n");
    SetColor(COLOR_NORMAL);

    if (nOK > 0) {
        SetColor(COLOR_YELLOW); wprintf(L"  ── Chi tiet ──\n\n"); SetColor(COLOR_NORMAL);
        for (int i = 0; i < count; i++) {
            if (!results[i].success) continue;
            SetColor(COLOR_CYAN); wprintf(L"  [%s]\n", results[i].ip); SetColor(COLOR_NORMAL);
            if (results[i].output) {
                TrimOutput(results[i].output, &results[i].outputLen);
                PrintBytes(results[i].output, results[i].outputLen);
                wprintf(L"\n");
            }
        }
    }
}

static void ModeBatch(LPCWSTR subnet, int start, int end,
    LPCWSTR user, LPCWSTR pass, LPCWSTR cmd)
{
    int total = end - start + 1;
    BATCH_RESULT* results = (BATCH_RESULT*)calloc(total, sizeof(BATCH_RESULT));
    if (!results) return;

    SetColor(COLOR_CYAN);
    wprintf(L"\n╔══════════════════════════════════════════════════╗\n");
    wprintf(L"║  [BATCH]  %s.%d → %d\n", subnet, start, end);
    wprintf(L"║  CMD : %s\n", cmd);
    wprintf(L"╚══════════════════════════════════════════════════╝\n\n");
    SetColor(COLOR_NORMAL);

    for (int i = start; i <= end; i++) {
        int idx = i - start;
        WCHAR ip[64];
        StringCchPrintfW(ip, ARRAYSIZE(ip), L"%s.%d", subnet, i);
        StringCchCopyW(results[idx].ip, ARRAYSIZE(results[idx].ip), ip);

        wprintf(L"  %-18s ", ip);
        SetColor(COLOR_GRAY); wprintf(L"checking...\r"); SetColor(COLOR_NORMAL);

        results[idx].online = PingHost(ip, WINRM_PORT);

        if (!results[idx].online) {
            PrintBatchProgress(&results[idx], idx + 1, total);
            continue;
        }

        //SESSION s = { .ip = ip, .user = user, .pass = pass };
        SESSION s = {};
        s.ip = ip;
        s.user = user;
        s.pass = pass;

        ULONGLONG t0 = GetTickCount64();
        HRESULT hr = SessionOpen(&s);
        if (SUCCEEDED(hr)) {
            hr = RunCmd(&s, cmd, &results[idx].exitCode,
                &results[idx].output, &results[idx].outputLen);
            results[idx].success = SUCCEEDED(hr);
            SessionClose(&s);
        }
        results[idx].elapsedMs = (DWORD)(GetTickCount64() - t0);

        PrintBatchProgress(&results[idx], idx + 1, total);
    }

    PrintBatchSummary(results, total, cmd);

    for (int i = 0; i < total; i++) if (results[i].output) free(results[i].output);
    free(results);
}

// ═════════════════════════════════════════════════════════════
// PHẦN 8 — Usage + wmain
// ═════════════════════════════════════════════════════════════
static void Usage(LPCWSTR exe)
{
    SetColor(COLOR_CYAN);
    wprintf(L"\n  WinRM Remote Exec\n\n");
    SetColor(COLOR_YELLOW);
    wprintf(L"  Che do:\n\n");
    SetColor(COLOR_NORMAL);
    wprintf(L"  %-8s %s single <IP> <user> <pass> <lenh>\n", L"[1-shot]", exe);
    wprintf(L"  %-8s %s shell  <IP> <user> <pass>\n", L"[REPL]", exe);
    wprintf(L"  %-8s %s batch  <subnet> <start> <end> <user> <pass> <lenh>\n\n", L"[multi]", exe);
    SetColor(COLOR_GREEN);
    wprintf(L"  Vi du:\n");
    SetColor(COLOR_NORMAL);
    wprintf(L"    %s single 192.168.1.100 Administrator P@ss \"ipconfig /all\"\n", exe);
    wprintf(L"    %s shell  192.168.1.100 Administrator P@ss\n", exe);
    wprintf(L"    %s batch  192.168.1 1 50 Administrator P@ss \"hostname\"\n\n", exe);
}

int wmain(int argc, WCHAR* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    if (argc < 2) { Usage(argv[0]); return 1; }

    // ── single ────────────────────────────────────────────────
    if (_wcsicmp(argv[1], L"single") == 0)
    {
        if (argc < 6) {
            wprintf(L"Thieu tham so: single <IP> <user> <pass> <lenh>\n");
            return 1;
        }
        // Ghép lệnh từ argv[5] trở đi (hỗ trợ space)
        WCHAR cmd[2048] = {};
        for (int i = 5; i < argc; i++) {
            if (i > 5) StringCchCatW(cmd, ARRAYSIZE(cmd), L" ");
            StringCchCatW(cmd, ARRAYSIZE(cmd), argv[i]);
        }
        ModeSingle(argv[2], argv[3], argv[4], cmd);
    }
    // ── shell ─────────────────────────────────────────────────
    else if (_wcsicmp(argv[1], L"shell") == 0)
    {
        if (argc < 5) {
            wprintf(L"Thieu tham so: shell <IP> <user> <pass>\n");
            return 1;
        }
        ModeShell(argv[2], argv[3], argv[4]);
    }
    // ── batch ─────────────────────────────────────────────────
    else if (_wcsicmp(argv[1], L"batch") == 0)
    {
        if (argc < 8) {
            wprintf(L"Thieu tham so: batch <subnet> <start> <end> <user> <pass> <lenh>\n");
            return 1;
        }
        // Validate số
        int start = _wtoi(argv[3]);
        int end = _wtoi(argv[4]);
        if (start < 1 || end>254 || start > end) {
            wprintf(L"[!] Range khong hop le (1-254, start <= end)\n");
            return 1;
        }
        // Ghép lệnh từ argv[7] trở đi
        WCHAR cmd[2048] = {};
        for (int i = 7; i < argc; i++) {
            if (i > 7) StringCchCatW(cmd, ARRAYSIZE(cmd), L" ");
            StringCchCatW(cmd, ARRAYSIZE(cmd), argv[i]);
        }
        ModeBatch(argv[2], start, end, argv[5], argv[6], cmd);
    }
    else {
        SetColor(COLOR_RED);
        wprintf(L"[!] Che do khong hop le: '%s'\n", argv[1]);
        SetColor(COLOR_NORMAL);
        Usage(argv[0]);
        return 1;
    }

    return 0;
}