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
// BƯỚC 8 — PHẦN 1: Logger
// Ghi log song song ra file trong khi vẫn in ra console
// ═════════════════════════════════════════════════════════════

typedef struct {
    HANDLE  hFile;       // file handle
    BOOL    enabled;     // có đang ghi log không
    WCHAR   path[260];   // đường dẫn file log
    HANDLE  hMutex;      // mutex tránh 2 thread ghi cùng lúc
} LOGGER;

// Logger toàn cục — dùng chung cho mọi chế độ
static LOGGER g_log = {};

// Khởi tạo logger — tạo file log với tên theo thời gian
static BOOL LogInit(LPCWSTR prefix)
{
    SYSTEMTIME st;
    GetLocalTime(&st);

    // Tên file: prefix_YYYYMMDD_HHMMSS.txt
    // VD: winrm_20240115_143022.txt
    StringCchPrintfW(g_log.path, ARRAYSIZE(g_log.path),
        L"%s_%04d%02d%02d_%02d%02d%02d.txt",
        prefix,
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    g_log.hFile = CreateFileW(
        g_log.path,
        GENERIC_WRITE,
        FILE_SHARE_READ,   // cho phép đọc trong khi ghi
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (g_log.hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] Khong the tao file log: %s\n", g_log.path);
        return FALSE;
    }

    // Viết BOM UTF-8 để mở đúng encoding trong Notepad
    BYTE bom[] = { 0xEF, 0xBB, 0xBF };
    DWORD written;
    WriteFile(g_log.hFile, bom, sizeof(bom), &written, NULL);

    g_log.hMutex = CreateMutexW(NULL, FALSE, NULL);
    g_log.enabled = TRUE;

    SetColor(COLOR_GREEN);
    wprintf(L"[+] Log file: %s\n", g_log.path);
    SetColor(COLOR_NORMAL);
    return TRUE;
}

static void LogClose()
{
    if (!g_log.enabled) return;
    if (g_log.hFile && g_log.hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_log.hFile);
        g_log.hFile = NULL;
    }
    if (g_log.hMutex) {
        CloseHandle(g_log.hMutex);
        g_log.hMutex = NULL;
    }
    g_log.enabled = FALSE;
}

// Ghi 1 dòng log với timestamp
// Format: [HH:MM:SS] message
static void LogWrite(LPCWSTR fmt, ...)
{
    if (!g_log.enabled) return;

    // Lấy timestamp
    SYSTEMTIME st;
    GetLocalTime(&st);

    WCHAR line[2048];
    StringCchPrintfW(line, ARRAYSIZE(line),
        L"[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);

    // Format message
    WCHAR msg[1024];
    va_list args;
    va_start(args, fmt);
    StringCchVPrintfW(msg, ARRAYSIZE(msg), fmt, args);
    va_end(args);
    StringCchCatW(line, ARRAYSIZE(line), msg);
    StringCchCatW(line, ARRAYSIZE(line), L"\r\n");

    // Convert sang UTF-8 để ghi file
    char utf8[4096];
    int  utf8Len = WideCharToMultiByte(CP_UTF8, 0,
        line, -1, utf8, sizeof(utf8), NULL, NULL);

    // Lock mutex trước khi ghi (thread-safe)
    WaitForSingleObject(g_log.hMutex, INFINITE);
    DWORD written;
    WriteFile(g_log.hFile, utf8, utf8Len - 1, &written, NULL);
    ReleaseMutex(g_log.hMutex);
}

// Ghi raw bytes (output lệnh) vào log
static void LogWriteBytes(const char* buf, DWORD len)
{
    if (!g_log.enabled || !buf || !len) return;
    WaitForSingleObject(g_log.hMutex, INFINITE);
    DWORD written;
    WriteFile(g_log.hFile, buf, len, &written, NULL);
    // Thêm newline nếu chưa có
    if (len > 0 && buf[len - 1] != '\n')
        WriteFile(g_log.hFile, "\r\n", 2, &written, NULL);
    ReleaseMutex(g_log.hMutex);
}

// ═════════════════════════════════════════════════════════════
// BƯỚC 8 — PHẦN 2: Parallel Scanner
//
// Dùng Windows ThreadPool để scan nhiều IP cùng lúc
// Mỗi IP = 1 work item chạy trên thread pool
// ═════════════════════════════════════════════════════════════

// Dữ liệu truyền vào mỗi thread scan
typedef struct {
    WCHAR   ip[64];         // IP cần scan
    int     port;           // port cần check
    BOOL    isOpen;         // kết quả: open hay không
    HANDLE  hDone;          // event báo thread xong
} SCAN_ITEM;

// Hàm chạy trong thread pool — scan 1 IP
static VOID CALLBACK ScanWorker(
    PTP_CALLBACK_INSTANCE instance,
    PVOID context,
    PTP_WORK work)
{
    SCAN_ITEM* item = (SCAN_ITEM*)context;
    item->isOpen = PingHost(item->ip, item->port);
    SetEvent(item->hDone);  // báo thread chính biết xong
}

// Scan toàn bộ subnet song song
// maxThreads: số IP scan cùng lúc (khuyến nghị 50-100)
static int ScanSubnet(LPCWSTR subnet, int start, int end,
    int port, int maxThreads,
    WCHAR results[][64], int maxResults)
{
    int total = end - start + 1;
    int found = 0;

    // Cấp phát mảng scan items
    SCAN_ITEM* items = (SCAN_ITEM*)calloc(total, sizeof(SCAN_ITEM));
    if (!items) return 0;

    // Tạo thread pool với giới hạn thread
    TP_CALLBACK_ENVIRON env;
    InitializeThreadpoolEnvironment(&env);

    PTP_POOL pool = CreateThreadpool(NULL);
    SetThreadpoolThreadMaximum(pool, maxThreads);
    SetThreadpoolThreadMinimum(pool, 1);
    SetThreadpoolCallbackPool(&env, pool);

    SetColor(COLOR_CYAN);
    wprintf(L"\n[*] Scanning %s.%d-%d port %d (%d threads)...\n\n",
        subnet, start, end, port, maxThreads);
    SetColor(COLOR_NORMAL);

    // Submit tất cả work items
    PTP_WORK* works = (PTP_WORK*)calloc(total, sizeof(PTP_WORK));

    for (int i = 0; i < total; i++)
    {
        int ip_last = start + i;
        StringCchPrintfW(items[i].ip, ARRAYSIZE(items[i].ip),
            L"%s.%d", subnet, ip_last);
        items[i].port = port;
        items[i].hDone = CreateEvent(NULL, FALSE, FALSE, NULL);

        // Tạo work item và submit vào pool
        works[i] = CreateThreadpoolWork(ScanWorker, &items[i], &env);
        if (works[i])
            SubmitThreadpoolWork(works[i]);
        else
            SetEvent(items[i].hDone);  // lỗi → đánh dấu xong ngay
    }

    // Chờ tất cả hoàn thành + in tiến độ
    int  done = 0;
    BOOL showDot = FALSE;

    while (done < total)
    {
        // Chờ batch 10 item hoặc 100ms
        for (int i = 0; i < total; i++) {
            if (!items[i].hDone) continue;
            DWORD w = WaitForSingleObject(items[i].hDone, 0);
            if (w == WAIT_OBJECT_0) {
                // Item này xong rồi
                CloseHandle(items[i].hDone);
                items[i].hDone = NULL;
                done++;

                // In tiến độ
                if (items[i].isOpen) {
                    SetColor(COLOR_GREEN);
                    wprintf(L"  [OPEN]  %s\n", items[i].ip);
                    SetColor(COLOR_NORMAL);
                    LogWrite(L"SCAN OPEN: %s:%d", items[i].ip, port);
                }
            }
        }

        // In dấu chấm tiến độ mỗi 100ms
        Sleep(50);
        wprintf(L"\r  [%d/%d scanned]  ", done, total);
    }

    wprintf(L"\n");

    // Thu thập kết quả
    for (int i = 0; i < total && found < maxResults; i++) {
        if (items[i].isOpen) {
            StringCchCopyW(results[found], 64, items[i].ip);
            found++;
        }
    }

    // Dọn dẹp
    for (int i = 0; i < total; i++) {
        if (works[i]) CloseThreadpoolWork(works[i]);
        if (items[i].hDone) CloseHandle(items[i].hDone);
    }
    CloseThreadpool(pool);
    DestroyThreadpoolEnvironment(&env);
    free(items);
    free(works);

    return found;  // số IP tìm được
}

// ModeScán — gọi ScanSubnet rồi in kết quả
static void ModeScan(LPCWSTR subnet, int start, int end, int threads)
{
    SetColor(COLOR_CYAN);
    wprintf(L"\n╔══════════════════════════════════════════════════╗\n");
    wprintf(L"║  [SCAN] WinRM Discovery                         ║\n");
    wprintf(L"║  Subnet : %-38s║\n", subnet);
    wprintf(L"║  Range  : .%-3d → .%-3d                           ║\n",
        start, end);
    wprintf(L"║  Threads: %-3d                                   ║\n",
        threads);
    wprintf(L"╚══════════════════════════════════════════════════╝\n");
    SetColor(COLOR_NORMAL);

    LogWrite(L"=== SCAN START: %s.%d-%d ===", subnet, start, end);

    // Cấp phát mảng kết quả
    int    maxResults = end - start + 1;
    WCHAR(*found)[64] = (WCHAR(*)[64])calloc(maxResults, 64 * sizeof(WCHAR));
    if (!found) return;

    ULONGLONG t0 = GetTickCount64();
    int       nOpen = ScanSubnet(subnet, start, end,
        WINRM_PORT, threads,
        found, maxResults);
    ULONGLONG ms = GetTickCount64() - t0;

    // In kết quả
    SetColor(COLOR_CYAN);
    wprintf(L"\n╔══════════════════════════════════════════════════╗\n");
    wprintf(L"║  SCAN RESULT                                    ║\n");
    wprintf(L"╠══════════════════════════════════════════════════╣\n");
    SetColor(COLOR_NORMAL);
    wprintf(L"║  Quet   : %-3d IP                                ║\n",
        end - start + 1);
    SetColor(COLOR_GREEN);
    wprintf(L"║  Tim thay: %-3d IP co WinRM (port %d)           ║\n",
        nOpen, WINRM_PORT);
    SetColor(COLOR_NORMAL);
    wprintf(L"║  Thoi gian: %llums                               ║\n", ms);
    SetColor(COLOR_CYAN);
    wprintf(L"╚══════════════════════════════════════════════════╝\n\n");
    SetColor(COLOR_NORMAL);

    for (int i = 0; i < nOpen; i++) {
        SetColor(COLOR_GREEN);
        wprintf(L"  [%2d] %s\n", i + 1, found[i]);
        SetColor(COLOR_NORMAL);
        LogWrite(L"  FOUND: %s", found[i]);
    }
    wprintf(L"\n");

    LogWrite(L"=== SCAN END: %d found in %llums ===", nOpen, ms);
    free(found);
}

// ═════════════════════════════════════════════════════════════
// BƯỚC 8 — PHẦN 3: Brute-force Credentials
//
// Đọc 2 file wordlist → thử từng cặp user:pass
// Dừng ngay khi tìm được cặp đúng
// ═════════════════════════════════════════════════════════════

// Đọc file wordlist → mảng strings
// Mỗi dòng = 1 entry. Bỏ qua dòng trống và comment (#)
static int LoadWordlist(LPCWSTR path, WCHAR** entries, int maxEntries)
{
    FILE* f = NULL;
    _wfopen_s(&f, path, L"r, ccs=UTF-8");
    if (!f) {
        fwprintf(stderr, L"[!] Khong the mo file: %s\n", path);
        return 0;
    }

    int count = 0;
    WCHAR line[256];

    while (count < maxEntries && fgetws(line, ARRAYSIZE(line), f))
    {
        // Trim \r\n
        line[wcscspn(line, L"\r\n")] = L'\0';

        // Bỏ qua dòng trống và comment
        if (line[0] == L'\0' || line[0] == L'#') continue;

        entries[count] = (WCHAR*)malloc((wcslen(line) + 1) * sizeof(WCHAR));
        if (entries[count]) {
            StringCchCopyW(entries[count], wcslen(line) + 1, line);
            count++;
        }
    }

    fclose(f);
    return count;
}

// Thử đăng nhập với 1 cặp credentials
// Trả về TRUE nếu đăng nhập thành công
static BOOL TryCredential(LPCWSTR ip, LPCWSTR user, LPCWSTR pass)
{
    //SESSION s = { .ip = ip, .user = user, .pass = pass };
    SESSION s = {};
    s.ip = ip;
    s.user = user;
    s.pass = pass;

    HRESULT hr = SessionOpen(&s);

    if (SUCCEEDED(hr)) {
        // Xác nhận thực sự bằng cách chạy lệnh đơn giản
        char* buf = NULL; DWORD len = 0;
        hr = RunCmd(&s, L"echo OK", NULL, &buf, &len);
        if (buf) free(buf);
        SessionClose(&s);
    }

    return SUCCEEDED(hr);
}

// ModeBrute — thử từng cặp user:pass từ wordlist
static void ModeBrute(LPCWSTR ip,
    LPCWSTR usersFile,
    LPCWSTR passesFile)
{
    SetColor(COLOR_CYAN);
    wprintf(L"\n╔══════════════════════════════════════════════════╗\n");
    wprintf(L"║  [BRUTE] Credential Testing                     ║\n");
    wprintf(L"║  Target : %-38s║\n", ip);
    wprintf(L"║  Users  : %-38s║\n", usersFile);
    wprintf(L"║  Passes : %-38s║\n", passesFile);
    wprintf(L"╚══════════════════════════════════════════════════╝\n\n");
    SetColor(COLOR_NORMAL);

    // Load wordlists
    WCHAR* users[256] = {};
    WCHAR* passes[1024] = {};
    int nUsers = LoadWordlist(usersFile, users, 256);
    int nPasses = LoadWordlist(passesFile, passes, 1024);

    if (nUsers == 0 || nPasses == 0) {
        wprintf(L"[!] Wordlist trong hoac khong doc duoc\n");
        return;
    }

    wprintf(L"[*] %d users × %d passwords = %d combinations\n\n",
        nUsers, nPasses, nUsers * nPasses);
    LogWrite(L"=== BRUTE START: %s (%d×%d) ===",
        ip, nUsers, nPasses);

    BOOL found = FALSE;
    int  tried = 0;
    int  total = nUsers * nPasses;

    ULONGLONG t0 = GetTickCount64();

    // Vòng lặp thử từng cặp
    for (int u = 0; u < nUsers && !found; u++)
    {
        for (int p = 0; p < nPasses && !found; p++)
        {
            tried++;

            // In tiến độ
            SetColor(COLOR_YELLOW);
            wprintf(L"\r  [%d/%d] Trying %-20s : %-20s",
                tried, total, users[u], passes[p]);
            SetColor(COLOR_NORMAL);

            LogWrite(L"TRY: %s:%s", users[u], passes[p]);

            if (TryCredential(ip, users[u], passes[p]))
            {
                // Tìm được!
                wprintf(L"\n\n");
                SetColor(COLOR_GREEN);
                wprintf(L"  ╔══════════════════════════════════╗\n");
                wprintf(L"  ║  ✓ CREDENTIALS FOUND!           ║\n");
                wprintf(L"  ║  User : %-24s║\n", users[u]);
                wprintf(L"  ║  Pass : %-24s║\n", passes[p]);
                wprintf(L"  ╚══════════════════════════════════╝\n\n");
                SetColor(COLOR_NORMAL);

                LogWrite(L"FOUND: %s:%s", users[u], passes[p]);
                found = TRUE;
            }
            else {
                // Thêm delay nhỏ để tránh bị lock account
                // (AD thường lock sau 5-10 lần sai liên tiếp)
                Sleep(200);
            }
        }
    }

    ULONGLONG ms = GetTickCount64() - t0;

    if (!found) {
        SetColor(COLOR_RED);
        wprintf(L"\n\n  [!] Khong tim thay credentials hop le\n");
        SetColor(COLOR_NORMAL);
        LogWrite(L"BRUTE FAILED: no valid credentials found");
    }

    wprintf(L"  [*] Da thu: %d combinations trong %llums\n\n",
        tried, ms);
    LogWrite(L"=== BRUTE END: %d tried in %llums ===", tried, ms);

    // Dọn dẹp wordlist
    for (int i = 0; i < nUsers; i++) if (users[i])  free(users[i]);
    for (int i = 0; i < nPasses; i++) if (passes[i]) free(passes[i]);
}

// ═════════════════════════════════════════════════════════════
// BƯỚC 8 — PHẦN 4: Parallel Batch
//
// Chạy lệnh trên nhiều máy cùng lúc bằng ThreadPool
// Mỗi máy = 1 work item
// ═════════════════════════════════════════════════════════════

// Dữ liệu cho mỗi thread trong parallel batch
typedef struct {
    // Input
    WCHAR   ip[64];
    WCHAR   user[128];
    WCHAR   pass[128];
    WCHAR   cmd[2048];
    // Output
    BATCH_RESULT result;
    // Sync
    HANDLE  hDone;
} PBATCH_ITEM;

// Worker thread — chạy lệnh trên 1 máy
static VOID CALLBACK PBatchWorker(
    PTP_CALLBACK_INSTANCE instance,
    PVOID context,
    PTP_WORK work)
{
    PBATCH_ITEM* item = (PBATCH_ITEM*)context;

    StringCchCopyW(item->result.ip, ARRAYSIZE(item->result.ip), item->ip);
    item->result.online = PingHost(item->ip, WINRM_PORT);

    if (item->result.online) {
        SESSION s = {};
        s.ip = item->ip;
        s.user = item->user;
        s.pass = item->pass;

        ULONGLONG t0 = GetTickCount64();
        HRESULT hr = SessionOpen(&s);

        if (SUCCEEDED(hr)) {
            hr = RunCmd(&s, item->cmd,
                &item->result.exitCode,
                &item->result.output,
                &item->result.outputLen);
            item->result.success = SUCCEEDED(hr);
            SessionClose(&s);
        }
        item->result.elapsedMs = (DWORD)(GetTickCount64() - t0);
    }

    SetEvent(item->hDone);  // báo xong
}

// ModeBatchParallel — thay thế ModeBatch cũ, chạy song song
static void ModeBatchParallel(LPCWSTR subnet, int start, int end,
    LPCWSTR user, LPCWSTR pass,
    LPCWSTR cmd, int maxThreads)
{
    int total = end - start + 1;

    SetColor(COLOR_CYAN);
    wprintf(L"\n╔══════════════════════════════════════════════════╗\n");
    wprintf(L"║  [BATCH PARALLEL]                               ║\n");
    wprintf(L"║  Subnet : %-38s║\n", subnet);
    wprintf(L"║  Range  : .%-3d → .%-3d                           ║\n",
        start, end);
    wprintf(L"║  Threads: %-3d                                   ║\n",
        maxThreads);
    wprintf(L"║  CMD    : %-38s║\n", cmd);
    wprintf(L"╚══════════════════════════════════════════════════╝\n\n");
    SetColor(COLOR_NORMAL);

    LogWrite(L"=== BATCH PARALLEL START: %s.%d-%d CMD=%s ===",
        subnet, start, end, cmd);

    // Cấp phát items
    PBATCH_ITEM* items = (PBATCH_ITEM*)calloc(total, sizeof(PBATCH_ITEM));
    if (!items) return;

    // Điền thông tin vào từng item
    for (int i = 0; i < total; i++) {
        StringCchPrintfW(items[i].ip, ARRAYSIZE(items[i].ip),
            L"%s.%d", subnet, start + i);
        StringCchCopyW(items[i].user, ARRAYSIZE(items[i].user), user);
        StringCchCopyW(items[i].pass, ARRAYSIZE(items[i].pass), pass);
        StringCchCopyW(items[i].cmd, ARRAYSIZE(items[i].cmd), cmd);
        items[i].hDone = CreateEvent(NULL, FALSE, FALSE, NULL);
    }

    // Tạo thread pool
    TP_CALLBACK_ENVIRON env;
    InitializeThreadpoolEnvironment(&env);
    PTP_POOL pool = CreateThreadpool(NULL);
    SetThreadpoolThreadMaximum(pool, maxThreads);
    SetThreadpoolThreadMinimum(pool, 1);
    SetThreadpoolCallbackPool(&env, pool);

    // Submit tất cả
    PTP_WORK* works = (PTP_WORK*)calloc(total, sizeof(PTP_WORK));
    for (int i = 0; i < total; i++) {
        works[i] = CreateThreadpoolWork(PBatchWorker, &items[i], &env);
        if (works[i]) SubmitThreadpoolWork(works[i]);
        else SetEvent(items[i].hDone);
    }

    ULONGLONG t0 = GetTickCount64();
    int       done = 0;

    // Chờ và in kết quả realtime khi từng item hoàn thành
    while (done < total)
    {
        for (int i = 0; i < total; i++) {
            if (!items[i].hDone) continue;
            if (WaitForSingleObject(items[i].hDone, 0) != WAIT_OBJECT_0)
                continue;

            // Item này xong → in kết quả ngay
            CloseHandle(items[i].hDone);
            items[i].hDone = NULL;
            done++;

            BATCH_RESULT* r = &items[i].result;

            // In 1 dòng kết quả
            wprintf(L"  %-18s ", r->ip);
            if (!r->online) {
                SetColor(COLOR_GRAY);
                wprintf(L"[offline]\n");
            }
            else if (!r->success) {
                SetColor(COLOR_RED);
                wprintf(L"[FAIL]  (%lums)\n", r->elapsedMs);
                LogWrite(L"FAIL: %s", r->ip);
            }
            else {
                SetColor(COLOR_GREEN);
                wprintf(L"[OK]  ");
                SetColor(COLOR_NORMAL);

                // In dòng đầu output
                if (r->output && r->outputLen > 0) {
                    char line[128] = {}; DWORD n = 0;
                    for (DWORD j = 0; j < r->outputLen && j < 127; j++) {
                        if (r->output[j] == '\r' || r->output[j] == '\n') break;
                        line[n++] = r->output[j];
                    }
                    if (n) printf("%s", line);
                }

                SetColor(COLOR_GRAY);
                wprintf(L"  (%lums)\n", r->elapsedMs);
                LogWrite(L"OK: %s exitCode=%lu", r->ip, r->exitCode);
            }
            SetColor(COLOR_NORMAL);
        }
        Sleep(50);
    }

    ULONGLONG totalMs = GetTickCount64() - t0;

    // Tổng kết
    int nOK = 0, nFail = 0, nOffline = 0;
    for (int i = 0; i < total; i++) {
        if (!items[i].result.online) nOffline++;
        else if (items[i].result.success) nOK++;
        else nFail++;
    }

    SetColor(COLOR_CYAN);
    wprintf(L"\n  Tong ket: ");
    SetColor(COLOR_GREEN);  wprintf(L"%d OK  ", nOK);
    SetColor(COLOR_RED);    wprintf(L"%d FAIL  ", nFail);
    SetColor(COLOR_GRAY);   wprintf(L"%d offline  ", nOffline);
    SetColor(COLOR_YELLOW); wprintf(L"| %llums tong\n\n", totalMs);
    SetColor(COLOR_NORMAL);

    LogWrite(L"=== BATCH END: %d OK, %d FAIL, %d offline in %llums ===",
        nOK, nFail, nOffline, totalMs);

    // Dọn dẹp
    for (int i = 0; i < total; i++) {
        if (works[i]) CloseThreadpoolWork(works[i]);
        if (items[i].result.output) free(items[i].result.output);
        if (items[i].hDone) CloseHandle(items[i].hDone);
    }
    CloseThreadpool(pool);
    DestroyThreadpoolEnvironment(&env);
    free(items);
    free(works);
}

// ═════════════════════════════════════════════════════════════
// PHẦN 8 — Usage + wmain
// ═════════════════════════════════════════════════════════════
static void Usage(LPCWSTR exe)
{
    SetColor(COLOR_CYAN);
    wprintf(L"\n  WinRM Remote Exec v2.0\n\n");
    SetColor(COLOR_YELLOW);
    wprintf(L"  Che do:\n\n");
    SetColor(COLOR_NORMAL);

    wprintf(L"  %-8s %s single <IP> <user> <pass> <lenh> [--log]\n",
        L"[1-shot]", exe);
    wprintf(L"  %-8s %s shell  <IP> <user> <pass> [--log]\n",
        L"[REPL]", exe);
    wprintf(L"  %-8s %s batch  <subnet> <s> <e> <user> <pass> <lenh> [--log]\n",
        L"[multi]", exe);
    wprintf(L"  %-8s %s pbatch <subnet> <s> <e> <user> <pass> <lenh> [threads]\n",
        L"[fast]", exe);
    wprintf(L"  %-8s %s scan   <subnet> <s> <e> [threads]\n",
        L"[disco]", exe);
    wprintf(L"  %-8s %s brute  <IP> <users.txt> <passes.txt> [--log]\n\n",
        L"[brute]", exe);

    SetColor(COLOR_GREEN);
    wprintf(L"  Vi du:\n");
    SetColor(COLOR_NORMAL);
    wprintf(L"    %s scan   192.168.1 1 254 100\n", exe);
    wprintf(L"    %s brute  192.168.1.100 users.txt passes.txt --log\n", exe);
    wprintf(L"    %s pbatch 192.168.1 1 50 Admin P@ss hostname 30\n", exe);
    wprintf(L"    %s shell  192.168.1.100 Administrator P@ss --log\n\n", exe);
}

int wmain(int argc, WCHAR* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    if (argc < 2) { Usage(argv[0]); return 1; }

    // Kiểm tra flag --log ở bất kỳ vị trí nào
    // VD: winrm_exec.exe shell IP user pass --log
    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"--log") == 0) {
            LogInit(L"winrm");
            break;
        }
    }

    // ── single ────────────────────────────────────────────────
    if (_wcsicmp(argv[1], L"single") == 0)
    {
        if (argc < 6) {
            wprintf(L"Thieu: single <IP> <user> <pass> <lenh> [--log]\n");
            return 1;
        }
        WCHAR cmd[2048] = {};
        for (int i = 5; i < argc; i++) {
            if (_wcsicmp(argv[i], L"--log") == 0) continue;
            if (i > 5) StringCchCatW(cmd, ARRAYSIZE(cmd), L" ");
            StringCchCatW(cmd, ARRAYSIZE(cmd), argv[i]);
        }
        LogWrite(L"=== SINGLE: %s CMD=%s ===", argv[2], cmd);
        ModeSingle(argv[2], argv[3], argv[4], cmd);
    }
    // ── shell ─────────────────────────────────────────────────
    else if (_wcsicmp(argv[1], L"shell") == 0)
    {
        if (argc < 5) {
            wprintf(L"Thieu: shell <IP> <user> <pass> [--log]\n");
            return 1;
        }
        LogWrite(L"=== SHELL SESSION: %s ===", argv[2]);
        ModeShell(argv[2], argv[3], argv[4]);
    }
    // ── batch (tuần tự — giữ lại) ─────────────────────────────
    else if (_wcsicmp(argv[1], L"batch") == 0)
    {
        if (argc < 8) {
            wprintf(L"Thieu: batch <subnet> <start> <end> <user> <pass> <lenh>\n");
            return 1;
        }
        int start = _wtoi(argv[3]), end = _wtoi(argv[4]);
        if (start < 1 || end>254 || start > end) { wprintf(L"Range 1-254\n"); return 1; }
        WCHAR cmd[2048] = {};
        for (int i = 7; i < argc; i++) {
            if (_wcsicmp(argv[i], L"--log") == 0) continue;
            if (i > 7) StringCchCatW(cmd, ARRAYSIZE(cmd), L" ");
            StringCchCatW(cmd, ARRAYSIZE(cmd), argv[i]);
        }
        LogWrite(L"=== BATCH: %s.%d-%d CMD=%s ===", argv[2], start, end, cmd);
        ModeBatch(argv[2], start, end, argv[5], argv[6], cmd);
    }
    // ── pbatch (song song) — MỚI ──────────────────────────────
    else if (_wcsicmp(argv[1], L"pbatch") == 0)
    {
        // pbatch <subnet> <start> <end> <user> <pass> <lenh> [threads]
        if (argc < 8) {
            wprintf(L"Thieu: pbatch <subnet> <start> <end> <user> <pass> <lenh> [threads=20]\n");
            return 1;
        }
        int start = _wtoi(argv[3]);
        int end = _wtoi(argv[4]);
        int threads = (argc >= 9 && _wtoi(argv[8]) > 0) ? _wtoi(argv[8]) : 20;
        if (start < 1 || end>254 || start > end) { wprintf(L"Range 1-254\n"); return 1; }
        WCHAR cmd[2048] = {};
        for (int i = 7; i < argc; i++) {
            if (_wcsicmp(argv[i], L"--log") == 0) continue;
            if (_wtoi(argv[i]) > 0 && i == 8) continue; // threads arg
            if (i > 7) StringCchCatW(cmd, ARRAYSIZE(cmd), L" ");
            StringCchCatW(cmd, ARRAYSIZE(cmd), argv[i]);
        }
        ModeBatchParallel(argv[2], start, end,
            argv[5], argv[6], cmd, threads);
    }
    // ── scan — MỚI ────────────────────────────────────────────
    else if (_wcsicmp(argv[1], L"scan") == 0)
    {
        // scan <subnet> <start> <end> [threads=100]
        if (argc < 5) {
            wprintf(L"Thieu: scan <subnet> <start> <end> [threads=100]\n");
            return 1;
        }
        int start = _wtoi(argv[3]);
        int end = _wtoi(argv[4]);
        int threads = (argc >= 6) ? _wtoi(argv[5]) : 100;
        if (threads < 1) threads = 100;
        ModeScan(argv[2], start, end, threads);
    }
    // ── brute — MỚI ───────────────────────────────────────────
    else if (_wcsicmp(argv[1], L"brute") == 0)
    {
        // brute <IP> <users.txt> <passes.txt> [--log]
        if (argc < 5) {
            wprintf(L"Thieu: brute <IP> <users.txt> <passes.txt>\n");
            return 1;
        }
        LogWrite(L"=== BRUTE: %s ===", argv[2]);
        ModeBrute(argv[2], argv[3], argv[4]);
    }
    else {
        SetColor(COLOR_RED);
        wprintf(L"[!] Che do khong hop le: '%s'\n\n", argv[1]);
        SetColor(COLOR_NORMAL);
        Usage(argv[0]);
        return 1;
    }

    LogClose();
    return 0;
}