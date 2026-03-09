/*
 * ============================================================
 *  WinRM Remote Command Executor + Interactive Shell
 *  SDK      : Windows SDK 10.0.26100+
 *  Compiler : MSVC  →  cl /EHsc /D_UNICODE /DUNICODE winrm_remote_exec.cpp wsmsvc.lib ws2_32.lib /Fe:winrm_exec.exe
 *
 *  Chế độ:
 *    single  – thực thi 1 lệnh, lấy output, thoát
 *    shell   – interactive REPL: nhập lệnh liên tục như cmd thật
 *    batch   – chạy 1 lệnh trên nhiều host trong subnet
 *
 *  Thiết lập TARGET (PowerShell Admin):
 *    Enable-PSRemoting -Force -SkipNetworkProfileCheck
 *    winrm set winrm/config/service '@{AllowUnencrypted="true"}'
 *    winrm set winrm/config/service/auth '@{Basic="true"}'
 *    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
 *
 *  Thiết lập CLIENT (PowerShell Admin):
 *    Enable-PSRemoting -Force -SkipNetworkProfileCheck
 *    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
 *    Set-Item WSMan:\localhost\Client\AllowUnencrypted -Value $true
 * ============================================================
 */
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

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Wsmsvc.lib")
#pragma comment(lib, "Strsafe.lib")

#define WINRM_PORT        5985
#define SHELL_URI         L"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
#define TIMEOUT_CREATE    15000   // timeout tạo shell/session
#define TIMEOUT_CMD       30000   // timeout chờ lệnh xong
#define TIMEOUT_RECV      5000    // timeout mỗi lần receive chunk
#define OPT_TIMEOUT_SHELL ((WSManSessionOption)211)

 // ═══════════════════════════════════════════════════════════════
 //  Async context
 // ═══════════════════════════════════════════════════════════════
typedef struct _CTX {
    HANDLE               hEvent;
    HRESULT              hr;
    WSMAN_SHELL_HANDLE   hShell;
    WSMAN_COMMAND_HANDLE hCommand;
    char* pOut;
    DWORD                cbOut;
    DWORD                dwExitCode;
    BOOL                 bDone;
    BOOL                 bRecv;   // TRUE = receive context
} CTX;

static BOOL  CtxInit(CTX* c, BOOL bRecv)
{
    ZeroMemory(c, sizeof(*c));
    c->bRecv = bRecv;
    c->hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    return c->hEvent != NULL;
}
static void  CtxFree(CTX* c)
{
    if (c->hEvent) { CloseHandle(c->hEvent); c->hEvent = NULL; }
    if (c->pOut) { free(c->pOut);          c->pOut = NULL; }
}
static HRESULT CtxWait(CTX* c, DWORD ms)
{
    DWORD w = WaitForSingleObject(c->hEvent, ms);
    if (w == WAIT_TIMEOUT) return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
    return c->hr;
}

// ─── helpers ─────────────────────────────────────────────────
static void P(LPCWSTR f, ...) { va_list v; va_start(v, f); wprintf(L"[*] "); vwprintf(f, v); wprintf(L"\n"); va_end(v); }
static void G(LPCWSTR f, ...) { va_list v; va_start(v, f); wprintf(L"[+] "); vwprintf(f, v); wprintf(L"\n"); va_end(v); }
static void E(LPCWSTR ctx, HRESULT hr) {
    WCHAR b[256] = {};
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, (DWORD)hr, 0, b, (DWORD)ARRAYSIZE(b), NULL);
    fwprintf(stderr, L"[!] %s hr=0x%08X %s\n", ctx, (UINT)hr, b);
}

// In buffer OEM ra console
static void PrintOEM(const char* buf, DWORD cb)
{
    if (!buf || !cb) return;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  w = 0;
    // Thử WriteConsoleA trực tiếp (giữ nguyên encoding OEM/UTF-8)
    if (!WriteConsoleA(h, buf, cb, &w, NULL) || !w)
        fwrite(buf, 1, cb, stdout);
}

// Append vào buffer
static void BufAppend(char** pp, DWORD* pcb, const BYTE* src, DWORD len)
{
    char* t = (char*)realloc(*pp, *pcb + len + 1);
    if (!t) return;
    *pp = t;
    memcpy(*pp + *pcb, src, len);
    *pcb += len;
    (*pp)[*pcb] = '\0';
}

// ═══════════════════════════════════════════════════════════════
//  WSMan callback
// ═══════════════════════════════════════════════════════════════
static void CALLBACK CB(
    PVOID                  operationContext,
    DWORD                  flags,
    WSMAN_ERROR* error,
    WSMAN_SHELL_HANDLE     shell,
    WSMAN_COMMAND_HANDLE   command,
    WSMAN_OPERATION_HANDLE /*op*/,
    WSMAN_RESPONSE_DATA* data)
{
    CTX* c = (CTX*)operationContext;
    if (!c) return;

    if (error && error->code) {
        c->hr = HRESULT_FROM_WIN32(error->code);
        fwprintf(stderr, L"[CB] err=%u %s\n", error->code,
            error->errorDetail ? error->errorDetail : L"");
        SetEvent(c->hEvent);
        return;
    }
    c->hr = S_OK;
    if (shell)   c->hShell = shell;
    if (command) c->hCommand = command;

    if (c->bRecv && data) {
        WSMAN_RECEIVE_DATA_RESULT* r = &data->receiveData;
        if (r->commandState &&
            wcscmp(r->commandState, WSMAN_COMMAND_STATE_DONE) == 0)
        {
            c->dwExitCode = r->exitCode;
            c->bDone = TRUE;
        }
        if (r->streamData.binaryData.dataLength > 0)
            BufAppend(&c->pOut, &c->cbOut,
                r->streamData.binaryData.data,
                r->streamData.binaryData.dataLength);
    }

    if (flags & WSMAN_FLAG_CALLBACK_END_OF_OPERATION)
        SetEvent(c->hEvent);
}

// ═══════════════════════════════════════════════════════════════
//  WinRM session wrapper
// ═══════════════════════════════════════════════════════════════
typedef struct _SESSION {
    WSMAN_API_HANDLE     hAPI;
    WSMAN_SESSION_HANDLE hSess;
    WSMAN_SHELL_HANDLE   hShell;
} SESSION;

// Thử tạo session với một cơ chế auth cụ thể
static HRESULT TrySessionWithAuth(
    SESSION* s, LPCWSTR ep, LPCWSTR usr, LPCWSTR pw,
    DWORD authMech, LPCWSTR mechName)
{
    WSMAN_USERNAME_PASSWORD_CREDS upc = { usr, pw };
    WSMAN_AUTHENTICATION_CREDENTIALS auth = {};
    auth.authenticationMechanism = authMech;
    auth.userAccount = upc;

    HRESULT hr = WSManCreateSession(s->hAPI, ep, 0, &auth, NULL, &s->hSess);
    if (FAILED(hr)) return hr;

    // Options
    WSMAN_DATA d = {}; d.type = WSMAN_DATA_TYPE_DWORD;
    d.number = TIMEOUT_CMD;
    WSManSetSessionOption(s->hSess, OPT_TIMEOUT_SHELL, &d);
    // Cho phép credentials qua HTTP không mã hóa (lab workgroup)
    d.number = 1;
    WSManSetSessionOption(s->hSess, WSMAN_OPTION_ALLOW_NEGOTIATE_IMPLICIT_CREDENTIALS, &d);
    // Cho phép unencrypted transport (HTTP, không phải HTTPS)
    // Tương đương: Set-Item WSMan:\localhost\Client\AllowUnencrypted $true
    WSManSetSessionOption(s->hSess, (WSManSessionOption)3 /*WSMAN_OPTION_UNENCRYPTED_MESSAGES*/, &d);

    // Thử tạo shell để xác nhận auth thực sự hoạt động
    CTX c; CtxInit(&c, FALSE);
    WSMAN_SHELL_ASYNC a = { &c, CB };
    WSManCreateShell(s->hSess, 0, SHELL_URI, NULL, NULL, NULL, &a, &s->hShell);
    hr = CtxWait(&c, TIMEOUT_CREATE);
    if (SUCCEEDED(hr)) {
        s->hShell = c.hShell;
        G(L"Connected via %s auth", mechName);
    }
    else {
        // Auth này thất bại → dọn session để thử auth khác
        WSManCloseSession(s->hSess, 0);
        s->hSess = NULL;
        s->hShell = NULL;
    }
    CtxFree(&c);
    return hr;
}

static HRESULT SessionOpen(SESSION* s, LPCWSTR ip, LPCWSTR usr, LPCWSTR pw)
{
    ZeroMemory(s, sizeof(*s));

    HRESULT hr = WSManInitialize(WSMAN_FLAG_REQUESTED_API_VERSION_1_1, &s->hAPI);
    if (FAILED(hr)) { E(L"WSManInitialize", hr); return hr; }

    WCHAR ep[512];
    StringCchPrintfW(ep, ARRAYSIZE(ep), L"http://%s:%d/wsman", ip, WINRM_PORT);
    P(L"Connecting → %s", ep);

    // Thứ tự thử: Negotiate trước (domain env), Basic sau (workgroup/lab)
    struct { DWORD mech; LPCWSTR name; } auths[] = {
        { WSMAN_FLAG_AUTH_NEGOTIATE, L"Negotiate(NTLM)" },
        { WSMAN_FLAG_AUTH_BASIC,     L"Basic"           },
    };

    hr = E_FAIL;
    for (int i = 0; i < 2; i++) {
        P(L"Thu auth: %s ...", auths[i].name);
        hr = TrySessionWithAuth(s, ep, usr, pw, auths[i].mech, auths[i].name);
        if (SUCCEEDED(hr)) return S_OK;
        // Lỗi auth cụ thể (code 5 = Access Denied / auth not supported)
        // → thử auth tiếp theo
        fwprintf(stderr, L"    [-] %s that bai: hr=0x%08X\n", auths[i].name, (UINT)hr);
    }

    E(L"SessionOpen: tat ca auth deu that bai", hr);
    return hr;
}

static void SessionClose(SESSION* s)
{
    if (s->hShell) { WSManCloseShell(s->hShell, 0, NULL); s->hShell = NULL; }
    if (s->hSess) { WSManCloseSession(s->hSess, 0);      s->hSess = NULL; }
    if (s->hAPI) { WSManDeinitialize(s->hAPI, 0);        s->hAPI = NULL; }
}

// ═══════════════════════════════════════════════════════════════
//  Thực thi 1 lệnh, trả về output (accumulate tất cả chunks)
//  bPrint = TRUE  → in ra console ngay
//  bPrint = FALSE → chỉ lưu vào ppOut (caller free)
// ═══════════════════════════════════════════════════════════════
static HRESULT RunCmd(
    SESSION* s,
    LPCWSTR  cmd,
    BOOL     bPrint,
    char** ppOut,    // nullable
    DWORD* pcbOut,   // nullable
    DWORD* pExit)    // nullable
{
    WSMAN_COMMAND_HANDLE   hCmd = NULL;
    WSMAN_OPERATION_HANDLE hOp = NULL;
    HRESULT hr = S_OK;

    // Gửi lệnh
    CTX cc; CtxInit(&cc, FALSE);
    WSMAN_SHELL_ASYNC ac = { &cc, CB };
    WSManRunShellCommand(s->hShell, 0, cmd, NULL, NULL, &ac, &hCmd);
    hr = CtxWait(&cc, TIMEOUT_CREATE);
    if (SUCCEEDED(hr)) hCmd = cc.hCommand;
    CtxFree(&cc);
    if (FAILED(hr)) { E(L"WSManRunShellCommand", hr); return hr; }

    // Receive loop – accumulate toàn bộ output cho đến Done
    PCWSTR streams[2] = { L"stdout", L"stderr" };
    WSMAN_STREAM_ID_SET ss = { 2, streams };

    CTX rc; CtxInit(&rc, TRUE);
    BOOL bDone = FALSE;

    while (!bDone) {
        ResetEvent(rc.hEvent);
        WSMAN_SHELL_ASYNC ar = { &rc, CB };
        WSManReceiveShellOutput(s->hShell, hCmd, 0, &ss, &ar, &hOp);

        HRESULT hrW = CtxWait(&rc, TIMEOUT_RECV);

        if (hOp) { WSManCloseOperation(hOp, 0); hOp = NULL; }

        if (hrW == HRESULT_FROM_WIN32(ERROR_TIMEOUT)) {
            // Timeout nhưng đã có data → flush ra console và tiếp tục
            if (rc.cbOut > 0 && bPrint) {
                PrintOEM(rc.pOut, rc.cbOut);
                free(rc.pOut); rc.pOut = NULL; rc.cbOut = 0;
            }
            // Nếu lệnh là interactive (cmd.exe) thì thoát vòng lặp
            break;
        }

        if (FAILED(hrW)) { hr = hrW; break; }

        // In/lưu chunk hiện tại
        if (rc.cbOut > 0) {
            if (bPrint) PrintOEM(rc.pOut, rc.cbOut);
            if (ppOut && pcbOut)
                BufAppend(ppOut, pcbOut, (BYTE*)rc.pOut, rc.cbOut);
            free(rc.pOut); rc.pOut = NULL; rc.cbOut = 0;
        }

        bDone = rc.bDone;
    }

    if (pExit) *pExit = rc.dwExitCode;
    CtxFree(&rc);

    if (hCmd) WSManCloseCommand(hCmd, 0, NULL);
    return hr;
}

// ═══════════════════════════════════════════════════════════════
//  Chế độ SINGLE – chạy 1 lệnh rồi thoát
// ═══════════════════════════════════════════════════════════════
static void ModeSingle(LPCWSTR ip, LPCWSTR usr, LPCWSTR pw, LPCWSTR cmd)
{
    SESSION s;
    HRESULT hr = SessionOpen(&s, ip, usr, pw);
    if (FAILED(hr)) return;

    wprintf(L"\n────────────────── OUTPUT ──────────────────\n");
    DWORD dwExit = 0;
    RunCmd(&s, cmd, TRUE, NULL, NULL, &dwExit);
    wprintf(L"\n────────────────────────────────────────────\n");
    G(L"ExitCode: %lu", dwExit);

    SessionClose(&s);
}

// ═══════════════════════════════════════════════════════════════
//  Chế độ SHELL – interactive REPL
//  Mỗi lần nhập lệnh → tạo WSManRunShellCommand mới → nhận output
//  → hiện kết quả → chờ lệnh tiếp theo
//  (WinRM không hỗ trợ stdin pipe thực sự, đây là pseudo-interactive)
// ═══════════════════════════════════════════════════════════════
static void ModeShell(LPCWSTR ip, LPCWSTR usr, LPCWSTR pw)
{
    SESSION s;
    HRESULT hr = SessionOpen(&s, ip, usr, pw);
    if (FAILED(hr)) return;

    wprintf(L"\n");
    wprintf(L"╔══════════════════════════════════════════════════╗\n");
    wprintf(L"║  WinRM Interactive Shell  →  %s\n", ip);
    wprintf(L"║  Gõ 'exit' hoặc 'quit' để thoát\n");
    wprintf(L"╚══════════════════════════════════════════════════╝\n\n");

    // Lấy hostname để hiện prompt
    char  szHost[128] = {};
    DWORD cbHost = 0;
    RunCmd(&s, L"hostname", FALSE,
        &szHost[0] != NULL ? (char**)&szHost : NULL,
        &cbHost, NULL);
    // Xóa newline cuối
    for (DWORD i = 0; i < cbHost; i++)
        if (szHost[i] == '\r' || szHost[i] == '\n') { szHost[i] = '\0'; break; }

    char szPrompt[256];
    if (cbHost > 0)
        StringCchPrintfA(szPrompt, ARRAYSIZE(szPrompt), "%s> ", szHost);
    else
        StringCchPrintfA(szPrompt, ARRAYSIZE(szPrompt), "%S> ", ip);

    WCHAR  szLine[2048];
    char   szLineMB[2048];

    while (TRUE)
    {
        // Hiện prompt
        printf("%s", szPrompt);
        fflush(stdout);

        // Đọc input từ user
        if (!fgetws(szLine, ARRAYSIZE(szLine), stdin)) break;

        // Xóa newline
        szLine[wcscspn(szLine, L"\r\n")] = L'\0';

        // Lệnh thoát
        if (_wcsicmp(szLine, L"exit") == 0 ||
            _wcsicmp(szLine, L"quit") == 0) break;

        // Bỏ qua dòng trống
        if (szLine[0] == L'\0') continue;

        // Thực thi lệnh và in output ngay
        DWORD dwExit = 0;
        hr = RunCmd(&s, szLine, TRUE, NULL, NULL, &dwExit);
        wprintf(L"\n");

        if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_TIMEOUT)) {
            fwprintf(stderr, L"[!] Loi thuc thi: 0x%08X\n", (UINT)hr);
            // Shell có thể đã chết → thử reconnect
            SessionClose(&s);
            wprintf(L"[*] Reconnecting...\n");
            hr = SessionOpen(&s, ip, usr, pw);
            if (FAILED(hr)) break;
        }
    }

    wprintf(L"\n[*] Thoat shell.\n");
    SessionClose(&s);
}

// ═══════════════════════════════════════════════════════════════
//  Fallback: winrs.exe process (non-interactive, 1 lệnh)
// ═══════════════════════════════════════════════════════════════
static DWORD WinrsRun(LPCWSTR ip, LPCWSTR usr, LPCWSTR pw, LPCWSTR cmd)
{
    WCHAR line[2048];
    StringCchPrintfW(line, ARRAYSIZE(line),
        L"winrs.exe -r:http://%s:%d -u:%s -p:%s -a:basic \"%s\"",
        ip, WINRM_PORT, usr, pw, cmd);
    P(L"[winrs] %s", line);

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hR, hW;
    if (!CreatePipe(&hR, &hW, &sa, 0)) return (DWORD)-1;
    SetHandleInformation(hR, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {}; PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hW; si.hStdError = hW;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    if (!CreateProcessW(NULL, line, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        CloseHandle(hR); CloseHandle(hW); return (DWORD)-1;
    }
    CloseHandle(hW);

    char buf[4096]; DWORD r;
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    while (ReadFile(hR, buf, sizeof(buf) - 1, &r, NULL) && r)
    {
        DWORD w = 0;
        if (!WriteConsoleA(hCon, buf, r, &w, NULL) || !w)
            fwrite(buf, 1, r, stdout);
    }

    WaitForSingleObject(pi.hProcess, TIMEOUT_CMD);
    DWORD ex = 0; GetExitCodeProcess(pi.hProcess, &ex);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hR);
    return ex;
}

// ═══════════════════════════════════════════════════════════════
//  Ping check
// ═══════════════════════════════════════════════════════════════
static BOOL PingHost(LPCWSTR ip)
{
    WCHAR cmd[256];
    StringCchPrintfW(cmd, ARRAYSIZE(cmd), L"ping -n 1 -w 800 %s", ip);
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hR, hW;
    if (!CreatePipe(&hR, &hW, &sa, 0)) return FALSE;
    SetHandleInformation(hR, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si = {}; PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; si.hStdOutput = hW; si.hStdError = hW;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hW);
    if (!ok) { CloseHandle(hR); return FALSE; }
    char tmp[64]; DWORD r;
    while (ReadFile(hR, tmp, sizeof(tmp), &r, NULL) && r) {}
    WaitForSingleObject(pi.hProcess, 4000);
    DWORD ex = 1; GetExitCodeProcess(pi.hProcess, &ex);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hR);
    return ex == 0;
}

// ═══════════════════════════════════════════════════════════════
//  Batch exec
// ═══════════════════════════════════════════════════════════════
static void ModeBatch(LPCWSTR subnet, int s, int e,
    LPCWSTR usr, LPCWSTR pw, LPCWSTR cmd)
{
    wprintf(L"\n╔══════════════════════════════════════╗\n");
    wprintf(L"║  BATCH  %s.%d-%d\n", subnet, s, e);
    wprintf(L"║  CMD: %s\n", cmd);
    wprintf(L"╚══════════════════════════════════════╝\n\n");

    for (int i = s; i <= e; i++) {
        WCHAR ip[64];
        StringCchPrintfW(ip, ARRAYSIZE(ip), L"%s.%d", subnet, i);
        wprintf(L"─ %-16s ", ip);
        if (!PingHost(ip)) { wprintf(L"[offline]\n"); continue; }
        wprintf(L"[online] → ");
        fflush(stdout);
        WinrsRun(ip, usr, pw, cmd);
        wprintf(L"\n");
    }
}

// ═══════════════════════════════════════════════════════════════
//  Usage
// ═══════════════════════════════════════════════════════════════
static void Usage(LPCWSTR exe)
{
    wprintf(
        L"\nWinRM Remote Exec\n\n"
        L"  %-8s %s single <IP> <user> <pass> <command>\n"
        L"  %-8s %s shell  <IP> <user> <pass>\n"
        L"  %-8s %s batch  <subnet> <start> <end> <user> <pass> <command>\n\n"
        L"Vi du:\n"
        L"  %s single 192.168.1.100 Administrator P@ss \"ipconfig /all\"\n"
        L"  %s shell  192.168.1.100 Administrator P@ss\n"
        L"  %s batch  192.168.1 1 50 Administrator P@ss \"hostname\"\n\n",
        L"[1-shot]", exe, L"[REPL]", exe, L"[multi]", exe,
        exe, exe, exe);
}

// ═══════════════════════════════════════════════════════════════
//  wmain
// ═══════════════════════════════════════════════════════════════
int wmain(int argc, WCHAR* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    if (argc < 2) { Usage(argv[0]); return 1; }

    // ── single ───────────────────────────────────────────────
    if (_wcsicmp(argv[1], L"single") == 0)
    {
        if (argc < 6) {
            wprintf(L"Thieu tham so: single <IP> <user> <pass> <command>\n");
            return 1;
        }
        // Ghép argv[5..] thành lệnh (phòng space)
        WCHAR szCmd[2048] = {};
        for (int i = 5; i < argc; i++) {
            if (i > 5) StringCchCatW(szCmd, ARRAYSIZE(szCmd), L" ");
            StringCchCatW(szCmd, ARRAYSIZE(szCmd), argv[i]);
        }
        ModeSingle(argv[2], argv[3], argv[4], szCmd);
    }
    // ── shell (interactive REPL) ──────────────────────────────
    else if (_wcsicmp(argv[1], L"shell") == 0)
    {
        if (argc < 5) {
            wprintf(L"Thieu tham so: shell <IP> <user> <pass>\n");
            return 1;
        }
        ModeShell(argv[2], argv[3], argv[4]);
    }
    // ── batch ────────────────────────────────────────────────
    else if (_wcsicmp(argv[1], L"batch") == 0)
    {
        if (argc < 8) {
            wprintf(L"Thieu tham so: batch <subnet> <start> <end> <user> <pass> <cmd>\n");
            return 1;
        }
        WCHAR szCmd[2048] = {};
        for (int i = 7; i < argc; i++) {
            if (i > 7) StringCchCatW(szCmd, ARRAYSIZE(szCmd), L" ");
            StringCchCatW(szCmd, ARRAYSIZE(szCmd), argv[i]);
        }
        ModeBatch(argv[2], _wtoi(argv[3]), _wtoi(argv[4]),
            argv[5], argv[6], szCmd);
    }
    else {
        Usage(argv[0]);
        return 1;
    }

    return 0;
}