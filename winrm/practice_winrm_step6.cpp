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
// Tất cả struct + callback + helper từ Bước 4
// (copy nguyên, không thay đổi)
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

typedef struct {
    WSMAN_API_HANDLE     hAPI;
    WSMAN_SESSION_HANDLE hSession;
    LPCWSTR              ip;
    LPCWSTR              user;
    LPCWSTR              pass;
} SESSION;

// ── Kết quả của 1 máy trong batch ────────────────────────────
// Lưu lại để in báo cáo tổng kết cuối cùng
typedef struct {
    WCHAR  ip[64];          // địa chỉ IP
    BOOL   online;          // ping được không
    BOOL   success;         // chạy lệnh thành công không
    DWORD  exitCode;        // exit code của lệnh
    char* output;          // output (caller free)
    DWORD  outputLen;
    DWORD  elapsedMs;       // thời gian thực thi (ms)
} BATCH_RESULT;

static void PrintError(LPCWSTR where, HRESULT hr)
{
    WCHAR msg[256] = {};
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, (DWORD)hr, 0, msg, ARRAYSIZE(msg), NULL);
    fwprintf(stderr, L"  [!] %s: 0x%08X — %s\n", where, (UINT)hr, msg);
}

static void PrintBytes(const char* buf, DWORD cb)
{
    if (!buf || !cb) return;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD w = 0;
    if (!WriteConsoleA(h, buf, cb, &w, NULL) || !w)
        fwrite(buf, 1, cb, stdout);
}

static void SetColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}
#define COLOR_NORMAL  0x0007
#define COLOR_GREEN   0x000A
#define COLOR_YELLOW  0x000E
#define COLOR_CYAN    0x000B
#define COLOR_RED     0x000C

// ── Callbacks (không đổi) ─────────────────────────────────────
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

// ── ReceiveLoop (không đổi) ───────────────────────────────────
static HRESULT ReceiveLoop(CTX* ctx)
{
    PCWSTR streamNames[2] = { L"stdout", L"stderr" };
    WSMAN_STREAM_ID_SET streams = { 2, streamNames };

    while (!ctx->bCmdDone) {
        if (ctx->pChunk) { free(ctx->pChunk); ctx->pChunk = NULL; ctx->cbChunk = 0; }
        ResetEvent(ctx->hEvent);

        WSMAN_SHELL_ASYNC a = { ctx, OnChunkReceived };
        WSMAN_OPERATION_HANDLE hOp = NULL;
        WSManReceiveShellOutput(ctx->hShell, ctx->hCommand, 0, &streams, &a, &hOp);

        DWORD w = WaitForSingleObject(ctx->hEvent, 30000);
        if (hOp) { WSManCloseOperation(hOp, 0); hOp = NULL; }

        if (w == WAIT_TIMEOUT) break;
        if (ctx->hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) break;
        if (FAILED(ctx->hr)) return ctx->hr;
    }
    return S_OK;
}

// ── SessionOpen / SessionClose / RunCmd (không đổi) ───────────
static HRESULT SessionOpen(SESSION* s)
{
    s->hAPI = NULL; s->hSession = NULL;
    HRESULT hr = WSManInitialize(WSMAN_FLAG_REQUESTED_API_VERSION_1_1, &s->hAPI);
    if (FAILED(hr)) return hr;

    WSMAN_USERNAME_PASSWORD_CREDS creds = { s->user, s->pass };
    WSMAN_AUTHENTICATION_CREDENTIALS auth = {};
    auth.authenticationMechanism = WSMAN_FLAG_AUTH_NEGOTIATE;
    auth.userAccount = creds;

    WCHAR endpoint[256];
    StringCchPrintfW(endpoint, ARRAYSIZE(endpoint),
        L"http://%s:5985/wsman", s->ip);

    hr = WSManCreateSession(s->hAPI, endpoint, 0, &auth, NULL, &s->hSession);
    if (FAILED(hr)) return hr;

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

    {
        WSMAN_SHELL_ASYNC a = { &ctx, OnShellCreated };
        WSMAN_SHELL_HANDLE hShell = NULL;
        WSManCreateShell(s->hSession, 0,
            L"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
            NULL, NULL, NULL, &a, &hShell);
        if (WaitForSingleObject(ctx.hEvent, 15000) == WAIT_TIMEOUT) {
            hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT); goto cleanup;
        }
        if (FAILED(ctx.hr)) { hr = ctx.hr; goto cleanup; }
    }

    ResetEvent(ctx.hEvent);
    {
        WSMAN_SHELL_ASYNC a = { &ctx, OnCommandSent };
        WSMAN_COMMAND_HANDLE hCmd = NULL;
        WSManRunShellCommand(ctx.hShell, 0, cmd, NULL, NULL, &a, &hCmd);
        if (WaitForSingleObject(ctx.hEvent, 15000) == WAIT_TIMEOUT) {
            hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT); goto cleanup;
        }
        if (FAILED(ctx.hr)) { hr = ctx.hr; goto cleanup; }
    }

    hr = ReceiveLoop(&ctx);
    if (pExitCode) *pExitCode = ctx.exitCode;

    if (ppOutBuf && pOutLen && ctx.pChunk) {
        *ppOutBuf = ctx.pChunk;
        *pOutLen = ctx.cbChunk;
        ctx.pChunk = NULL;
    }

cleanup:
    if (ctx.pChunk)   free(ctx.pChunk);
    if (ctx.hCommand) WSManCloseCommand(ctx.hCommand, 0, NULL);
    if (ctx.hShell)   WSManCloseShell(ctx.hShell, 0, NULL);
    if (ctx.hEvent)   CloseHandle(ctx.hEvent);
    return hr;
}

// ═════════════════════════════════════════════════════════════
// PingHost — MỚI ở Bước 6
//
// Cách hoạt động:
//   Thay vì dùng ICMP API phức tạp,
//   ta thử mở TCP connection đến port 5985 (WinRM)
//   Nếu connect được → máy đó đang chạy WinRM → online
//   Nếu refused/timeout → skip
//
// Tại sao không dùng ping ICMP?
//   - ICMP thường bị firewall chặn
//   - Port 5985 mở = WinRM đang chạy = ta có thể kết nối
//   - Kiểm tra đúng mục đích hơn
// ═════════════════════════════════════════════════════════════
static BOOL PingHost(LPCWSTR ip, int port)
{
    // Khởi động Winsock (cần 1 lần cho toàn process)
    static BOOL wsStarted = FALSE;
    if (!wsStarted) {
        WSADATA wd;
        WSAStartup(MAKEWORD(2, 2), &wd);
        wsStarted = TRUE;
    }

    // Convert IP từ wide string sang char
    char ipA[64] = {};
    WideCharToMultiByte(CP_ACP, 0, ip, -1, ipA, sizeof(ipA), NULL, NULL);

    // Tạo socket TCP
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return FALSE;

    // Đặt timeout 800ms cho connect
    // (không muốn chờ lâu khi scan subnet)
    DWORD timeout = 800;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
        (char*)&timeout, sizeof(timeout));

    // Chuyển socket sang non-blocking để có thể timeout connect
    u_long nonBlock = 1;
    ioctlsocket(sock, FIONBIO, &nonBlock);

    // Điền địa chỉ đích
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    addr.sin_addr.s_addr = inet_addr(ipA);

    // Thử kết nối (non-blocking → trả về ngay)
    connect(sock, (sockaddr*)&addr, sizeof(addr));

    // Dùng select() để chờ tối đa 800ms
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    timeval tv = { 0, 800000 };  // 800ms

    BOOL online = (select(0, NULL, &fds, NULL, &tv) > 0);

    closesocket(sock);
    return online;
}

// ═════════════════════════════════════════════════════════════
// RunOnHost — MỚI ở Bước 6
//
// Chạy lệnh trên 1 máy cụ thể, lưu kết quả vào BATCH_RESULT
// Tách riêng để dễ đọc trong ModeBatch
// ═════════════════════════════════════════════════════════════
static void RunOnHost(LPCWSTR ip, LPCWSTR user, LPCWSTR pass,
    LPCWSTR cmd, BATCH_RESULT* result)
{
    StringCchCopyW(result->ip, ARRAYSIZE(result->ip), ip);
    result->online = TRUE;
    result->success = FALSE;

    SESSION s = {};
    s.ip = ip;
    s.user = user;
    s.pass = pass;

    ULONGLONG t0 = GetTickCount64();

    HRESULT hr = SessionOpen(&s);
    if (SUCCEEDED(hr)) {
        hr = RunCmd(&s, cmd, &result->exitCode,
            &result->output, &result->outputLen);
        result->success = SUCCEEDED(hr);
        SessionClose(&s);
    }

    result->elapsedMs = (DWORD)(GetTickCount64() - t0);

    if (FAILED(hr))
        PrintError(ip, hr);
}

// ═════════════════════════════════════════════════════════════
// TrimOutput — MỚI ở Bước 6
//
// Xóa \r\n ở đầu và cuối output để in gọn hơn
// ═════════════════════════════════════════════════════════════
static void TrimOutput(char* buf, DWORD* pLen)
{
    if (!buf || !*pLen) return;

    // Xóa đầu
    DWORD start = 0;
    while (start < *pLen &&
        (buf[start] == '\r' || buf[start] == '\n' || buf[start] == ' '))
        start++;

    // Xóa cuối
    DWORD end = *pLen;
    while (end > start &&
        (buf[end - 1] == '\r' || buf[end - 1] == '\n' || buf[end - 1] == ' '))
        end--;

    // Dịch chuyển về đầu
    DWORD newLen = end - start;
    memmove(buf, buf + start, newLen);
    buf[newLen] = '\0';
    *pLen = newLen;
}

// ═════════════════════════════════════════════════════════════
// PrintBatchProgress — MỚI ở Bước 6
//
// In 1 dòng kết quả ngay khi xử lý xong 1 máy
// Không chờ đến cuối mới in → user thấy tiến độ realtime
// ═════════════════════════════════════════════════════════════
static void PrintBatchProgress(const BATCH_RESULT* r, int idx, int total)
{
    // Thanh tiến độ đơn giản: [====      ] 4/10
    int barWidth = 20;
    int filled = (idx * barWidth) / total;

    SetColor(COLOR_YELLOW);
    wprintf(L"  [");
    SetColor(COLOR_GREEN);
    for (int i = 0; i < filled; i++) wprintf(L"=");
    SetColor(COLOR_NORMAL);
    for (int i = filled; i < barWidth; i++) wprintf(L" ");
    SetColor(COLOR_YELLOW);
    wprintf(L"] %d/%d  ", idx, total);
    SetColor(COLOR_NORMAL);

    // IP
    wprintf(L"%-18s ", r->ip);

    if (!r->online) {
        SetColor(0x0008);  // abu tối
        wprintf(L"[offline]\n");
        SetColor(COLOR_NORMAL);
        return;
    }

    if (!r->success) {
        SetColor(COLOR_RED);
        wprintf(L"[FAIL]\n");
        SetColor(COLOR_NORMAL);
        return;
    }

    // Thành công → in output 1 dòng (trim newline)
    SetColor(COLOR_GREEN);
    wprintf(L"[OK] ");
    SetColor(COLOR_NORMAL);

    if (r->output && r->outputLen > 0) {
        // Chỉ in dòng đầu tiên để không làm lộn table
        char firstLine[128] = {};
        DWORD lineLen = 0;
        for (DWORD i = 0; i < r->outputLen && i < 127; i++) {
            if (r->output[i] == '\r' || r->output[i] == '\n') break;
            firstLine[lineLen++] = r->output[i];
        }
        firstLine[lineLen] = '\0';
        if (lineLen > 0) {
            printf("%s", firstLine);
        }
    }
    SetColor(0x0008);
    wprintf(L"  (%lums)\n", r->elapsedMs);
    SetColor(COLOR_NORMAL);
}

// ═════════════════════════════════════════════════════════════
// PrintBatchSummary — MỚI ở Bước 6
//
// In báo cáo tổng kết sau khi scan xong toàn subnet
// ═════════════════════════════════════════════════════════════
static void PrintBatchSummary(BATCH_RESULT* results, int count,
    LPCWSTR cmd)
{
    int nOnline = 0;
    int nSuccess = 0;
    int nFail = 0;
    DWORD totalMs = 0;

    for (int i = 0; i < count; i++) {
        if (!results[i].online)  continue;
        nOnline++;
        if (results[i].success) nSuccess++;
        else                    nFail++;
        totalMs += results[i].elapsedMs;
    }

    SetColor(COLOR_CYAN);
    wprintf(L"\n╔══════════════════════════════════════════════════╗\n");
    wprintf(L"║                  BATCH SUMMARY                  ║\n");
    wprintf(L"╠══════════════════════════════════════════════════╣\n");
    SetColor(COLOR_NORMAL);

    wprintf(L"║  Lenh    : %-38s║\n", cmd);
    wprintf(L"║  Tong    : %-3d may duoc quet               "
        L"      ║\n", count);

    SetColor(COLOR_GREEN);
    wprintf(L"║  Online  : %-3d may phan hoi WinRM               "
        L"║\n", nOnline);
    SetColor(COLOR_NORMAL);

    wprintf(L"║  Thanh cong: %-3d                                 "
        L"║\n", nSuccess);

    if (nFail > 0) {
        SetColor(COLOR_RED);
        wprintf(L"║  That bai: %-3d                                   "
            L"║\n", nFail);
        SetColor(COLOR_NORMAL);
    }

    wprintf(L"║  Thoi gian TB: %lums/may                          "
        L"║\n", nOnline > 0 ? totalMs / nOnline : 0);

    SetColor(COLOR_CYAN);
    wprintf(L"╚══════════════════════════════════════════════════╝\n\n");
    SetColor(COLOR_NORMAL);

    // In full output của những máy thành công
    // (lúc trước chỉ in dòng đầu, giờ in đầy đủ)
    if (nSuccess > 0) {
        SetColor(COLOR_YELLOW);
        wprintf(L"  ── Chi tiet output ──\n\n");
        SetColor(COLOR_NORMAL);

        for (int i = 0; i < count; i++) {
            if (!results[i].success) continue;

            SetColor(COLOR_CYAN);
            wprintf(L"  [%s]\n", results[i].ip);
            SetColor(COLOR_NORMAL);

            if (results[i].output && results[i].outputLen > 0) {
                TrimOutput(results[i].output, &results[i].outputLen);
                PrintBytes(results[i].output, results[i].outputLen);
                wprintf(L"\n");
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════
// ModeBatch — TRÁI TIM của Bước 6
//
// Tham số:
//   subnet  = "192.168.1"     (không có .x cuối)
//   start   = 1
//   end     = 50
//   → quét từ 192.168.1.1 đến 192.168.1.50
// ═════════════════════════════════════════════════════════════
static void ModeBatch(LPCWSTR subnet, int start, int end,
    LPCWSTR user, LPCWSTR pass, LPCWSTR cmd)
{
    int total = end - start + 1;

    // Cấp phát mảng kết quả
    BATCH_RESULT* results = (BATCH_RESULT*)calloc(total, sizeof(BATCH_RESULT));
    if (!results) { wprintf(L"[!] Out of memory\n"); return; }

    // Banner
    SetColor(COLOR_CYAN);
    wprintf(L"\n╔══════════════════════════════════════════════════╗\n");
    wprintf(L"║  BATCH SCAN                                      ║\n");
    wprintf(L"║  Subnet : %-38s  ║\n", subnet);
    wprintf(L"║  Range  : .%-3d → .%-3d                            ║\n",
        start, end);
    wprintf(L"║  Lenh   : %-38s  ║\n", cmd);
    wprintf(L"╚══════════════════════════════════════════════════╝\n\n");
    SetColor(COLOR_NORMAL);

    // ── Loop chính ────────────────────────────────────────────
    for (int i = start; i <= end; i++)
    {
        int idx = i - start;

        // Tạo IP đầy đủ: subnet + "." + số
        WCHAR ip[64];
        StringCchPrintfW(ip, ARRAYSIZE(ip), L"%s.%d", subnet, i);

        // Bước A: Ping (kiểm tra WinRM port 5985)
        wprintf(L"  %-18s ", ip);
        SetColor(0x0008);
        wprintf(L"checking...\r");
        SetColor(COLOR_NORMAL);

        BOOL online = PingHost(ip, 5985);
        results[idx].online = online;
        StringCchCopyW(results[idx].ip, ARRAYSIZE(results[idx].ip), ip);

        if (!online) {
            // In ngay kết quả offline
            PrintBatchProgress(&results[idx], idx + 1, total);
            continue;
        }

        // Bước B: Chạy lệnh trên máy online
        RunOnHost(ip, user, pass, cmd, &results[idx]);

        // In tiến độ ngay sau khi xong 1 máy
        PrintBatchProgress(&results[idx], idx + 1, total);
    }

    // ── Báo cáo tổng kết ─────────────────────────────────────
    PrintBatchSummary(results, total, cmd);

    // ── Dọn dẹp ──────────────────────────────────────────────
    for (int i = 0; i < total; i++)
        if (results[i].output) free(results[i].output);
    free(results);
}

// ═════════════════════════════════════════════════════════════
// wmain
// ═════════════════════════════════════════════════════════════
int wmain(int argc, WCHAR* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    if (argc < 7) {
        wprintf(L"Dung: step6.exe <subnet> <start> <end> "
            L"<user> <pass> <lenh>\n\n");
        wprintf(L"VD: step6.exe 192.168.1 1 50 "
            L"Administrator P@ss \"hostname\"\n");
        return 1;
    }

    LPCWSTR subnet = argv[1];
    int     start = _wtoi(argv[2]);
    int     end = _wtoi(argv[3]);
    LPCWSTR user = argv[4];
    LPCWSTR pass = argv[5];

    // Ghép lệnh từ argv[6] trở đi
    WCHAR cmd[2048] = {};
    for (int i = 6; i < argc; i++) {
        if (i > 6) StringCchCatW(cmd, ARRAYSIZE(cmd), L" ");
        StringCchCatW(cmd, ARRAYSIZE(cmd), argv[i]);
    }

    // Validate range
    if (start < 1 || end > 254 || start > end) {
        wprintf(L"[!] Range khong hop le (1-254)\n");
        return 1;
    }

    ModeBatch(subnet, start, end, user, pass, cmd);
    return 0;
}