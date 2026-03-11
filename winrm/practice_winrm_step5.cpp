// step5.cpp
// Mục tiêu: Interactive REPL shell qua WinRM
//
// Compile:
//   cl /EHsc /DUNICODE /D_UNICODE step5.cpp Wsmsvc.lib /Fe:step5.exe
//
// Chạy:
//   step5.exe 192.168.1.100 Administrator P@ssword

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
// Cấu hình
// ═════════════════════════════════════════════════════════════
#define MAX_HISTORY     20      // số lệnh lưu trong history
#define TIMEOUT_SHELL   15000   // timeout tạo shell (ms)
#define TIMEOUT_CMD     30000   // timeout nhận output (ms)
#define MAX_RECONNECT   3       // số lần thử reconnect

// ═════════════════════════════════════════════════════════════
// CTX + SESSION — giống Bước 4
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
    LPCWSTR              ip;      // lưu lại để reconnect
    LPCWSTR              user;
    LPCWSTR              pass;
} SESSION;

// ═════════════════════════════════════════════════════════════
// SHELL_STATE — MỚI ở Bước 5
// Lưu trạng thái của shell qua các lệnh
// ═════════════════════════════════════════════════════════════
typedef struct {
    WCHAR  hostname[64];         // tên máy đích (làm prompt)
    WCHAR  cwd[512];             // thư mục hiện tại (giả lập)
    WCHAR  history[MAX_HISTORY][512]; // lịch sử lệnh
    int    historyCount;         // số lệnh trong history
    int    historyPos;           // vị trí đang duyệt history
    int    cmdCount;             // tổng số lệnh đã chạy
    DWORD  lastExitCode;         // exit code của lệnh vừa rồi
} SHELL_STATE;

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

// Màu console
static void SetColor(WORD color)
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}
#define COLOR_NORMAL   0x0007   // abu
#define COLOR_GREEN    0x000A   // xanh lá
#define COLOR_YELLOW   0x000E   // vàng
#define COLOR_CYAN     0x000B   // xanh lam
#define COLOR_RED      0x000C   // đỏ
#define COLOR_MAGENTA  0x000D   // tím

// ═════════════════════════════════════════════════════════════
// Callbacks — giống Bước 4
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
// ReceiveLoop — giống Bước 4
// ═════════════════════════════════════════════════════════════
static HRESULT ReceiveLoop(CTX* ctx)
{
    PCWSTR streamNames[2] = { L"stdout", L"stderr" };
    WSMAN_STREAM_ID_SET streams = { 2, streamNames };

    while (!ctx->bCmdDone)
    {
        if (ctx->pChunk) { free(ctx->pChunk); ctx->pChunk = NULL; ctx->cbChunk = 0; }
        ResetEvent(ctx->hEvent);

        WSMAN_SHELL_ASYNC a = { ctx, OnChunkReceived };
        WSMAN_OPERATION_HANDLE hOp = NULL;
        WSManReceiveShellOutput(ctx->hShell, ctx->hCommand, 0, &streams, &a, &hOp);

        DWORD w = WaitForSingleObject(ctx->hEvent, TIMEOUT_CMD);
        if (hOp) { WSManCloseOperation(hOp, 0); hOp = NULL; }

        if (w == WAIT_TIMEOUT) { wprintf(L"\n[!] Timeout\n"); break; }

        if (ctx->hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) {
            if (ctx->pChunk && ctx->cbChunk > 0) {
                PrintBytes(ctx->pChunk, ctx->cbChunk);
            }
            break;
        }

        if (FAILED(ctx->hr)) { PrintError(L"ReceiveLoop", ctx->hr); return ctx->hr; }

        if (ctx->pChunk && ctx->cbChunk > 0)
            PrintBytes(ctx->pChunk, ctx->cbChunk);
    }

    return S_OK;
}

// ═════════════════════════════════════════════════════════════
// SessionOpen / SessionClose — giống Bước 4, thêm lưu ip/user/pass
// ═════════════════════════════════════════════════════════════
static HRESULT SessionOpen(SESSION* s)
{
    // Giữ ip/user/pass (đã được set bởi caller)
    LPCWSTR ip = s->ip;
    LPCWSTR user = s->user;
    LPCWSTR pass = s->pass;

    s->hAPI = NULL;
    s->hSession = NULL;

    HRESULT hr = WSManInitialize(WSMAN_FLAG_REQUESTED_API_VERSION_1_1, &s->hAPI);
    if (FAILED(hr)) { PrintError(L"WSManInitialize", hr); return hr; }

    WSMAN_USERNAME_PASSWORD_CREDS creds = { user, pass };
    WSMAN_AUTHENTICATION_CREDENTIALS auth = {};
    auth.authenticationMechanism = WSMAN_FLAG_AUTH_NEGOTIATE;
    auth.userAccount = creds;

    WCHAR endpoint[256];
    StringCchPrintfW(endpoint, ARRAYSIZE(endpoint),
        L"http://%s:5985/wsman", ip);

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

// ═════════════════════════════════════════════════════════════
// RunCmd — giống Bước 4, trả thêm output vào buffer tùy chọn
//
// ppOutBuf: nếu không NULL → lưu output vào đây (caller free)
//           nếu NULL       → chỉ in ra console
// ═════════════════════════════════════════════════════════════
static HRESULT RunCmd(SESSION* s, LPCWSTR cmd,
    DWORD* pExitCode,
    char** ppOutBuf, DWORD* pOutLen)
{
    HRESULT hr = S_OK;
    CTX ctx = {};
    ctx.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ctx.hEvent) return E_OUTOFMEMORY;

    // ASYNC 1: Shell
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

    // ASYNC 2: Command
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

    // ASYNC 3: Receive
    hr = ReceiveLoop(&ctx);

    if (pExitCode) *pExitCode = ctx.exitCode;

    // Nếu caller muốn lưu output thay vì in
    // (dùng để lấy hostname, cwd...)
    if (ppOutBuf && pOutLen && ctx.pChunk) {
        *ppOutBuf = ctx.pChunk;
        *pOutLen = ctx.cbChunk;
        ctx.pChunk = NULL;   // tránh free ở cleanup
    }

cleanup:
    if (ctx.pChunk)   free(ctx.pChunk);
    if (ctx.hCommand) WSManCloseCommand(ctx.hCommand, 0, NULL);
    if (ctx.hShell)   WSManCloseShell(ctx.hShell, 0, NULL);
    if (ctx.hEvent)   CloseHandle(ctx.hEvent);
    return hr;
}

// ═════════════════════════════════════════════════════════════
// History — MỚI ở Bước 5
// ═════════════════════════════════════════════════════════════

// Thêm lệnh vào history (bỏ qua nếu trùng lệnh vừa rồi)
static void HistoryAdd(SHELL_STATE* st, LPCWSTR cmd)
{
    if (!cmd || cmd[0] == L'\0') return;

    // Không lưu nếu trùng lệnh cuối
    if (st->historyCount > 0 &&
        wcscmp(st->history[st->historyCount - 1], cmd) == 0)
        return;

    if (st->historyCount < MAX_HISTORY) {
        StringCchCopyW(st->history[st->historyCount], 512, cmd);
        st->historyCount++;
    }
    else {
        // Dịch chuyển lên 1, bỏ lệnh cũ nhất
        for (int i = 0; i < MAX_HISTORY - 1; i++)
            StringCchCopyW(st->history[i], 512, st->history[i + 1]);
        StringCchCopyW(st->history[MAX_HISTORY - 1], 512, cmd);
    }

    st->historyPos = st->historyCount;  // reset vị trí duyệt
}

// ═════════════════════════════════════════════════════════════
// ReadLineWithHistory — MỚI ở Bước 5
//
// Đọc input từ user, hỗ trợ phím ↑↓ để duyệt history
//
// Cách hoạt động:
//   Console thường đọc cả dòng (ReadLine)
//   Muốn bắt phím ↑↓ cần chuyển sang Raw mode:
//     GetConsoleMode → tắt ENABLE_LINE_INPUT + ENABLE_ECHO_INPUT
//     → đọc từng ký tự bằng ReadConsoleInputW
//     → xử lý phím đặc biệt thủ công
// ═════════════════════════════════════════════════════════════
static BOOL ReadLineWithHistory(SHELL_STATE* st,
    WCHAR* buf, int maxLen)
{
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);

    // Lưu mode cũ để restore sau
    DWORD oldMode;
    GetConsoleMode(hIn, &oldMode);

    // Raw mode: tắt line buffering và echo
    SetConsoleMode(hIn, ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT);

    int  len = 0;          // độ dài hiện tại
    int  cursor = 0;       // vị trí con trỏ trong buf
    BOOL done = FALSE;
    BOOL eof = FALSE;

    ZeroMemory(buf, maxLen * sizeof(WCHAR));

    // Hàm nội bộ: vẽ lại dòng input từ đầu
    // (xóa dòng cũ rồi in lại)
    auto Redraw = [&]() {
        // Lùi về đầu dòng
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hOut, &csbi);
        COORD pos = { 0, csbi.dwCursorPosition.Y };
        SetConsoleCursorPosition(hOut, pos);

        // Xóa dòng
        DWORD written;
        FillConsoleOutputCharacterW(hOut, L' ',
            csbi.dwSize.X, pos, &written);
        SetConsoleCursorPosition(hOut, pos);

        // In lại prompt + buf
        // (prompt đã được in trước khi gọi hàm này,
        //  nên chỉ cần in buf)
        DWORD w;
        WriteConsoleW(hOut, buf, len, &w, NULL);

        // Di chuyển cursor đến vị trí đúng
        GetConsoleScreenBufferInfo(hOut, &csbi);
        pos = csbi.dwCursorPosition;
        pos.X = (SHORT)(pos.X - (len - cursor));
        SetConsoleCursorPosition(hOut, pos);
        };

    while (!done) {
        INPUT_RECORD rec;
        DWORD nRead;
        ReadConsoleInputW(hIn, &rec, 1, &nRead);

        if (rec.EventType != KEY_EVENT || !rec.Event.KeyEvent.bKeyDown)
            continue;

        WORD vk = rec.Event.KeyEvent.wVirtualKeyCode;
        WCHAR ch = rec.Event.KeyEvent.uChar.UnicodeChar;

        if (vk == VK_RETURN) {
            // Enter → kết thúc nhập
            buf[len] = L'\0';
            wprintf(L"\n");
            done = TRUE;
        }
        else if (vk == VK_BACK) {
            // Backspace → xóa ký tự trước cursor
            if (cursor > 0) {
                memmove(buf + cursor - 1, buf + cursor,
                    (len - cursor) * sizeof(WCHAR));
                cursor--;
                len--;
                buf[len] = L'\0';
                Redraw();
            }
        }
        else if (vk == VK_DELETE) {
            // Delete → xóa ký tự tại cursor
            if (cursor < len) {
                memmove(buf + cursor, buf + cursor + 1,
                    (len - cursor - 1) * sizeof(WCHAR));
                len--;
                buf[len] = L'\0';
                Redraw();
            }
        }
        else if (vk == VK_LEFT && cursor > 0) {
            cursor--;
            Redraw();
        }
        else if (vk == VK_RIGHT && cursor < len) {
            cursor++;
            Redraw();
        }
        else if (vk == VK_UP) {
            // ↑ → lệnh cũ hơn trong history
            if (st->historyPos > 0) {
                st->historyPos--;
                StringCchCopyW(buf, maxLen,
                    st->history[st->historyPos]);
                len = (int)wcslen(buf);
                cursor = len;
                Redraw();
            }
        }
        else if (vk == VK_DOWN) {
            // ↓ → lệnh mới hơn trong history
            if (st->historyPos < st->historyCount - 1) {
                st->historyPos++;
                StringCchCopyW(buf, maxLen,
                    st->history[st->historyPos]);
                len = (int)wcslen(buf);
                cursor = len;
                Redraw();
            }
            else {
                // Cuối history → dòng trống
                st->historyPos = st->historyCount;
                ZeroMemory(buf, maxLen * sizeof(WCHAR));
                len = cursor = 0;
                Redraw();
            }
        }
        else if (vk == VK_HOME) {
            cursor = 0;
            Redraw();
        }
        else if (vk == VK_END) {
            cursor = len;
            Redraw();
        }
        else if (ch >= 0x20 && len < maxLen - 1) {
            // Ký tự bình thường → chèn vào vị trí cursor
            memmove(buf + cursor + 1, buf + cursor,
                (len - cursor) * sizeof(WCHAR));
            buf[cursor] = ch;
            cursor++;
            len++;
            buf[len] = L'\0';
            Redraw();
        }
        else if (vk == VK_ESCAPE) {
            // Escape → xóa cả dòng
            ZeroMemory(buf, maxLen * sizeof(WCHAR));
            len = cursor = 0;
            Redraw();
        }
        else if (ch == 0x03) {
            // Ctrl+C → thoát
            eof = TRUE;
            done = TRUE;
        }
    }

    // Restore mode cũ
    SetConsoleMode(hIn, oldMode);
    return !eof;
}

// ═════════════════════════════════════════════════════════════
// GetCwd — MỚI ở Bước 5
//
// Lấy thư mục hiện tại thực sự từ máy đích
// Chạy lệnh "cd" (không có arg) → trả về đường dẫn
// ═════════════════════════════════════════════════════════════
static void GetCwd(SESSION* s, SHELL_STATE* st)
{
    char* buf = NULL;
    DWORD  len = 0;

    // Chạy "cd" không có arg → in ra thư mục hiện tại
    // ppOutBuf mode: không in ra console, lưu vào buf
    HRESULT hr = RunCmd(s, L"cd", NULL, &buf, &len);
    if (SUCCEEDED(hr) && buf && len > 0) {
        // Convert OEM → Wide + trim \r\n
        WCHAR wide[512] = {};
        MultiByteToWideChar(CP_OEMCP, 0, buf, len, wide, ARRAYSIZE(wide));
        // Xóa \r\n cuối
        for (int i = (int)wcslen(wide) - 1; i >= 0; i--) {
            if (wide[i] == L'\r' || wide[i] == L'\n')
                wide[i] = L'\0';
            else break;
        }
        StringCchCopyW(st->cwd, ARRAYSIZE(st->cwd), wide);
        free(buf);
    }
}

// ═════════════════════════════════════════════════════════════
// PrintPrompt — MỚI ở Bước 5
//
// In prompt có màu:
//   [3] DESKTOP-ABC | C:\Users\Administrator>
//    ↑       ↑               ↑
//  cmd#   hostname          cwd
// ═════════════════════════════════════════════════════════════
static void PrintPrompt(const SHELL_STATE* st)
{
    // Số thứ tự lệnh — màu vàng
    SetColor(COLOR_YELLOW);
    wprintf(L"[%d] ", st->cmdCount + 1);

    // Hostname — màu xanh lam
    SetColor(COLOR_CYAN);
    wprintf(L"%s", st->hostname);

    // Separator
    SetColor(COLOR_NORMAL);
    wprintf(L" | ");

    // Thư mục hiện tại — màu xanh lá
    SetColor(COLOR_GREEN);
    wprintf(L"%s", st->cwd[0] ? st->cwd : L"?");

    // Dấu > — màu trắng
    SetColor(COLOR_NORMAL);
    wprintf(L"> ");
}

// ═════════════════════════════════════════════════════════════
// HandleBuiltin — MỚI ở Bước 5
//
// Xử lý các lệnh đặc biệt không cần gửi lên server:
//   help    → in danh sách lệnh
//   history → in lịch sử
//   clear   → xóa màn hình
//   exit    → thoát
//
// Trả về TRUE nếu đã xử lý (không cần gửi lên server)
//         FALSE nếu cần gửi lên server bình thường
// ═════════════════════════════════════════════════════════════
static BOOL HandleBuiltin(LPCWSTR cmd, SHELL_STATE* st, BOOL* pShouldExit)
{
    *pShouldExit = FALSE;

    if (_wcsicmp(cmd, L"exit") == 0 ||
        _wcsicmp(cmd, L"quit") == 0) {
        *pShouldExit = TRUE;
        return TRUE;
    }

    if (_wcsicmp(cmd, L"clear") == 0 ||
        _wcsicmp(cmd, L"cls") == 0) {
        system("cls");
        return TRUE;
    }

    if (_wcsicmp(cmd, L"history") == 0) {
        SetColor(COLOR_YELLOW);
        wprintf(L"\n  Lich su lenh:\n");
        SetColor(COLOR_NORMAL);
        for (int i = 0; i < st->historyCount; i++)
            wprintf(L"  %3d  %s\n", i + 1, st->history[i]);
        wprintf(L"\n");
        return TRUE;
    }

    if (_wcsicmp(cmd, L"help") == 0) {
        SetColor(COLOR_CYAN);
        wprintf(L"\n  ┌─────────────────────────────────────────┐\n");
        wprintf(L"  │  Lenh dac biet (xu ly local, khong gui) │\n");
        wprintf(L"  ├─────────────────────────────────────────┤\n");
        wprintf(L"  │  help      in trang nay                 │\n");
        wprintf(L"  │  history   xem lich su lenh             │\n");
        wprintf(L"  │  clear     xoa man hinh                 │\n");
        wprintf(L"  │  exit      thoat shell                  │\n");
        wprintf(L"  ├─────────────────────────────────────────┤\n");
        wprintf(L"  │  Phim tat                               │\n");
        wprintf(L"  │  ↑ ↓       duyet lich su lenh           │\n");
        wprintf(L"  │  ← →       di chuyen trong dong         │\n");
        wprintf(L"  │  Home/End  dau / cuoi dong              │\n");
        wprintf(L"  │  Del       xoa ky tu tai cursor         │\n");
        wprintf(L"  │  Esc       xoa ca dong                  │\n");
        wprintf(L"  │  Ctrl+C    thoat                        │\n");
        wprintf(L"  └─────────────────────────────────────────┘\n\n");
        SetColor(COLOR_NORMAL);
        return TRUE;
    }

    return FALSE;  // không phải builtin → gửi lên server
}

// ═════════════════════════════════════════════════════════════
// TryReconnect — MỚI ở Bước 5
//
// Khi RunCmd thất bại → thử kết nối lại tối đa MAX_RECONNECT lần
// ═════════════════════════════════════════════════════════════
static BOOL TryReconnect(SESSION* s)
{
    SessionClose(s);

    for (int attempt = 1; attempt <= MAX_RECONNECT; attempt++) {
        SetColor(COLOR_YELLOW);
        wprintf(L"\n[*] Reconnect lan %d/%d...\n", attempt, MAX_RECONNECT);
        SetColor(COLOR_NORMAL);

        Sleep(1000 * attempt);  // chờ lâu hơn mỗi lần

        HRESULT hr = SessionOpen(s);
        if (SUCCEEDED(hr)) {
            SetColor(COLOR_GREEN);
            wprintf(L"[+] Reconnect thanh cong!\n\n");
            SetColor(COLOR_NORMAL);
            return TRUE;
        }

        SetColor(COLOR_RED);
        wprintf(L"[!] That bai: 0x%08X\n", (UINT)hr);
        SetColor(COLOR_NORMAL);
    }

    return FALSE;
}

// ═════════════════════════════════════════════════════════════
// ModeShell — TRÁI TIM của Bước 5
// ═════════════════════════════════════════════════════════════
static void ModeShell(LPCWSTR ip, LPCWSTR user, LPCWSTR pass)
{
    // ── Kết nối ───────────────────────────────────────────────
    SESSION s = {};
    s.ip = ip;
    s.user = user;
    s.pass = pass;

    SetColor(COLOR_CYAN);
    wprintf(L"\n[*] Dang ket noi toi %s...\n", ip);
    SetColor(COLOR_NORMAL);

    HRESULT hr = SessionOpen(&s);
    if (FAILED(hr)) {
        SetColor(COLOR_RED);
        wprintf(L"[!] Khong the ket noi.\n");
        SetColor(COLOR_NORMAL);
        return;
    }

    // ── Khởi tạo SHELL_STATE ──────────────────────────────────
    SHELL_STATE st = {};

    // Lấy hostname
    {
        char* buf = NULL; DWORD len = 0;
        hr = RunCmd(&s, L"hostname", NULL, &buf, &len);
        if (SUCCEEDED(hr) && buf) {
            WCHAR wide[64] = {};
            MultiByteToWideChar(CP_OEMCP, 0, buf, len, wide, ARRAYSIZE(wide));
            // Trim \r\n
            for (int i = (int)wcslen(wide) - 1; i >= 0; i--) {
                if (wide[i] == L'\r' || wide[i] == L'\n') wide[i] = L'\0'; else break;
            }
            StringCchCopyW(st.hostname, ARRAYSIZE(st.hostname), wide);
            free(buf);
        }
    }
    if (st.hostname[0] == L'\0')
        StringCchCopyW(st.hostname, ARRAYSIZE(st.hostname), ip);

    // Lấy cwd ban đầu
    GetCwd(&s, &st);

    // ── Banner ────────────────────────────────────────────────
    SetColor(COLOR_CYAN);
    wprintf(L"\n╔══════════════════════════════════════════════════╗\n");
    wprintf(L"║  WinRM Shell  →  %-30s  ║\n", st.hostname);
    wprintf(L"║  Go 'help' de xem lenh dac biet                 ║\n");
    wprintf(L"║  Go 'exit' hoac Ctrl+C de thoat                 ║\n");
    wprintf(L"╚══════════════════════════════════════════════════╝\n\n");
    SetColor(COLOR_NORMAL);

    // ── Vòng lặp REPL ─────────────────────────────────────────
    WCHAR cmdBuf[512];

    while (TRUE)
    {
        // In prompt có màu
        PrintPrompt(&st);

        // Đọc input (hỗ trợ ↑↓ history)
        if (!ReadLineWithHistory(&st, cmdBuf, ARRAYSIZE(cmdBuf)))
            break;  // Ctrl+C

        // Bỏ qua dòng trống
        if (cmdBuf[0] == L'\0') continue;

        // Lưu vào history
        HistoryAdd(&st, cmdBuf);

        // Kiểm tra builtin (exit, help, history, clear)
        BOOL shouldExit = FALSE;
        if (HandleBuiltin(cmdBuf, &st, &shouldExit)) {
            if (shouldExit) break;
            continue;
        }

        // ── Gửi lệnh lên server ───────────────────────────────
        DWORD exitCode = 0;
        ULONGLONG t0 = GetTickCount64();

        wprintf(L"\n");
        hr = RunCmd(&s, cmdBuf, &exitCode, NULL, NULL);
        ULONGLONG elapsed = GetTickCount64() - t0;

        // ── Xử lý kết quả ─────────────────────────────────────
        if (FAILED(hr)) {
            SetColor(COLOR_RED);
            wprintf(L"\n[!] Loi: 0x%08X\n", (UINT)hr);
            SetColor(COLOR_NORMAL);

            // Thử reconnect
            if (!TryReconnect(&s)) {
                wprintf(L"[!] Khong the reconnect. Thoat.\n");
                break;
            }
            // Sau reconnect, lấy lại cwd
            GetCwd(&s, &st);
            continue;
        }

        // Cập nhật trạng thái
        st.cmdCount++;
        st.lastExitCode = exitCode;

        // Cập nhật cwd nếu lệnh là cd
        // (cd trên WinRM không giữ state giữa các lần RunCmd,
        //  nhưng ta giả lập bằng cách lấy lại cwd sau mỗi lệnh cd)
        if (_wcsnicmp(cmdBuf, L"cd", 2) == 0)
            GetCwd(&s, &st);

        // In dòng trạng thái phía dưới output
        wprintf(L"\n");
        SetColor(exitCode == 0 ? COLOR_GREEN : COLOR_RED);
        wprintf(L"  [exit:%lu | %llums]",
            exitCode, elapsed);
        SetColor(COLOR_NORMAL);
        wprintf(L"\n\n");
    }

    // ── Thoát ─────────────────────────────────────────────────
    SetColor(COLOR_YELLOW);
    wprintf(L"\n[*] Thoat shell. Tam biet!\n");
    SetColor(COLOR_NORMAL);

    SessionClose(&s);
}

// ═════════════════════════════════════════════════════════════
// wmain
// ═════════════════════════════════════════════════════════════
int wmain(int argc, WCHAR* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    if (argc < 4) {
        wprintf(L"Dung: step5.exe <IP> <user> <pass>\n");
        wprintf(L"VD  : step5.exe 192.168.1.100 Administrator P@ssword\n");
        return 1;
    }

    ModeShell(argv[1], argv[2], argv[3]);
    return 0;
}