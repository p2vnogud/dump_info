#define WSMAN_API_VERSION_1_1
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <wsman.h>
#include <stdio.h>

#pragma comment(lib, "Wsmsvc.lib")

// ─────────────────────────────────────────────────────────────
// CTX — "hộp thư" truyền dữ liệu giữa code chính và callback
// ─────────────────────────────────────────────────────────────
// Vì sao cần CTX?
//
//   Code chính                      Callback (thread khác)
//       │                                  │
//       │── gửi request ──────────────>    │
//       │── chờ (WaitForSingleObject) ─>🔒 │
//       │                                  │── có kết quả
//       │                                  │── lưu vào CTX
//       │<── SetEvent ──────────────────── │── bật đèn xanh
//       │🔓 tiếp tục, đọc kết quả từ CTX  │
//
typedef struct {
    HANDLE             hEvent;    // "cái đèn" để đồng bộ
    HRESULT            hr;        // kết quả: thành công hay thất bại
    WSMAN_SHELL_HANDLE hShell;    // handle của shell khi tạo xong
} CTX;

// ─────────────────────────────────────────────────────────────
// Callback — Windows tự gọi hàm này khi có kết quả
// ─────────────────────────────────────────────────────────────
// Quy tắc: KHÔNG được làm việc nặng ở đây
//          Chỉ: lưu kết quả vào CTX → bật đèn xanh → thoát
//
void CALLBACK OnShellCreated(
    PVOID                  pCtx,      // con trỏ tới CTX của mình
    DWORD                  flags,
    WSMAN_ERROR* pError,
    WSMAN_SHELL_HANDLE     hShell,    // shell vừa được tạo
    WSMAN_COMMAND_HANDLE   hCmd,      // không dùng ở bước này
    WSMAN_OPERATION_HANDLE hOp,       // không dùng ở bước này
    WSMAN_RESPONSE_DATA* pData)     // không dùng ở bước này
{
    CTX* c = (CTX*)pCtx;   // lấy lại CTX của mình từ con trỏ void

    // Có lỗi không?
    if (pError && pError->code != 0) {
        c->hr = HRESULT_FROM_WIN32(pError->code);
        wprintf(L"[Callback] Loi: code=%u, %s\n",
            pError->code,
            pError->errorDetail ? pError->errorDetail : L"(no detail)");
    }
    else {
        c->hr = S_OK;    // thành công
        c->hShell = hShell;  // lưu handle shell để dùng sau
    }

    // 🟢 Bật đèn xanh → code chính tiếp tục chạy
    SetEvent(c->hEvent);
}

// ─────────────────────────────────────────────────────────────
// wmain — điểm vào chương trình
// ─────────────────────────────────────────────────────────────
int wmain(int argc, WCHAR* argv[])
{
    // ── Kiểm tra tham số ─────────────────────────────────────
    if (argc < 4) {
        wprintf(L"Dung: step1.exe <IP> <user> <pass>\n");
        wprintf(L"VD  : step1.exe 192.168.1.100 Administrator P@ssword\n");
        return 1;
    }

    LPCWSTR ip = argv[1];
    LPCWSTR user = argv[2];
    LPCWSTR pass = argv[3];

    // ── Bước A: Khởi động WinRM engine ───────────────────────
    // Giống như "cắm điện máy fax trước khi gửi fax"
    WSMAN_API_HANDLE hAPI = NULL;
    HRESULT hr = WSManInitialize(WSMAN_FLAG_REQUESTED_API_VERSION_1_1, &hAPI);
    if (FAILED(hr)) {
        wprintf(L"[!] WSManInitialize that bai: 0x%08X\n", (UINT)hr);
        return 1;
    }
    wprintf(L"[+] WinRM engine khoi dong OK\n");

    // ── Bước B: Tạo session (đăng nhập) ──────────────────────
    // Điền thông tin credentials
    WSMAN_USERNAME_PASSWORD_CREDS creds;
    creds.username = user;
    creds.password = pass;

    WSMAN_AUTHENTICATION_CREDENTIALS auth = {};
    //auth.authenticationMechanism = WSMAN_FLAG_AUTH_BASIC; // dùng Basic cho lab
    auth.authenticationMechanism = WSMAN_FLAG_AUTH_NEGOTIATE;
    auth.userAccount = creds;

    // Xây URL endpoint: http://192.168.1.100:5985/wsman
    WCHAR endpoint[256];
    swprintf_s(endpoint, ARRAYSIZE(endpoint),
        L"http://%s:5985/wsman", ip);
    wprintf(L"[*] Ket noi toi: %s\n", endpoint);

    WSMAN_SESSION_HANDLE hSession = NULL;
    hr = WSManCreateSession(
        hAPI,       // engine đã khởi động
        endpoint,   // địa chỉ máy đích
        0,          // flags (0 = mặc định)
        &auth,      // thông tin đăng nhập
        NULL,       // proxy (không dùng)
        &hSession   // [OUT] handle session
    );
    if (FAILED(hr)) {
        wprintf(L"[!] WSManCreateSession that bai: 0x%08X\n", (UINT)hr);
        WSManDeinitialize(hAPI, 0);
        return 1;
    }
    wprintf(L"[+] Session tao OK\n");

    // Cho phép HTTP không mã hóa (bắt buộc với lab workgroup)
    WSMAN_DATA opt = {};
    opt.type = WSMAN_DATA_TYPE_DWORD;
    opt.number = 1;
    WSManSetSessionOption(hSession,
        (WSManSessionOption)3, // WSMAN_OPTION_UNENCRYPTED_MESSAGES
        &opt);

    // ── Bước C: Tạo Shell (mở cmd.exe trên máy đích) ─────────
    // Đây là lệnh ASYNC → cần CTX + callback

    // C1: Tạo CTX với "đèn đỏ"
    CTX ctx = {};
    ctx.hEvent = CreateEvent(
        NULL,   // security attributes (mặc định)
        FALSE,  // auto-reset: tự về đỏ sau khi được đọc
        FALSE,  // trạng thái ban đầu: ĐỎ (chưa xong)
        NULL    // tên event (NULL = không tên)
    );

    // C2: Đóng gói callback
    // WSMAN_SHELL_ASYNC nói với WinRM:
    //   "Khi xong thì gọi hàm OnShellCreated, truyền &ctx vào"
    WSMAN_SHELL_ASYNC asyncInfo;
    asyncInfo.operationContext = &ctx;        // truyền CTX vào callback
    asyncInfo.completionFunction = OnShellCreated; // hàm sẽ được gọi

    // C3: Gửi request tạo shell
    WSMAN_SHELL_HANDLE hShell = NULL;
    wprintf(L"[*] Dang tao shell tren may dich...\n");
    WSManCreateShell(
        hSession,     // session đã đăng nhập
        0,            // flags
        // URI định nghĩa loại shell (cmd.exe)
        L"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
        NULL,         // startup info
        NULL,         // options
        NULL,         // connect XML
        &asyncInfo,   // callback info
        &hShell       // [OUT] handle (chưa dùng được ngay, phải chờ)
    );

    // C4: 🔴 Đứng chờ đèn xanh (tối đa 15 giây)
    wprintf(L"[*] Dang cho ket qua (toi da 15s)...\n");
    DWORD waitResult = WaitForSingleObject(ctx.hEvent, 15000);

    if (waitResult == WAIT_TIMEOUT) {
        wprintf(L"[!] Timeout! May dich khong phan hoi.\n");
        goto cleanup;
    }

    // C5: Kiểm tra kết quả trong CTX
    if (FAILED(ctx.hr)) {
        wprintf(L"[!] Tao shell that bai: 0x%08X\n", (UINT)ctx.hr);
        goto cleanup;
    }

    // 🎉 Thành công!
    wprintf(L"\n");
    wprintf(L"╔══════════════════════════════════════╗\n");
    wprintf(L"║  ✓ CONNECTED THANH CONG!             ║\n");
    wprintf(L"║  Shell da mo tren: %-18s║\n", ip);
    wprintf(L"╚══════════════════════════════════════╝\n");
    wprintf(L"\n[*] hShell = %p (se dung o buoc tiep theo)\n", ctx.hShell);

cleanup:
    // ── Dọn dẹp — theo thứ tự NGƯỢC lại lúc tạo ─────────────
    // Shell → Session → API
    if (ctx.hShell) WSManCloseShell(ctx.hShell, 0, NULL);
    if (hSession)   WSManCloseSession(hSession, 0);
    if (hAPI)       WSManDeinitialize(hAPI, 0);
    if (ctx.hEvent) CloseHandle(ctx.hEvent);

    wprintf(L"[*] Dong ket noi OK.\n");
    return SUCCEEDED(ctx.hr) ? 0 : 1;
}
