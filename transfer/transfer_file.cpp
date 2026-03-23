/*
 * 1. CopyFileW: copy, xcopy
 * 2. CreateFile + Read/Write: type, findstr >out, esentutl /y, makecab input
 * 3. expand (LZExpand API): expand, extrac32 (cabinet)
 * 4. URLDownloadToFile: certutil -urlcache
 * 5. WinHTTP: curl, powershell wget
 * 6. BITS (Background Intelligent Transfer Service)
 */
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>
#include <winhttp.h>
#include <urlmon.h>
#include <lzexpand.h>
#include <bits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
 /* ─────────────────────────────────────────────────────────────────────────────
  * Utility helpers
  * ───────────────────────────────────────────────────────────────────────────*/
static void print_last_error(const char* ctx)
{
    DWORD err = GetLastError();
    char buf[512];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, 0, buf, sizeof(buf), NULL);
    fprintf(stderr, "[ERROR] %s — 0x%08X: %s\n", ctx, err, buf);
}
static void print_hresult(const char* ctx, HRESULT hr)
{
    fprintf(stderr, "[ERROR] %s — HRESULT 0x%08X\n", ctx, (unsigned)hr);
}
/* ─────────────────────────────────────────────────────────────────────────────
 * 1. CopyFileW
 * ───────────────────────────────────────────────────────────────────────────*/
BOOL method_copyfile(LPCWSTR src, LPCWSTR dst)
{
    wprintf(L"[CopyFileW] %s → %s\n", src, dst);
    if (!CopyFileW(src, dst, FALSE)) {
        print_last_error("CopyFileW");
        return FALSE;
    }
    wprintf(L"[CopyFileW] OK\n");
    return TRUE;
}
/* ─────────────────────────────────────────────────────────────────────────────
 * 2. CreateFile + ReadFile + WriteFile
 * ───────────────────────────────────────────────────────────────────────────*/
BOOL method_readwrite(LPCWSTR src, LPCWSTR dst)
{
    wprintf(L"[ReadFile/WriteFile] %s → %s\n", src, dst);
    HANDLE hSrc = CreateFileW(src, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) {
        print_last_error("CreateFileW(src)");
        return FALSE;
    }
    HANDLE hDst = CreateFileW(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDst == INVALID_HANDLE_VALUE) {
        print_last_error("CreateFileW(dst)");
        CloseHandle(hSrc);
        return FALSE;
    }
    const DWORD CHUNK = 65536;
    BYTE* buf = (BYTE*)malloc(CHUNK);
    DWORD bytesRead, bytesWritten;
    BOOL ok = TRUE;
    ULONGLONG total = 0;
    while (ReadFile(hSrc, buf, CHUNK, &bytesRead, NULL) && bytesRead > 0) {
        if (!WriteFile(hDst, buf, bytesRead, &bytesWritten, NULL) || bytesWritten != bytesRead) {
            print_last_error("WriteFile");
            ok = FALSE;
            break;
        }
        total += bytesRead;
    }
    free(buf);
    CloseHandle(hSrc);
    CloseHandle(hDst);
    if (ok) wprintf(L"[ReadFile/WriteFile] OK — %llu bytes\n", total);
    return ok;
}
/* ─────────────────────────────────────────────────────────────────────────────
 * 3. LZExpand API
 * ───────────────────────────────────────────────────────────────────────────*/
BOOL method_lzexpand(LPCSTR src_a, LPCSTR dst_a)
{
    printf("[LZExpand] %s → %s\n", src_a, dst_a);
    OFSTRUCT ofSrc = { 0 }, ofDst = { 0 };
    INT hSrc = LZOpenFileA((LPSTR)src_a, &ofSrc, OF_READ);
    if (hSrc < 0) {
        fprintf(stderr, "[ERROR] LZOpenFile(src) returned %d\n", hSrc);
        return FALSE;
    }
    INT hDst = LZOpenFileA((LPSTR)dst_a, &ofDst, OF_CREATE);
    if (hDst < 0) {
        fprintf(stderr, "[ERROR] LZOpenFile(dst) returned %d\n", hDst);
        LZClose(hSrc);
        return FALSE;
    }
    LONG result = LZCopy(hSrc, hDst);
    LZClose(hSrc);
    LZClose(hDst);
    if (result < 0) {
        fprintf(stderr, "[ERROR] LZCopy returned %ld\n", result);
        return FALSE;
    }
    printf("[LZExpand] OK — %ld bytes\n", result);
    return TRUE;
}
/* ─────────────────────────────────────────────────────────────────────────────
 * 4. URLDownloadToFile
 * ───────────────────────────────────────────────────────────────────────────*/
BOOL method_urldownload(LPCWSTR url, LPCWSTR dst)
{
    wprintf(L"[URLDownloadToFile] %s → %s\n", url, dst);
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        print_hresult("CoInitializeEx", hr);
        return FALSE;
    }
    hr = URLDownloadToFileW(NULL, url, dst, 0, NULL);
    CoUninitialize();
    if (FAILED(hr)) {
        print_hresult("URLDownloadToFile", hr);
        return FALSE;
    }
    wprintf(L"[URLDownloadToFile] OK\n");
    return TRUE;
}
/* ─────────────────────────────────────────────────────────────────────────────
 * 5. WinHTTP (ĐÃ SỬA – KHÔNG DÙNG GOTO)
 * ───────────────────────────────────────────────────────────────────────────*/
BOOL method_winhttp(LPCWSTR host, INTERNET_PORT port, LPCWSTR path, LPCWSTR dst)
{
    wprintf(L"[WinHTTP] http://%s:%u%s → %s\n", host, port, path, dst);

    HINTERNET hSession = WinHttpOpen(
        L"WinAPI-Transfer/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession) {
        print_last_error("WinHttpOpen");
        return FALSE;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
    if (!hConnect) {
        print_last_error("WinHttpConnect");
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0
    );
    if (!hRequest) {
        print_last_error("WinHttpOpenRequest");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    if (!WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        print_last_error("WinHttpSendRequest");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        print_last_error("WinHttpReceiveResponse");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    /* Đọc status code */
    DWORD statusCode = 0;
    DWORD statusLen = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode, &statusLen, WINHTTP_NO_HEADER_INDEX);

    if (statusCode != 200) {
        fprintf(stderr, "[WinHTTP] HTTP status %lu\n", statusCode);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    /* Ghi vào file */
    HANDLE hFile = CreateFileW(dst, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        print_last_error("CreateFileW(dst)");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    /* Đọc và ghi dữ liệu */
    {
        BYTE chunk[65536];
        DWORD bytesRead, bytesWritten;
        ULONGLONG total = 0;
        BOOL ok = TRUE;

        while (WinHttpReadData(hRequest, chunk, sizeof(chunk), &bytesRead) &&
            bytesRead > 0) {
            if (!WriteFile(hFile, chunk, bytesRead, &bytesWritten, NULL)) {
                print_last_error("WriteFile");
                ok = FALSE;
                break;
            }
            total += bytesRead;
        }
        if (ok) wprintf(L"[WinHTTP] OK — %llu bytes\n", total);
    }

    CloseHandle(hFile);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return TRUE;
}
/* ─────────────────────────────────────────────────────────────────────────────
 * 6. BITS (ĐÃ SỬA – KHÔNG DÙNG GOTO)
 * ───────────────────────────────────────────────────────────────────────────*/
BOOL method_bits(LPCWSTR url, LPCWSTR dst)
{
    wprintf(L"[BITS] %s → %s\n", url, dst);

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return FALSE;
    }

    IBackgroundCopyManager* pMgr = NULL;
    IBackgroundCopyJob* pJob = NULL;
    GUID jobId;

    hr = CoCreateInstance(__uuidof(BackgroundCopyManager),
        NULL, CLSCTX_LOCAL_SERVER,
        __uuidof(IBackgroundCopyManager),
        (void**)&pMgr);
    if (FAILED(hr)) {
        print_hresult("CoCreateInstance(BITS)", hr);
        CoUninitialize();
        return FALSE;
    }

    hr = pMgr->CreateJob(L"WinAPI-Transfer", BG_JOB_TYPE_DOWNLOAD, &jobId, &pJob);
    if (FAILED(hr)) {
        print_hresult("CreateJob", hr);
        pMgr->Release();
        CoUninitialize();
        return FALSE;
    }

    hr = pJob->AddFile(url, dst);
    if (FAILED(hr)) {
        print_hresult("AddFile", hr);
        pJob->Release();
        pMgr->Release();
        CoUninitialize();
        return FALSE;
    }

    hr = pJob->Resume();
    if (FAILED(hr)) {
        print_hresult("Resume", hr);
        pJob->Release();
        pMgr->Release();
        CoUninitialize();
        return FALSE;
    }

    /* Poll trạng thái */
    wprintf(L"[BITS] Waiting");
    BOOL ok = FALSE;
    while (TRUE) {
        BG_JOB_STATE state;
        pJob->GetState(&state);

        if (state == BG_JOB_STATE_TRANSFERRED) {
            pJob->Complete();
            wprintf(L"\n[BITS] OK\n");
            ok = TRUE;
            break;
        }
        if (state == BG_JOB_STATE_ERROR || state == BG_JOB_STATE_TRANSIENT_ERROR) {
            wprintf(L"\n[BITS] Job error\n");
            pJob->Cancel();
            break;
        }
        wprintf(L".");
        Sleep(500);
    }

    if (pJob) pJob->Release();
    if (pMgr) pMgr->Release();
    CoUninitialize();
    return ok;
}
/* ─────────────────────────────────────────────────────────────────────────────
 * main — demo tất cả các method
 * ───────────────────────────────────────────────────────────────────────────*/
int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2) {
        wprintf(
            L"Usage:\n"
            L" transfer.exe smb <\\\\server\\share\\src> <dst>\n"
            L" transfer.exe rw <\\\\server\\share\\src> <dst>\n"
            L" transfer.exe lz <src> <dst>\n"
            L" transfer.exe url <http://...> <dst>\n"
            L" transfer.exe winhttp <host> <port> <path> <dst>\n"
            L" transfer.exe bits <http://...> <dst>\n"
            L"\nExamples (mimic các LOLBin):\n"
            L" transfer.exe smb \\\\192.168.119.20\\share\\test.txt out1.txt\n"
            L" transfer.exe rw \\\\192.168.119.20\\share\\test.txt out2.txt\n"
            L" transfer.exe url http://192.168.119.30:8080/test.txt out3.txt\n"
            L" transfer.exe winhttp 192.168.119.30 8080 /test.txt out4.txt\n"
            L" transfer.exe bits http://192.168.119.30:8080/test.txt out5.txt\n"
        );
        return 1;
    }

    LPCWSTR method = argv[1];
    if (wcscmp(method, L"smb") == 0 && argc >= 4)
        return method_copyfile(argv[2], argv[3]) ? 0 : 1;
    if (wcscmp(method, L"rw") == 0 && argc >= 4)
        return method_readwrite(argv[2], argv[3]) ? 0 : 1;
    if (wcscmp(method, L"lz") == 0 && argc >= 4) {
        char src_a[MAX_PATH], dst_a[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, argv[2], -1, src_a, MAX_PATH, NULL, NULL);
        WideCharToMultiByte(CP_ACP, 0, argv[3], -1, dst_a, MAX_PATH, NULL, NULL);
        return method_lzexpand(src_a, dst_a) ? 0 : 1;
    }
    if (wcscmp(method, L"url") == 0 && argc >= 4)
        return method_urldownload(argv[2], argv[3]) ? 0 : 1;
    if (wcscmp(method, L"winhttp") == 0 && argc >= 6) {
        INTERNET_PORT port = (INTERNET_PORT)_wtoi(argv[3]);
        return method_winhttp(argv[2], port, argv[4], argv[5]) ? 0 : 1;
    }
    if (wcscmp(method, L"bits") == 0 && argc >= 4)
        return method_bits(argv[2], argv[3]) ? 0 : 1;

    wprintf(L"[ERROR] Unknown method or wrong argument count\n");
    return 1;
}