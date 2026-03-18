/*
 * MyRegTool - Registry Tool với hỗ trợ Remote
 * Hỗ trợ thao tác registry cục bộ VÀ từ xa qua Win32 API
 *
 * Cú pháp mới (remote):
 *   myregtool <ACTION> <KEY> [options...] /target <hostname> /user <username> /pass <password>
 *
 * Ví dụ:
 *   myregtool QUERY HKLM\Software\Microsoft /s /target 192.168.1.10 /user admin /pass secret
 *   myregtool ADD HKLM\Software\MyApp /v Version /t REG_SZ /d "1.0" /f /target 192.168.1.10 /user admin /pass secret
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <fcntl.h>
#include <io.h>


#pragma comment (lib, "Mpr.lib")

 // ============================================================
 //  Hằng số & Macro
 // ============================================================

#define MAX_KEY_LENGTH   256
#define MAX_VALUE_NAME   16383
#define MAX_DATA_SIZE    (1024 * 1024)   // 1 MB
#define MAX_HOST_LEN     256
#define MAX_CRED_LEN     512

// ============================================================
//  Cấu trúc thông tin kết nối Remote
// ============================================================

typedef struct {
    BOOL   isRemote;
    wchar_t target[MAX_HOST_LEN];    // hostname hoặc IP
    wchar_t username[MAX_CRED_LEN];  // domain\user hoặc user
    wchar_t password[MAX_CRED_LEN];
    BOOL   connected;                // đã xác thực IPC$ chưa
} RemoteInfo;

// ============================================================
//  In lỗi Win32 ra stderr
// ============================================================

static void PrintError(const wchar_t* prefix, LONG code)
{
    wchar_t buf[512] = { 0 };
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, (DWORD)code, 0, buf, 512, NULL);
    fwprintf(stderr, L"[ERROR] %s: %s (code=%ld)\n", prefix, buf, code);
}

// ============================================================
//  Kết nối IPC$ tới máy target (xác thực SMB)
//  Dùng WNetAddConnection2W để mount \\target\IPC$
// ============================================================

static BOOL ConnectRemoteIPC(RemoteInfo* ri)
{
    if (!ri->isRemote) return TRUE;
    if (ri->connected) return TRUE;

    // Xây UNC path \\target\IPC$
    wchar_t uncPath[MAX_HOST_LEN + 8];
    _snwprintf_s(uncPath, ARRAYSIZE(uncPath), _TRUNCATE, L"\\\\%s\\IPC$", ri->target);

    NETRESOURCEW nr = { 0 };
    nr.dwType = RESOURCETYPE_ANY;
    nr.lpLocalName = NULL;          // không map drive
    nr.lpRemoteName = uncPath;
    nr.lpProvider = NULL;

    // Truyền username/password để xác thực
    const wchar_t* user = (ri->username[0]) ? ri->username : NULL;
    const wchar_t* pass = (ri->password[0]) ? ri->password : NULL;

    // Thử xóa kết nối cũ trước (tránh lỗi ERROR_SESSION_CREDENTIAL_CONFLICT)
    WNetCancelConnection2W(uncPath, 0, TRUE);

    DWORD rc = WNetAddConnection2W(&nr, pass, user, 0);
    if (rc == NO_ERROR || rc == ERROR_ALREADY_ASSIGNED || rc == ERROR_SESSION_CREDENTIAL_CONFLICT) {
        wprintf(L"[INFO] Đã kết nối IPC$ tới %s\n", ri->target);
        ri->connected = TRUE;
        return TRUE;
    }

    // ERROR_SESSION_CREDENTIAL_CONFLICT: đã có session, thử dùng luôn
    if (rc == ERROR_SESSION_CREDENTIAL_CONFLICT) {
        wprintf(L"[WARN] Đã có session tới %s, sử dụng session hiện tại.\n", ri->target);
        ri->connected = TRUE;
        return TRUE;
    }

    fwprintf(stderr, L"[ERROR] Không thể kết nối IPC$ tới '%s' với user '%s': ",
        ri->target, ri->username[0] ? ri->username : L"(current user)");
    PrintError(L"WNetAddConnection2W", (LONG)rc);
    return FALSE;
}

// ============================================================
//  Ngắt kết nối IPC$
// ============================================================

static void DisconnectRemoteIPC(RemoteInfo* ri)
{
    if (!ri->isRemote || !ri->connected) return;

    wchar_t uncPath[MAX_HOST_LEN + 8];
    _snwprintf_s(uncPath, ARRAYSIZE(uncPath), _TRUNCATE, L"\\\\%s\\IPC$", ri->target);
    WNetCancelConnection2W(uncPath, 0, FALSE);
    ri->connected = FALSE;
    wprintf(L"[INFO] Đã ngắt kết nối IPC$ tới %s\n", ri->target);
}

// ============================================================
//  Mở root key - hỗ trợ local VÀ remote
//  Remote: dùng RegConnectRegistryW để lấy handle HKEY từ xa
// ============================================================

typedef struct {
    HKEY   hRootLocal;   // HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, ...
    HKEY   hRootActual;  // handle thực tế (local = hRootLocal, remote = handle kết nối)
    BOOL   isRemote;
} RootKeyHandle;

static void CloseRootKeyHandle(RootKeyHandle* rkh)
{
    if (rkh->isRemote && rkh->hRootActual != NULL &&
        rkh->hRootActual != rkh->hRootLocal)
    {
        RegCloseKey(rkh->hRootActual);
        rkh->hRootActual = NULL;
    }
}

// ============================================================
//  Parse root key từ chuỗi
// ============================================================

static HKEY ParseRootKey(const wchar_t* s, const wchar_t** remainder)
{
    struct { const wchar_t* name; HKEY key; } table[] = {
        { L"HKLM",                  HKEY_LOCAL_MACHINE  },
        { L"HKEY_LOCAL_MACHINE",    HKEY_LOCAL_MACHINE  },
        { L"HKCU",                  HKEY_CURRENT_USER   },
        { L"HKEY_CURRENT_USER",     HKEY_CURRENT_USER   },
        { L"HKCR",                  HKEY_CLASSES_ROOT   },
        { L"HKEY_CLASSES_ROOT",     HKEY_CLASSES_ROOT   },
        { L"HKU",                   HKEY_USERS          },
        { L"HKEY_USERS",            HKEY_USERS          },
        { L"HKCC",                  HKEY_CURRENT_CONFIG },
        { L"HKEY_CURRENT_CONFIG",   HKEY_CURRENT_CONFIG },
    };
    for (int i = 0; i < (int)(sizeof(table) / sizeof(table[0])); i++) {
        size_t n = wcslen(table[i].name);
        if (_wcsnicmp(s, table[i].name, n) == 0) {
            if (s[n] == L'\\' || s[n] == L'\0') {
                if (remainder) *remainder = (s[n] == L'\\') ? s + n + 1 : s + n;
                return table[i].key;
            }
        }
    }
    if (remainder) *remainder = s;
    return NULL;
}

static BOOL SplitKeyPath(const wchar_t* full, HKEY* hRoot, wchar_t* subKey, int subKeyLen)
{
    const wchar_t* rest = NULL;
    *hRoot = ParseRootKey(full, &rest);
    if (*hRoot == NULL) {
        fwprintf(stderr, L"[ERROR] Root key không hợp lệ: %s\n", full);
        return FALSE;
    }
    wcsncpy_s(subKey, subKeyLen, rest, _TRUNCATE);
    return TRUE;
}

// ============================================================
//  Lấy root key handle - kết nối remote nếu cần
// ============================================================

static BOOL GetRootKeyHandle(HKEY hRootLocal, RemoteInfo* ri, RootKeyHandle* out)
{
    out->hRootLocal = hRootLocal;
    out->isRemote = ri->isRemote;

    if (!ri->isRemote) {
        out->hRootActual = hRootLocal;
        return TRUE;
    }

    // Kết nối IPC$ để xác thực
    if (!ConnectRemoteIPC(ri)) return FALSE;

    // Kết nối registry remote
    LONG rc = RegConnectRegistryW(ri->target, hRootLocal, &out->hRootActual);
    if (rc != ERROR_SUCCESS) {
        PrintError(L"RegConnectRegistryW", rc);
        return FALSE;
    }
    return TRUE;
}

// ============================================================
//  Parse tham số /target, /user, /pass từ argv
//  Trả về số lượng tham số đã tiêu thụ (để loại khỏi argv khi xử lý tiếp)
// ============================================================

static void ParseRemoteArgs(int argc, wchar_t* argv[], RemoteInfo* ri)
{
    memset(ri, 0, sizeof(RemoteInfo));
    for (int i = 0; i < argc; i++) {
        if (_wcsicmp(argv[i], L"/target") == 0 && i + 1 < argc) {
            // Hỗ trợ cả "hostname" lẫn "\\hostname"
            const wchar_t* t = argv[i + 1];
            if (t[0] == L'\\' && t[1] == L'\\') t += 2;
            wcsncpy_s(ri->target, ARRAYSIZE(ri->target), t, _TRUNCATE);
            ri->isRemote = TRUE;
            i++;
        }
        else if (_wcsicmp(argv[i], L"/user") == 0 && i + 1 < argc) {
            wcsncpy_s(ri->username, ARRAYSIZE(ri->username), argv[i + 1], _TRUNCATE);
            i++;
        }
        else if ((_wcsicmp(argv[i], L"/pass") == 0 || _wcsicmp(argv[i], L"/password") == 0)
            && i + 1 < argc) {
            wcsncpy_s(ri->password, ARRAYSIZE(ri->password), argv[i + 1], _TRUNCATE);
            i++;
        }
    }
}

// Lọc argv: loại bỏ /target, /user, /pass và giá trị của chúng
// Trả về argc mới
static int FilterRemoteArgs(int argc, wchar_t* argv[], wchar_t** newArgv)
{
    int newArgc = 0;
    for (int i = 0; i < argc; i++) {
        if ((_wcsicmp(argv[i], L"/target") == 0 ||
            _wcsicmp(argv[i], L"/user") == 0 ||
            _wcsicmp(argv[i], L"/pass") == 0 ||
            _wcsicmp(argv[i], L"/password") == 0) && i + 1 < argc) {
            i++; // bỏ cả tham số tiếp theo
        }
        else {
            newArgv[newArgc++] = argv[i];
        }
    }
    return newArgc;
}

// ============================================================
//  Kiểu dữ liệu registry
// ============================================================

static DWORD ParseType(const wchar_t* s)
{
    if (_wcsicmp(s, L"REG_SZ") == 0) return REG_SZ;
    if (_wcsicmp(s, L"REG_EXPAND_SZ") == 0) return REG_EXPAND_SZ;
    if (_wcsicmp(s, L"REG_MULTI_SZ") == 0) return REG_MULTI_SZ;
    if (_wcsicmp(s, L"REG_DWORD") == 0) return REG_DWORD;
    if (_wcsicmp(s, L"REG_QWORD") == 0) return REG_QWORD;
    if (_wcsicmp(s, L"REG_BINARY") == 0) return REG_BINARY;
    if (_wcsicmp(s, L"REG_NONE") == 0) return REG_NONE;
    return REG_SZ;
}

static const wchar_t* TypeName(DWORD type)
{
    switch (type) {
    case REG_SZ:        return L"REG_SZ";
    case REG_EXPAND_SZ: return L"REG_EXPAND_SZ";
    case REG_MULTI_SZ:  return L"REG_MULTI_SZ";
    case REG_DWORD:     return L"REG_DWORD";
    case REG_QWORD:     return L"REG_QWORD";
    case REG_BINARY:    return L"REG_BINARY";
    case REG_NONE:      return L"REG_NONE";
    default:            return L"REG_UNKNOWN";
    }
}

// ============================================================
//  In giá trị registry
// ============================================================

static void PrintValue(const wchar_t* name, DWORD type, const BYTE* data, DWORD dataSize)
{
    const wchar_t* displayName = (name == NULL || name[0] == L'\0') ? L"(Default)" : name;
    wprintf(L"    %-30s  %-15s  ", displayName, TypeName(type));

    switch (type) {
    case REG_SZ:
    case REG_EXPAND_SZ:
        wprintf(L"%s", (dataSize >= 2) ? (const wchar_t*)data : L"");
        break;

    case REG_MULTI_SZ: {
        const wchar_t* p = (const wchar_t*)data;
        BOOL first = TRUE;
        while (p && *p) {
            if (!first) wprintf(L"\\0");
            wprintf(L"%s", p);
            p += wcslen(p) + 1;
            first = FALSE;
        }
        break;
    }

    case REG_DWORD:
        if (dataSize >= 4) {
            DWORD val; memcpy(&val, data, 4);
            wprintf(L"0x%08x (%u)", val, val);
        }
        break;

    case REG_QWORD:
        if (dataSize >= 8) {
            ULONGLONG val; memcpy(&val, data, 8);
            wprintf(L"0x%016llx (%llu)", val, val);
        }
        break;

    case REG_BINARY:
        for (DWORD i = 0; i < dataSize; i++) wprintf(L"%02x ", data[i]);
        break;

    default:
        wprintf(L"<binary data, %u bytes>", dataSize);
        break;
    }
    wprintf(L"\n");
}

// ============================================================
//  CMD: QUERY
// ============================================================

static void QueryKeyRecursive(HKEY hKey, const wchar_t* path, BOOL recursive);

static int CmdQuery(int argc, wchar_t* argv[], RemoteInfo* ri)
{
    if (argc < 2) {
        wprintf(L"Cú pháp: myregtool QUERY <KeyName> [/v Tên | /ve] [/s] [/target host /user u /pass p]\n");
        return 1;
    }

    const wchar_t* keyPath = argv[1];
    const wchar_t* valueName = NULL;
    BOOL  valueDefault = FALSE;
    BOOL  recursive = FALSE;

    for (int i = 2; i < argc; i++) {
        if (_wcsicmp(argv[i], L"/s") == 0) recursive = TRUE;
        else if (_wcsicmp(argv[i], L"/ve") == 0) valueDefault = TRUE;
        else if (_wcsicmp(argv[i], L"/v") == 0 && i + 1 < argc) valueName = argv[++i];
    }

    HKEY  hRootLocal;
    wchar_t subKey[MAX_KEY_LENGTH * 4];
    if (!SplitKeyPath(keyPath, &hRootLocal, subKey, ARRAYSIZE(subKey))) return 1;

    RootKeyHandle rkh;
    if (!GetRootKeyHandle(hRootLocal, ri, &rkh)) return 1;

    HKEY hKey;
    // KEY_WOW64_64KEY: đọc đúng hive 64-bit, tránh redirect Wow6432Node
    LONG rc = RegOpenKeyExW(rkh.hRootActual, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (rc != ERROR_SUCCESS) {
        PrintError(L"RegOpenKeyExW", rc);
        CloseRootKeyHandle(&rkh);
        return 1;
    }

    if (ri->isRemote)
        wprintf(L"\n[Remote: %s] %s\n", ri->target, keyPath);
    else
        wprintf(L"\n%s\n", keyPath);

    if (valueName || valueDefault) {
        const wchar_t* vn = valueDefault ? L"" : valueName;
        DWORD type = 0, dataSize = MAX_DATA_SIZE;
        BYTE* data = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dataSize);
        if (data) {
            rc = RegQueryValueExW(hKey, vn, NULL, &type, data, &dataSize);
            if (rc == ERROR_SUCCESS)
                PrintValue(vn, type, data, dataSize);
            else
                PrintError(L"RegQueryValueExW", rc);
            HeapFree(GetProcessHeap(), 0, data);
        }
    }
    else {
        QueryKeyRecursive(hKey, keyPath, recursive);
    }

    RegCloseKey(hKey);
    CloseRootKeyHandle(&rkh);
    return 0;
}

static void QueryKeyRecursive(HKEY hKey, const wchar_t* path, BOOL recursive)
{
    DWORD valueCount = 0, maxValueName = 0, maxData = 0;
    RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL,
        &valueCount, &maxValueName, &maxData, NULL, NULL);

    BYTE* data = (BYTE*)HeapAlloc(GetProcessHeap(), 0, maxData + 2);
    wchar_t* vName = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (maxValueName + 2) * sizeof(wchar_t));

    for (DWORD i = 0; i < valueCount; i++) {
        DWORD nameLen = maxValueName + 1, dataSize = maxData + 2, type = 0;
        if (RegEnumValueW(hKey, i, vName, &nameLen, NULL, &type, data, &dataSize) == ERROR_SUCCESS)
            PrintValue(vName, type, data, dataSize);
    }
    HeapFree(GetProcessHeap(), 0, data);
    HeapFree(GetProcessHeap(), 0, vName);

    if (recursive) {
        DWORD subCount = 0, maxSubKey = 0;
        RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &subCount, &maxSubKey, NULL, NULL, NULL, NULL, NULL, NULL);
        wchar_t* skName = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (maxSubKey + 2) * sizeof(wchar_t));
        for (DWORD i = 0; i < subCount; i++) {
            DWORD skLen = maxSubKey + 1;
            if (RegEnumKeyExW(hKey, i, skName, &skLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                wchar_t fullPath[MAX_KEY_LENGTH * 8];
                _snwprintf_s(fullPath, ARRAYSIZE(fullPath), _TRUNCATE, L"%s\\%s", path, skName);
                wprintf(L"\n%s\n", fullPath);
                HKEY hSub;
                if (RegOpenKeyExW(hKey, skName, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                    QueryKeyRecursive(hSub, fullPath, TRUE);
                    RegCloseKey(hSub);
                }
            }
        }
        HeapFree(GetProcessHeap(), 0, skName);
    }
}

// ============================================================
//  CMD: ADD
// ============================================================

static int CmdAdd(int argc, wchar_t* argv[], RemoteInfo* ri)
{
    if (argc < 2) {
        wprintf(L"Cú pháp: myregtool ADD <KeyName> [/v Tên] [/ve] [/t Kiểu] [/d DữLiệu] [/f] [/target host /user u /pass p]\n");
        return 1;
    }

    const wchar_t* keyPath = argv[1];
    const wchar_t* valueName = NULL;
    const wchar_t* typeStr = L"REG_SZ";
    const wchar_t* dataStr = L"";
    BOOL  valueDefault = FALSE;
    BOOL  force = FALSE;

    for (int i = 2; i < argc; i++) {
        if (_wcsicmp(argv[i], L"/f") == 0) force = TRUE;
        else if (_wcsicmp(argv[i], L"/ve") == 0) valueDefault = TRUE;
        else if (_wcsicmp(argv[i], L"/v") == 0 && i + 1 < argc) valueName = argv[++i];
        else if (_wcsicmp(argv[i], L"/t") == 0 && i + 1 < argc) typeStr = argv[++i];
        else if (_wcsicmp(argv[i], L"/d") == 0 && i + 1 < argc) dataStr = argv[++i];
    }

    HKEY  hRootLocal;
    wchar_t subKey[MAX_KEY_LENGTH * 4];
    if (!SplitKeyPath(keyPath, &hRootLocal, subKey, ARRAYSIZE(subKey))) return 1;

    RootKeyHandle rkh;
    if (!GetRootKeyHandle(hRootLocal, ri, &rkh)) return 1;

    // KEY_WOW64_64KEY: bắt buộc khi ghi vào HKLM trên máy 64-bit qua remote,
    // tránh bị redirect vào Wow6432Node
    HKEY  hKey;
    DWORD disposition;
    LONG rc = RegCreateKeyExW(rkh.hRootActual, subKey, 0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE | KEY_WOW64_64KEY,
        NULL, &hKey, &disposition);
    if (rc != ERROR_SUCCESS) {
        PrintError(L"RegCreateKeyExW", rc);
        CloseRootKeyHandle(&rkh);
        return 1;
    }

    if (ri->isRemote)
        wprintf(L"[Remote: %s] ", ri->target);

    if (disposition == REG_CREATED_NEW_KEY)
        wprintf(L"Đã tạo key mới: %s\n", keyPath);
    else
        wprintf(L"Key đã tồn tại: %s\n", keyPath);

    if (!valueName && !valueDefault) {
        RegCloseKey(hKey);
        CloseRootKeyHandle(&rkh);
        return 0;
    }

    const wchar_t* vn = valueDefault ? L"" : valueName;
    DWORD          type = ParseType(typeStr);

    // Cấp phát trên heap - KHÔNG dùng stack (1MB sẽ gây stack overflow)
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_DATA_SIZE);
    if (!buf) {
        fwprintf(stderr, L"[ERROR] Không đủ bộ nhớ.\n");
        RegCloseKey(hKey);
        CloseRootKeyHandle(&rkh);
        return 1;
    }
    DWORD dataSize = 0;

    switch (type) {
    case REG_SZ:
    case REG_EXPAND_SZ: {
        dataSize = (DWORD)((wcslen(dataStr) + 1) * sizeof(wchar_t));
        memcpy(buf, dataStr, dataSize);
        break;
    }
    case REG_MULTI_SZ: {
        size_t len = wcslen(dataStr);
        memcpy(buf, dataStr, len * sizeof(wchar_t));
        ((wchar_t*)buf)[len] = L'\0';
        ((wchar_t*)buf)[len + 1] = L'\0';
        dataSize = (DWORD)((len + 2) * sizeof(wchar_t));
        break;
    }
    case REG_DWORD: {
        DWORD val = (DWORD)wcstoul(dataStr, NULL, 0);
        memcpy(buf, &val, sizeof(DWORD));
        dataSize = sizeof(DWORD);
        break;
    }
    case REG_QWORD: {
        ULONGLONG val = wcstoull(dataStr, NULL, 0);
        memcpy(buf, &val, sizeof(ULONGLONG));
        dataSize = sizeof(ULONGLONG);
        break;
    }
    case REG_BINARY: {
        const wchar_t* p = dataStr;
        while (*p) {
            while (*p == L' ') p++;
            if (!*p) break;
            wchar_t hex[3] = { p[0], p[1] ? p[1] : L'0', L'\0' };
            buf[dataSize++] = (BYTE)wcstoul(hex, NULL, 16);
            p += 2;
        }
        break;
    }
    default: dataSize = 0; break;
    }

    if (!force) {
        DWORD existType;
        if (RegQueryValueExW(hKey, vn, NULL, &existType, NULL, NULL) == ERROR_SUCCESS) {
            wprintf(L"Giá trị đã tồn tại. Ghi đè? (Y/N): ");
            wchar_t ch = (wchar_t)getwchar();
            if (ch != L'Y' && ch != L'y') {
                wprintf(L"Hủy bỏ.\n");
                HeapFree(GetProcessHeap(), 0, buf);
                RegCloseKey(hKey);
                CloseRootKeyHandle(&rkh);
                return 0;
            }
        }
    }

    rc = RegSetValueExW(hKey, vn, 0, type, buf, dataSize);
    if (rc == ERROR_SUCCESS)
        wprintf(L"Đã set giá trị '%s' thành công.\n", vn[0] ? vn : L"(Default)");
    else
        PrintError(L"RegSetValueExW", rc);

    HeapFree(GetProcessHeap(), 0, buf);
    RegCloseKey(hKey);
    CloseRootKeyHandle(&rkh);
    return (rc == ERROR_SUCCESS) ? 0 : 1;
}

// ============================================================
//  CMD: DELETE
// ============================================================

static LONG DeleteKeyRecursive(HKEY hRoot, const wchar_t* subKey);

static int CmdDelete(int argc, wchar_t* argv[], RemoteInfo* ri)
{
    if (argc < 2) {
        wprintf(L"Cú pháp: myregtool DELETE <KeyName> [/v Tên | /ve | /va] [/f] [/target host /user u /pass p]\n");
        return 1;
    }

    const wchar_t* keyPath = argv[1];
    const wchar_t* valueName = NULL;
    BOOL  valueDefault = FALSE;
    BOOL  deleteAllValues = FALSE;
    BOOL  force = FALSE;

    for (int i = 2; i < argc; i++) {
        if (_wcsicmp(argv[i], L"/f") == 0) force = TRUE;
        else if (_wcsicmp(argv[i], L"/ve") == 0) valueDefault = TRUE;
        else if (_wcsicmp(argv[i], L"/va") == 0) deleteAllValues = TRUE;
        else if (_wcsicmp(argv[i], L"/v") == 0 && i + 1 < argc) valueName = argv[++i];
    }

    HKEY  hRootLocal;
    wchar_t subKey[MAX_KEY_LENGTH * 4];
    if (!SplitKeyPath(keyPath, &hRootLocal, subKey, ARRAYSIZE(subKey))) return 1;

    if (!force) {
        if (ri->isRemote)
            wprintf(L"Bạn có chắc muốn xóa '%s' trên %s? (Y/N): ", keyPath, ri->target);
        else
            wprintf(L"Bạn có chắc muốn xóa '%s'? (Y/N): ", keyPath);
        wchar_t ch = (wchar_t)getwchar();
        if (ch != L'Y' && ch != L'y') { wprintf(L"Hủy bỏ.\n"); return 0; }
    }

    RootKeyHandle rkh;
    if (!GetRootKeyHandle(hRootLocal, ri, &rkh)) return 1;

    LONG rc = ERROR_SUCCESS;

    if (valueName || valueDefault) {
        HKEY hKey;
        rc = RegOpenKeyExW(rkh.hRootActual, subKey, 0, KEY_SET_VALUE, &hKey);
        if (rc != ERROR_SUCCESS) { PrintError(L"RegOpenKeyExW", rc); CloseRootKeyHandle(&rkh); return 1; }
        const wchar_t* vn = valueDefault ? L"" : valueName;
        rc = RegDeleteValueW(hKey, vn);
        if (rc == ERROR_SUCCESS) wprintf(L"Đã xóa giá trị '%s'.\n", vn[0] ? vn : L"(Default)");
        else PrintError(L"RegDeleteValueW", rc);
        RegCloseKey(hKey);
    }
    else if (deleteAllValues) {
        HKEY hKey;
        rc = RegOpenKeyExW(rkh.hRootActual, subKey, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey);
        if (rc != ERROR_SUCCESS) { PrintError(L"RegOpenKeyExW", rc); CloseRootKeyHandle(&rkh); return 1; }
        wchar_t vName[MAX_VALUE_NAME];
        DWORD vLen;
        while (TRUE) {
            vLen = MAX_VALUE_NAME;
            if (RegEnumValueW(hKey, 0, vName, &vLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            RegDeleteValueW(hKey, vName);
        }
        RegCloseKey(hKey);
        wprintf(L"Đã xóa tất cả giá trị trong '%s'.\n", keyPath);
    }
    else {
        rc = DeleteKeyRecursive(rkh.hRootActual, subKey);
        if (rc == ERROR_SUCCESS) wprintf(L"Đã xóa key '%s' thành công.\n", keyPath);
        else PrintError(L"DeleteKeyRecursive", rc);
    }

    CloseRootKeyHandle(&rkh);
    return (rc == ERROR_SUCCESS) ? 0 : 1;
}

static LONG DeleteKeyRecursive(HKEY hRoot, const wchar_t* subKey)
{
    HKEY hKey;
    LONG rc = RegOpenKeyExW(hRoot, subKey, 0, KEY_READ | KEY_WRITE, &hKey);
    if (rc != ERROR_SUCCESS) return rc;

    wchar_t childName[MAX_KEY_LENGTH];
    DWORD   childLen;
    while (TRUE) {
        childLen = MAX_KEY_LENGTH;
        if (RegEnumKeyExW(hKey, 0, childName, &childLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        wchar_t childPath[MAX_KEY_LENGTH * 8];
        _snwprintf_s(childPath, ARRAYSIZE(childPath), _TRUNCATE, L"%s\\%s", subKey, childName);
        DeleteKeyRecursive(hRoot, childPath);
    }
    RegCloseKey(hKey);
    return RegDeleteKeyW(hRoot, subKey);
}

// ============================================================
//  CMD: COPY
// ============================================================

static LONG CopyKeyRecursive(HKEY hSrc, HKEY hDst);

static int CmdCopy(int argc, wchar_t* argv[], RemoteInfo* ri)
{
    if (argc < 3) {
        wprintf(L"Cú pháp: myregtool COPY <KeyNguồn> <KeyĐích> [/s] [/f] [/target host /user u /pass p]\n");
        return 1;
    }

    HKEY  hRoot1, hRoot2;
    wchar_t subKey1[MAX_KEY_LENGTH * 4], subKey2[MAX_KEY_LENGTH * 4];
    if (!SplitKeyPath(argv[1], &hRoot1, subKey1, ARRAYSIZE(subKey1))) return 1;
    if (!SplitKeyPath(argv[2], &hRoot2, subKey2, ARRAYSIZE(subKey2))) return 1;

    // Nguồn và đích đều dùng cùng remote (nếu có)
    RootKeyHandle rkh1, rkh2;
    if (!GetRootKeyHandle(hRoot1, ri, &rkh1)) return 1;
    if (!GetRootKeyHandle(hRoot2, ri, &rkh2)) { CloseRootKeyHandle(&rkh1); return 1; }

    HKEY hSrc;
    LONG rc = RegOpenKeyExW(rkh1.hRootActual, subKey1, 0, KEY_READ, &hSrc);
    if (rc != ERROR_SUCCESS) { PrintError(L"Mở key nguồn", rc); CloseRootKeyHandle(&rkh1); CloseRootKeyHandle(&rkh2); return 1; }

    HKEY hDst;
    DWORD disp;
    rc = RegCreateKeyExW(rkh2.hRootActual, subKey2, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hDst, &disp);
    if (rc != ERROR_SUCCESS) {
        PrintError(L"Tạo key đích", rc);
        RegCloseKey(hSrc);
        CloseRootKeyHandle(&rkh1); CloseRootKeyHandle(&rkh2);
        return 1;
    }

    rc = CopyKeyRecursive(hSrc, hDst);
    if (rc == ERROR_SUCCESS)
        wprintf(L"Đã sao chép '%s' -> '%s' thành công.\n", argv[1], argv[2]);
    else
        PrintError(L"CopyKeyRecursive", rc);

    RegCloseKey(hSrc);
    RegCloseKey(hDst);
    CloseRootKeyHandle(&rkh1);
    CloseRootKeyHandle(&rkh2);
    return (rc == ERROR_SUCCESS) ? 0 : 1;
}

static LONG CopyKeyRecursive(HKEY hSrc, HKEY hDst)
{
    DWORD valueCount, maxValName, maxData, subCount, maxSubKey;
    LONG rc = RegQueryInfoKeyW(hSrc, NULL, NULL, NULL,
        &subCount, &maxSubKey, NULL, &valueCount, &maxValName, &maxData, NULL, NULL);
    if (rc != ERROR_SUCCESS) return rc;

    BYTE* data = (BYTE*)HeapAlloc(GetProcessHeap(), 0, maxData + 4);
    wchar_t* vn = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (maxValName + 2) * sizeof(wchar_t));

    for (DWORD i = 0; i < valueCount; i++) {
        DWORD nameLen = maxValName + 1, dataSize = maxData + 4, type = 0;
        if (RegEnumValueW(hSrc, i, vn, &nameLen, NULL, &type, data, &dataSize) == ERROR_SUCCESS)
            RegSetValueExW(hDst, vn, 0, type, data, dataSize);
    }
    HeapFree(GetProcessHeap(), 0, data);
    HeapFree(GetProcessHeap(), 0, vn);

    wchar_t* skName = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (maxSubKey + 2) * sizeof(wchar_t));
    for (DWORD i = 0; i < subCount; i++) {
        DWORD skLen = maxSubKey + 1;
        if (RegEnumKeyExW(hSrc, i, skName, &skLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY hSubSrc, hSubDst;
            DWORD d;
            if (RegOpenKeyExW(hSrc, skName, 0, KEY_READ, &hSubSrc) == ERROR_SUCCESS) {
                if (RegCreateKeyExW(hDst, skName, 0, NULL, REG_OPTION_NON_VOLATILE,
                    KEY_WRITE, NULL, &hSubDst, &d) == ERROR_SUCCESS) {
                    CopyKeyRecursive(hSubSrc, hSubDst);
                    RegCloseKey(hSubDst);
                }
                RegCloseKey(hSubSrc);
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, skName);
    return ERROR_SUCCESS;
}

// ============================================================
//  CMD: SAVE / RESTORE
// ============================================================

static BOOL EnablePrivilege(const wchar_t* privName)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privName, &luid)) { CloseHandle(hToken); return FALSE; }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(hToken);
    return ok && (GetLastError() == ERROR_SUCCESS);
}

static int CmdSave(int argc, wchar_t* argv[], RemoteInfo* ri)
{
    if (argc < 3) {
        wprintf(L"Cú pháp: myregtool SAVE <KeyName> <TênFile> [/target host /user u /pass p]\n");
        return 1;
    }
    EnablePrivilege(SE_BACKUP_NAME);

    HKEY  hRootLocal;
    wchar_t subKey[MAX_KEY_LENGTH * 4];
    if (!SplitKeyPath(argv[1], &hRootLocal, subKey, ARRAYSIZE(subKey))) return 1;

    RootKeyHandle rkh;
    if (!GetRootKeyHandle(hRootLocal, ri, &rkh)) return 1;

    HKEY hKey;
    LONG rc = RegOpenKeyExW(rkh.hRootActual, subKey, 0, KEY_READ, &hKey);
    if (rc != ERROR_SUCCESS) { PrintError(L"RegOpenKeyExW", rc); CloseRootKeyHandle(&rkh); return 1; }

    rc = RegSaveKeyW(hKey, argv[2], NULL);
    if (rc == ERROR_SUCCESS) wprintf(L"Đã lưu key ra file '%s'.\n", argv[2]);
    else PrintError(L"RegSaveKeyW", rc);

    RegCloseKey(hKey);
    CloseRootKeyHandle(&rkh);
    return (rc == ERROR_SUCCESS) ? 0 : 1;
}

static int CmdRestore(int argc, wchar_t* argv[], RemoteInfo* ri)
{
    if (argc < 3) {
        wprintf(L"Cú pháp: myregtool RESTORE <KeyName> <TênFile> [/target host /user u /pass p]\n");
        return 1;
    }
    EnablePrivilege(SE_RESTORE_NAME);

    HKEY  hRootLocal;
    wchar_t subKey[MAX_KEY_LENGTH * 4];
    if (!SplitKeyPath(argv[1], &hRootLocal, subKey, ARRAYSIZE(subKey))) return 1;

    RootKeyHandle rkh;
    if (!GetRootKeyHandle(hRootLocal, ri, &rkh)) return 1;

    HKEY hKey;
    LONG rc = RegOpenKeyExW(rkh.hRootActual, subKey, 0, KEY_WRITE, &hKey);
    if (rc != ERROR_SUCCESS) { PrintError(L"RegOpenKeyExW", rc); CloseRootKeyHandle(&rkh); return 1; }

    rc = RegRestoreKeyW(hKey, argv[2], 0);
    if (rc == ERROR_SUCCESS) wprintf(L"Đã khôi phục key từ file '%s'.\n", argv[2]);
    else PrintError(L"RegRestoreKeyW", rc);

    RegCloseKey(hKey);
    CloseRootKeyHandle(&rkh);
    return (rc == ERROR_SUCCESS) ? 0 : 1;
}

// ============================================================
//  CMD: EXPORT
// ============================================================

static void ExportKeyToFile(HKEY hKey, const wchar_t* keyPath, FILE* f);

static int CmdExport(int argc, wchar_t* argv[], RemoteInfo* ri)
{
    if (argc < 3) {
        wprintf(L"Cú pháp: myregtool EXPORT <KeyName> <TênFile.reg> [/y] [/target host /user u /pass p]\n");
        return 1;
    }
    BOOL overwrite = FALSE;
    for (int i = 3; i < argc; i++)
        if (_wcsicmp(argv[i], L"/y") == 0) overwrite = TRUE;

    if (!overwrite && GetFileAttributesW(argv[2]) != INVALID_FILE_ATTRIBUTES) {
        wprintf(L"File '%s' đã tồn tại. Ghi đè? (Y/N): ", argv[2]);
        wchar_t ch = (wchar_t)getwchar();
        if (ch != L'Y' && ch != L'y') { wprintf(L"Hủy bỏ.\n"); return 0; }
    }

    HKEY  hRootLocal;
    wchar_t subKey[MAX_KEY_LENGTH * 4];
    if (!SplitKeyPath(argv[1], &hRootLocal, subKey, ARRAYSIZE(subKey))) return 1;

    RootKeyHandle rkh;
    if (!GetRootKeyHandle(hRootLocal, ri, &rkh)) return 1;

    HKEY hKey;
    LONG rc = RegOpenKeyExW(rkh.hRootActual, subKey, 0, KEY_READ, &hKey);
    if (rc != ERROR_SUCCESS) { PrintError(L"RegOpenKeyExW", rc); CloseRootKeyHandle(&rkh); return 1; }

    FILE* f = NULL;
    _wfopen_s(&f, argv[2], L"w, ccs=UTF-8");
    if (!f) {
        fwprintf(stderr, L"[ERROR] Không thể tạo file.\n");
        RegCloseKey(hKey);
        CloseRootKeyHandle(&rkh);
        return 1;
    }

    fwprintf(f, L"Windows Registry Editor Version 5.00\r\n\r\n");
    ExportKeyToFile(hKey, argv[1], f);

    fclose(f);
    RegCloseKey(hKey);
    CloseRootKeyHandle(&rkh);
    wprintf(L"Đã xuất '%s' ra '%s'.\n", argv[1], argv[2]);
    return 0;
}

static void ExportValueToFile(const wchar_t* name, DWORD type, const BYTE* data, DWORD dataSize, FILE* f)
{
    if (name == NULL || name[0] == L'\0')
        fwprintf(f, L"@=");
    else
        fwprintf(f, L"\"%s\"=", name);

    switch (type) {
    case REG_SZ:
        fwprintf(f, L"\"%s\"\r\n", (dataSize >= 2) ? (const wchar_t*)data : L"");
        break;
    case REG_DWORD: {
        DWORD val = 0;
        if (dataSize >= 4) memcpy(&val, data, 4);
        fwprintf(f, L"dword:%08x\r\n", val);
        break;
    }
    default: {
        fwprintf(f, L"hex(%x):", type);
        for (DWORD i = 0; i < dataSize; i++) {
            fwprintf(f, L"%02x", data[i]);
            if (i + 1 < dataSize) fwprintf(f, L",");
        }
        fwprintf(f, L"\r\n");
        break;
    }
    }
}

static void ExportKeyToFile(HKEY hKey, const wchar_t* keyPath, FILE* f)
{
    fwprintf(f, L"[%s]\r\n", keyPath);

    DWORD valueCount, maxValName, maxData, subCount, maxSubKey;
    RegQueryInfoKeyW(hKey, NULL, NULL, NULL,
        &subCount, &maxSubKey, NULL, &valueCount, &maxValName, &maxData, NULL, NULL);

    BYTE* data = (BYTE*)HeapAlloc(GetProcessHeap(), 0, maxData + 4);
    wchar_t* vn = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (maxValName + 2) * sizeof(wchar_t));

    for (DWORD i = 0; i < valueCount; i++) {
        DWORD nameLen = maxValName + 1, dataSize = maxData + 4, type = 0;
        if (RegEnumValueW(hKey, i, vn, &nameLen, NULL, &type, data, &dataSize) == ERROR_SUCCESS)
            ExportValueToFile(vn, type, data, dataSize, f);
    }
    fwprintf(f, L"\r\n");

    HeapFree(GetProcessHeap(), 0, data);
    HeapFree(GetProcessHeap(), 0, vn);

    wchar_t* skName = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (maxSubKey + 2) * sizeof(wchar_t));
    for (DWORD i = 0; i < subCount; i++) {
        DWORD skLen = maxSubKey + 1;
        if (RegEnumKeyExW(hKey, i, skName, &skLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            wchar_t fullPath[MAX_KEY_LENGTH * 8];
            _snwprintf_s(fullPath, ARRAYSIZE(fullPath), _TRUNCATE, L"%s\\%s", keyPath, skName);
            HKEY hSub;
            if (RegOpenKeyExW(hKey, skName, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                ExportKeyToFile(hSub, fullPath, f);
                RegCloseKey(hSub);
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, skName);
}

// ============================================================
//  CMD: IMPORT  (local only - file .reg đọc từ máy chạy tool)
// ============================================================

static int CmdImport(int argc, wchar_t* argv[], RemoteInfo* ri)
{
    if (argc < 2) {
        wprintf(L"Cú pháp: myregtool IMPORT <TênFile.reg> [/target host /user u /pass p]\n");
        return 1;
    }
    FILE* f = NULL;
    _wfopen_s(&f, argv[1], L"r, ccs=UTF-8");
    if (!f) { fwprintf(stderr, L"[ERROR] Không thể mở file '%s'.\n", argv[1]); return 1; }

    // Kết nối IPC$ nếu remote (để xác thực trước khi ghi registry)
    if (ri->isRemote && !ConnectRemoteIPC(ri)) {
        fclose(f);
        return 1;
    }

    wchar_t line[4096];
    HKEY  hKey = NULL;
    HKEY  hCurRoot = NULL;
    wchar_t curSubKey[MAX_KEY_LENGTH * 4] = { 0 };
    RootKeyHandle rkh = { 0 };

    while (fgetws(line, ARRAYSIZE(line), f)) {
        size_t len = wcslen(line);
        while (len > 0 && (line[len - 1] == L'\r' || line[len - 1] == L'\n')) line[--len] = 0;
        if (len == 0 || line[0] == L';') continue;

        if (line[0] == L'[') {
            if (hKey) { RegCloseKey(hKey); hKey = NULL; }
            if (rkh.isRemote && rkh.hRootActual) { CloseRootKeyHandle(&rkh); memset(&rkh, 0, sizeof(rkh)); }

            BOOL deleteKey = (line[1] == L'-');
            wchar_t* start = deleteKey ? line + 2 : line + 1;
            wchar_t* end = wcsrchr(start, L']');
            if (end) *end = 0;

            HKEY hRootLocal;
            if (!SplitKeyPath(start, &hRootLocal, curSubKey, ARRAYSIZE(curSubKey))) continue;

            if (!GetRootKeyHandle(hRootLocal, ri, &rkh)) continue;

            if (deleteKey) {
                DeleteKeyRecursive(rkh.hRootActual, curSubKey);
                wprintf(L"Đã xóa key: [%s]\n", start);
                CloseRootKeyHandle(&rkh);
            }
            else {
                DWORD disp;
                RegCreateKeyExW(rkh.hRootActual, curSubKey, 0, NULL,
                    REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disp);
            }
            continue;
        }

        if (!hKey) continue;

        wchar_t* eq = wcschr(line, L'=');
        if (!eq) continue;
        *eq = 0;
        wchar_t* nameRaw = line;
        wchar_t* valRaw = eq + 1;

        wchar_t vName[MAX_VALUE_NAME];
        if (nameRaw[0] == L'@') {
            vName[0] = 0;
        }
        else {
            wchar_t* s = nameRaw + (nameRaw[0] == L'"' ? 1 : 0);
            wchar_t* e = wcsrchr(s, L'"');
            if (e) *e = 0;
            wcsncpy_s(vName, ARRAYSIZE(vName), s, _TRUNCATE);
        }

        if (valRaw[0] == L'"') {
            wchar_t* s = valRaw + 1;
            wchar_t* e = wcsrchr(s, L'"');
            if (e) *e = 0;
            RegSetValueExW(hKey, vName, 0, REG_SZ,
                (const BYTE*)s, (DWORD)((wcslen(s) + 1) * sizeof(wchar_t)));
        }
        else if (_wcsnicmp(valRaw, L"dword:", 6) == 0) {
            DWORD val = (DWORD)wcstoul(valRaw + 6, NULL, 16);
            RegSetValueExW(hKey, vName, 0, REG_DWORD, (const BYTE*)&val, sizeof(DWORD));
        }
        else if (_wcsnicmp(valRaw, L"hex", 3) == 0) {
            DWORD type = REG_BINARY;
            wchar_t* p = valRaw + 3;
            if (*p == L'(') {
                p++;
                type = (DWORD)wcstoul(p, &p, 16);
                if (*p == L')') p++;
            }
            if (*p == L':') p++;
            BYTE  bytes[MAX_DATA_SIZE];
            DWORD sz = 0;
            while (*p) {
                while (*p == L' ' || *p == L'\\' || *p == L'\r' || *p == L'\n') p++;
                if (!*p) break;
                wchar_t hex[3] = { p[0], (p[1] && p[1] != L',') ? p[1] : L'0', 0 };
                bytes[sz++] = (BYTE)wcstoul(hex, NULL, 16);
                p += 2;
                if (*p == L',') p++;
            }
            RegSetValueExW(hKey, vName, 0, type, bytes, sz);
        }
        else if (_wcsnicmp(valRaw, L"-", 1) == 0) {
            RegDeleteValueW(hKey, vName);
        }
    }

    if (hKey) RegCloseKey(hKey);
    if (rkh.isRemote && rkh.hRootActual) CloseRootKeyHandle(&rkh);
    fclose(f);
    wprintf(L"Import hoàn tất: '%s'\n", argv[1]);
    return 0;
}

// ============================================================
//  CMD: COMPARE
// ============================================================

static int CompareCount = 0;
static void CompareKeys(HKEY hKey1, const wchar_t* path1, HKEY hKey2, const wchar_t* path2, BOOL recursive);

static int CmdCompare(int argc, wchar_t* argv[], RemoteInfo* ri)
{
    if (argc < 3) {
        wprintf(L"Cú pháp: myregtool COMPARE <Key1> <Key2> [/s] [/target host /user u /pass p]\n");
        return 1;
    }
    BOOL recursive = FALSE;
    for (int i = 3; i < argc; i++)
        if (_wcsicmp(argv[i], L"/s") == 0) recursive = TRUE;

    HKEY  hRoot1, hRoot2;
    wchar_t subKey1[MAX_KEY_LENGTH * 4], subKey2[MAX_KEY_LENGTH * 4];
    if (!SplitKeyPath(argv[1], &hRoot1, subKey1, ARRAYSIZE(subKey1))) return 1;
    if (!SplitKeyPath(argv[2], &hRoot2, subKey2, ARRAYSIZE(subKey2))) return 1;

    RootKeyHandle rkh1, rkh2;
    if (!GetRootKeyHandle(hRoot1, ri, &rkh1)) return 1;
    if (!GetRootKeyHandle(hRoot2, ri, &rkh2)) { CloseRootKeyHandle(&rkh1); return 1; }

    HKEY hKey1, hKey2;
    if (RegOpenKeyExW(rkh1.hRootActual, subKey1, 0, KEY_READ, &hKey1) != ERROR_SUCCESS) {
        fwprintf(stderr, L"[ERROR] Không thể mở '%s'\n", argv[1]);
        CloseRootKeyHandle(&rkh1); CloseRootKeyHandle(&rkh2);
        return 1;
    }
    if (RegOpenKeyExW(rkh2.hRootActual, subKey2, 0, KEY_READ, &hKey2) != ERROR_SUCCESS) {
        fwprintf(stderr, L"[ERROR] Không thể mở '%s'\n", argv[2]);
        RegCloseKey(hKey1);
        CloseRootKeyHandle(&rkh1); CloseRootKeyHandle(&rkh2);
        return 1;
    }

    CompareCount = 0;
    CompareKeys(hKey1, argv[1], hKey2, argv[2], recursive);

    RegCloseKey(hKey1);
    RegCloseKey(hKey2);
    CloseRootKeyHandle(&rkh1);
    CloseRootKeyHandle(&rkh2);

    if (CompareCount == 0) wprintf(L"Hai key GIỐNG NHAU.\n");
    else wprintf(L"Tìm thấy %d điểm khác biệt.\n", CompareCount);
    return 0;
}

static void CompareKeys(HKEY hKey1, const wchar_t* path1,
    HKEY hKey2, const wchar_t* path2, BOOL recursive)
{
    DWORD vc1, mx1, md1, vc2, mx2, md2;
    RegQueryInfoKeyW(hKey1, NULL, NULL, NULL, NULL, NULL, NULL, &vc1, &mx1, &md1, NULL, NULL);
    RegQueryInfoKeyW(hKey2, NULL, NULL, NULL, NULL, NULL, NULL, &vc2, &mx2, &md2, NULL, NULL);

    DWORD maxVN = (mx1 > mx2 ? mx1 : mx2) + 2;
    DWORD maxD = (md1 > md2 ? md1 : md2) + 4;

    BYTE* d1 = (BYTE*)HeapAlloc(GetProcessHeap(), 0, maxD);
    BYTE* d2 = (BYTE*)HeapAlloc(GetProcessHeap(), 0, maxD);
    wchar_t* vn1 = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, maxVN * sizeof(wchar_t));

    for (DWORD i = 0; i < vc1; i++) {
        DWORD nl = maxVN, ds1 = maxD, t1 = 0;
        if (RegEnumValueW(hKey1, i, vn1, &nl, NULL, &t1, d1, &ds1) != ERROR_SUCCESS) continue;
        DWORD ds2 = maxD, t2 = 0;
        LONG rc2 = RegQueryValueExW(hKey2, vn1, NULL, &t2, d2, &ds2);
        if (rc2 != ERROR_SUCCESS) {
            wprintf(L"< Chỉ có ở %s: %s\n", path1, vn1[0] ? vn1 : L"(Default)");
            CompareCount++;
        }
        else if (t1 != t2 || ds1 != ds2 || memcmp(d1, d2, ds1) != 0) {
            wprintf(L"! Khác nhau: [%s vs %s] %s\n", path1, path2, vn1[0] ? vn1 : L"(Default)");
            CompareCount++;
        }
    }

    HeapFree(GetProcessHeap(), 0, d1);
    HeapFree(GetProcessHeap(), 0, d2);
    HeapFree(GetProcessHeap(), 0, vn1);

    if (recursive) {
        DWORD sc1, msk1;
        RegQueryInfoKeyW(hKey1, NULL, NULL, NULL, &sc1, &msk1, NULL, NULL, NULL, NULL, NULL, NULL);
        wchar_t* sk = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (msk1 + 2) * sizeof(wchar_t));
        for (DWORD i = 0; i < sc1; i++) {
            DWORD skLen = msk1 + 1;
            if (RegEnumKeyExW(hKey1, i, sk, &skLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                wchar_t fp1[MAX_KEY_LENGTH * 8], fp2[MAX_KEY_LENGTH * 8];
                _snwprintf_s(fp1, ARRAYSIZE(fp1), _TRUNCATE, L"%s\\%s", path1, sk);
                _snwprintf_s(fp2, ARRAYSIZE(fp2), _TRUNCATE, L"%s\\%s", path2, sk);
                HKEY hSub1, hSub2;
                BOOL ok1 = RegOpenKeyExW(hKey1, sk, 0, KEY_READ, &hSub1) == ERROR_SUCCESS;
                BOOL ok2 = RegOpenKeyExW(hKey2, sk, 0, KEY_READ, &hSub2) == ERROR_SUCCESS;
                if (ok1 && ok2) { CompareKeys(hSub1, fp1, hSub2, fp2, TRUE); }
                else if (ok1) { wprintf(L"< Chỉ có ở key 1: [%s]\n", fp1); CompareCount++; }
                else if (ok2) { wprintf(L"> Chỉ có ở key 2: [%s]\n", fp2); CompareCount++; }
                if (ok1) RegCloseKey(hSub1);
                if (ok2) RegCloseKey(hSub2);
            }
        }
        HeapFree(GetProcessHeap(), 0, sk);
    }
}

// ============================================================
//  CMD: FLAGS
// ============================================================

static int CmdFlags(int argc, wchar_t* argv[], RemoteInfo* ri)
{
    if (argc < 2) {
        wprintf(L"Cú pháp: myregtool FLAGS <KeyName> [QUERY | SET <FlagHex>] [/target host /user u /pass p]\n");
        return 1;
    }

    HKEY  hRootLocal;
    wchar_t subKey[MAX_KEY_LENGTH * 4];
    if (!SplitKeyPath(argv[1], &hRootLocal, subKey, ARRAYSIZE(subKey))) return 1;

    BOOL doSet = (argc >= 4 && _wcsicmp(argv[2], L"SET") == 0);

    RootKeyHandle rkh;
    if (!GetRootKeyHandle(hRootLocal, ri, &rkh)) return 1;

    HKEY  hKey;
    REGSAM access = doSet ? (KEY_READ | KEY_WRITE) : KEY_READ;
    LONG rc = RegOpenKeyExW(rkh.hRootActual, subKey, 0, access, &hKey);
    if (rc != ERROR_SUCCESS) { PrintError(L"RegOpenKeyExW", rc); CloseRootKeyHandle(&rkh); return 1; }

    if (doSet) {
        DWORD flags = (DWORD)wcstoul(argv[3], NULL, 16);
        RegSetKeyValueW(rkh.hRootActual, subKey, NULL, REG_DWORD, &flags, sizeof(DWORD));
        wprintf(L"Flags đã được set (giá trị 0x%08x).\n", flags);
    }
    else {
        FILETIME lastWrite;
        wchar_t className[256];
        DWORD classLen = 256, subKeys, values;
        rc = RegQueryInfoKeyW(hKey, className, &classLen, NULL,
            &subKeys, NULL, NULL, &values, NULL, NULL, NULL, &lastWrite);
        if (rc == ERROR_SUCCESS) {
            SYSTEMTIME st;
            FileTimeToSystemTime(&lastWrite, &st);
            if (ri->isRemote) wprintf(L"Remote:      %s\n", ri->target);
            wprintf(L"Key:         %s\n", argv[1]);
            wprintf(L"Class:       %s\n", className[0] ? className : L"(none)");
            wprintf(L"SubKeys:     %u\n", subKeys);
            wprintf(L"Values:      %u\n", values);
            wprintf(L"LastWrite:   %04d-%02d-%02d %02d:%02d:%02d UTC\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        }
        else PrintError(L"RegQueryInfoKeyW", rc);
    }

    RegCloseKey(hKey);
    CloseRootKeyHandle(&rkh);
    return (rc == ERROR_SUCCESS) ? 0 : 1;
}

// ============================================================
//  In hướng dẫn sử dụng
// ============================================================

static void PrintUsage(void)
{
    wprintf(
        L"\nMyRegTool - Công cụ Registry với hỗ trợ Local & Remote\n"
        L"=======================================================\n\n"
        L"Cú pháp:  myregtool <LỆNH> [tham số...] [/target Host /user User /pass Pass]\n\n"
        L"Các lệnh:\n"
        L"  QUERY   <KeyName> [/v Tên | /ve] [/s]\n"
        L"  ADD     <KeyName> [/v Tên] [/ve] [/t Kiểu] [/d DữLiệu] [/f]\n"
        L"  DELETE  <KeyName> [/v Tên | /ve | /va] [/f]\n"
        L"  COPY    <KeyNguồn> <KeyĐích> [/s] [/f]\n"
        L"  SAVE    <KeyName> <File>        (cần quyền admin)\n"
        L"  RESTORE <KeyName> <File>        (cần quyền admin)\n"
        L"  EXPORT  <KeyName> <File.reg> [/y]\n"
        L"  IMPORT  <File.reg>\n"
        L"  COMPARE <Key1> <Key2> [/s]\n"
        L"  FLAGS   <KeyName> [QUERY | SET <FlagHex>]\n\n"
        L"Tùy chọn Remote (thêm vào cuối bất kỳ lệnh nào):\n"
        L"  /target <hostname|IP>   Máy đích (hỗ trợ cả \\\\host và host)\n"
        L"  /user   <domain\\user>  Tài khoản xác thực SMB/IPC$\n"
        L"  /pass   <password>      Mật khẩu (dùng \"\" để nhập rỗng)\n\n"
        L"  Lưu ý: Yêu cầu Remote Registry Service chạy trên máy đích.\n"
        L"         Máy đích phải mở cổng TCP 445 (SMB) và 135 (RPC).\n"
        L"         Tài khoản cần có quyền admin trên máy đích.\n\n"
        L"Root keys hợp lệ:\n"
        L"  HKLM / HKEY_LOCAL_MACHINE   HKCU / HKEY_CURRENT_USER\n"
        L"  HKCR / HKEY_CLASSES_ROOT    HKU  / HKEY_USERS\n"
        L"  HKCC / HKEY_CURRENT_CONFIG\n\n"
        L"Ví dụ (Local):\n"
        L"  myregtool QUERY HKCU\\Software\\Microsoft /s\n"
        L"  myregtool ADD HKCU\\Software\\MyApp /v Version /t REG_SZ /d \"1.0\" /f\n"
        L"  myregtool EXPORT HKCU\\Software\\MyApp backup.reg\n\n"
        L"Ví dụ (Remote):\n"
        L"  myregtool QUERY HKLM\\Software /s /target 192.168.1.10 /user admin /pass secret\n"
        L"  myregtool ADD HKLM\\Software\\MyApp /v Ver /t REG_SZ /d \"2.0\" /f\n"
        L"       /target server01 /user DOMAIN\\Administrator /pass P@ssw0rd\n"
        L"  myregtool DELETE HKLM\\Software\\OldApp /f /target 10.0.0.5 /user admin /pass \"\"\n"
        L"  myregtool COMPARE HKLM\\Software\\App HKLM\\Software\\App /s\n"
        L"       /target 192.168.1.10 /user admin /pass secret\n"
        L"  myregtool EXPORT HKLM\\Software\\App remote_backup.reg /y\n"
        L"       /target 192.168.1.10 /user admin /pass secret\n"
    );
}

// ============================================================
//  main
// ============================================================

int wmain(int argc, wchar_t* argv[])
{
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    if (argc < 2) { PrintUsage(); return 0; }

    // --- Parse và lọc tham số remote ---
    RemoteInfo ri;
    ParseRemoteArgs(argc - 1, argv + 1, &ri);  // bỏ argv[0] (tên chương trình)

    // Tạo argv đã lọc (không còn /target /user /pass)
    wchar_t** filteredArgv = (wchar_t**)HeapAlloc(GetProcessHeap(), 0, argc * sizeof(wchar_t*));
    if (!filteredArgv) return 1;
    filteredArgv[0] = argv[0]; // tên chương trình
    int filteredArgc = 1 + FilterRemoteArgs(argc - 1, argv + 1, filteredArgv + 1);

    // Lệnh là filteredArgv[1]
    if (filteredArgc < 2) { PrintUsage(); HeapFree(GetProcessHeap(), 0, filteredArgv); return 0; }
    const wchar_t* cmd = filteredArgv[1];

    int ret;
    // Truyền filteredArgv+1 (cmd, keyname, options...) vào từng hàm
    if (_wcsicmp(cmd, L"QUERY") == 0) ret = CmdQuery(filteredArgc - 1, filteredArgv + 1, &ri);
    else if (_wcsicmp(cmd, L"ADD") == 0) ret = CmdAdd(filteredArgc - 1, filteredArgv + 1, &ri);
    else if (_wcsicmp(cmd, L"DELETE") == 0) ret = CmdDelete(filteredArgc - 1, filteredArgv + 1, &ri);
    else if (_wcsicmp(cmd, L"COPY") == 0) ret = CmdCopy(filteredArgc - 1, filteredArgv + 1, &ri);
    else if (_wcsicmp(cmd, L"SAVE") == 0) ret = CmdSave(filteredArgc - 1, filteredArgv + 1, &ri);
    else if (_wcsicmp(cmd, L"RESTORE") == 0) ret = CmdRestore(filteredArgc - 1, filteredArgv + 1, &ri);
    else if (_wcsicmp(cmd, L"EXPORT") == 0) ret = CmdExport(filteredArgc - 1, filteredArgv + 1, &ri);
    else if (_wcsicmp(cmd, L"IMPORT") == 0) ret = CmdImport(filteredArgc - 1, filteredArgv + 1, &ri);
    else if (_wcsicmp(cmd, L"COMPARE") == 0) ret = CmdCompare(filteredArgc - 1, filteredArgv + 1, &ri);
    else if (_wcsicmp(cmd, L"FLAGS") == 0) ret = CmdFlags(filteredArgc - 1, filteredArgv + 1, &ri);
    else {
        fwprintf(stderr, L"Lệnh không hợp lệ: %s\n", cmd);
        PrintUsage();
        ret = 1;
    }

    // Ngắt kết nối IPC$ khi xong
    DisconnectRemoteIPC(&ri);

    HeapFree(GetProcessHeap(), 0, filteredArgv);
    return ret;
}