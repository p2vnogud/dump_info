#include <windows.h>
#include <stdio.h>


static void PrintError(const wchar_t* prefix, LONG code)
{
    wchar_t buf[512] = { 0 };
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, (DWORD)code, 0, buf, 512, NULL);
    fwprintf(stderr, L"[ERROR] %s: %s (code=%ld)\n", prefix, buf, code);
}


void CreateKey() {
    HKEY keyRoot = HKEY_CURRENT_USER;
    // LPCWSTR
    const wchar_t* lsubkey = L"Environment\\test";
    WCHAR buf[500];
    HKEY hKey;
    DWORD disposition;

    swprintf_s(buf, 500, L"%s\\%s", keyRoot, lsubkey);
    LSTATUS rck = RegCreateKeyExW(keyRoot, lsubkey, 0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE, NULL, &hKey, &disposition);
    if (rck != ERROR_SUCCESS) {
        DWORD err = GetLastError();
        PrintError(L"Create Key failed", err);
        return;
    }

    if (disposition == REG_CREATED_NEW_KEY) {
        wprintf(L"Create key (%s) sucess!\n", buf);
    }
    else {
        printf("Key existed| Create key failed!\n");
    }

    
    if (RegCloseKey(hKey) == ERROR_SUCCESS) {
        printf("Close handle key success!\n");
    }
    else {
        DWORD err = GetLastError();
        PrintError(L"Close key failed", err);
    }
}

void DeleteKey() {
    HKEY keyRoot = HKEY_CURRENT_USER;
    const wchar_t* lsubkey = L"Environment\\test";
    WCHAR buf[200];
    swprintf_s(buf, 200, L"HKCU\\%s", lsubkey);

    LSTATUS rdk = RegDeleteKeyEx(keyRoot, lsubkey, KEY_WOW64_64KEY, 0);

    if (rdk != ERROR_SUCCESS) {
        DWORD err = GetLastError();
        PrintError(L"Delete key failed", err);
        return;
    }
    wprintf(L"Delete key (%s) success!\n", buf);
}

void QueryKey() {
    HKEY keyRoot = HKEY_CURRENT_USER;
    const wchar_t* lsubkey = L"Control Panel";
    WCHAR buf[200];
    swprintf_s(buf, 200, L"HKCU\\%s", lsubkey);
    HKEY hKey;

    //LSTATUS rqk = RegQueryInfoKeyW(keyRoot, NULL, NULL, NULL, NULL, );

    LSTATUS rok = RegOpenKeyExW(keyRoot, lsubkey, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hKey);
    if (rok != ERROR_SUCCESS) {
        DWORD err = GetLastError();
        PrintError(L"Create Key failed", err);
        return;
    }
    wprintf(L"Open key (%s) success!\n", buf);

    DWORD cSubkey = 0;  // so luong subkey
    DWORD sizeMaxSubLen = 0;    // size cua subkey co name dai nhat
    DWORD cValue = 0;   // so luong values
    DWORD sizeMaxValueLen = 0;  // size cua value co name dai nhat

    LSTATUS rqik = RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &cSubkey, 
        &sizeMaxSubLen, NULL, &cValue, &sizeMaxValueLen, NULL, NULL, NULL);
    if (rqik != ERROR_SUCCESS) {
        DWORD err = GetLastError();
        PrintError(L"Reg query key info failed", err);
        return;
    }
    wprintf(L"RegQueryInfoKeyW (%s) success!\n", buf);
    printf("So luong subkey: %d\n", cSubkey);
    printf("Size cua subkey name dai nhat: %d\n", sizeMaxSubLen);
    printf("So luong values: %d\n", cValue);
    printf("Size value name dai nhat: %d\n", sizeMaxValueLen);

    if (RegCloseKey(hKey) == ERROR_SUCCESS) {
        printf("Close handle key success!\n");
    }
    else {
        DWORD err = GetLastError();
        PrintError(L"Close key failed", err);
    }
}

int main() {
    //CreateKey();
    //DeleteKey();
    QueryKey();
	return 0;
}