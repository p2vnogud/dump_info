#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <iostream>

#pragma comment(lib, "advapi32.lib")

bool aes_encrypt_file(
    const std::string& input_file,
    const std::string& output_file,
    const BYTE* key,   // 16 bytes
    const BYTE* iv     // 16 bytes
)
{
    // 1. Mở file input
    HANDLE hInput = CreateFileA(input_file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInput == INVALID_HANDLE_VALUE)
    {
        std::cout << "Khong mo duoc file dau vao\n";
        return false;
    }

    // Lấy kích thước file
    LARGE_INTEGER size;
    if (!GetFileSizeEx(hInput, &size))
    {
        std::cout << "Loi lay kich thuoc file\n";
        CloseHandle(hInput);
        return false;
    }

    if (size.QuadPart == 0)
    {
        std::cout << "File rong\n";
        CloseHandle(hInput);
        return false;
    }

    // Đọc toàn bộ file vào vector
    std::vector<BYTE> data(size.QuadPart);
    DWORD bytesRead = 0;
    if (!ReadFile(hInput, data.data(), (DWORD)size.QuadPart, &bytesRead, NULL) ||
        bytesRead != size.QuadPart)
    {
        std::cout << "Loi doc file\n";
        CloseHandle(hInput);
        return false;
    }
    CloseHandle(hInput);

    // 2. Chuẩn bị mã hóa AES
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        std::cout << "Loi khoi tao Crypto\n";
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        std::cout << "Loi tao hash\n";
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptHashData(hHash, key, 16, 0))
    {
        std::cout << "Loi hash key\n";
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, CRYPT_EXPORTABLE, &hKey))
    {
        std::cout << "Loi tao key AES\n";
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0))
    {
        std::cout << "Loi dat IV\n";
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    // 3. Mã hóa dữ liệu
    DWORD dataLen = (DWORD)data.size();
    DWORD bufLen = dataLen;

    // Tính kích thước sau khi mã hóa (có padding)
    if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &bufLen, 0))
    {
        std::cout << "Loi tinh kich thuoc ma hoa\n";
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    data.resize(bufLen);

    // Thực hiện mã hóa
    if (!CryptEncrypt(hKey, 0, TRUE, 0, data.data(), &dataLen, bufLen))
    {
        std::cout << "Loi ma hoa du lieu\n";
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    data.resize(dataLen);  // Cắt phần thừa

    // 4. Ghi file output
    HANDLE hOutput = CreateFileA(output_file.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutput == INVALID_HANDLE_VALUE)
    {
        std::cout << "Khong tao duoc file dau ra\n";
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    DWORD bytesWritten = 0;
    if (!WriteFile(hOutput, data.data(), (DWORD)data.size(), &bytesWritten, NULL) ||
        bytesWritten != data.size())
    {
        std::cout << "Loi ghi file\n";
        CloseHandle(hOutput);
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    CloseHandle(hOutput);

    // Dọn dẹp CryptoAPI
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    std::cout << "Ma hoa thanh cong!\n";
    std::cout << "File vao : " << input_file << " (" << size.QuadPart << " bytes)\n";
    std::cout << "File ra  : " << output_file << " (" << data.size() << " bytes)\n";

    return true;
}

int main()
{
    BYTE key[16] = { 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
                    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };

    BYTE iv[16] = { 0 };  // Trong thực tế nên random IV

    std::string input = "shellcode.bin";
    std::string output = "payload.aes";

    if (aes_encrypt_file(input, output, key, iv))
    {
        std::cout << "Xong roi!\n";
    }
    else
    {
        std::cout << "That bai.\n";
    }

    return 0;
}