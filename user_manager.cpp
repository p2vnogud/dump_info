#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <lm.h>          // NetUser*, NetLocalGroup*
#include <ntsecapi.h>    // LsaAddAccountRights, LsaEnumerateAccountRights
#include <sddl.h>        // ConvertSidToStringSid
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

 // ─────────────────────────────────────────────
 //  Utility helpers
 // ─────────────────────────────────────────────

static std::wstring s2w(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

static std::string w2s(const std::wstring& w) {
    return std::string(w.begin(), w.end());
}

static void printBanner() {
    std::wcout << L"\n";
    std::wcout << L"╔══════════════════════════════════════════════════════╗\n";
    std::wcout << L"║      Windows User & Permission Manager  (WinAPI)     ║\n";
    std::wcout << L"╚══════════════════════════════════════════════════════╝\n";
    std::wcout << L"  Requires: Run as Administrator\n\n";
}

static void printError(const wchar_t* func, NET_API_STATUS st) {
    std::wcerr << L"[ERROR] " << func << L" failed, code=" << st << L"\n";
}

// ─────────────────────────────────────────────
//  1. Tạo user mới
// ─────────────────────────────────────────────
bool CreateUser(const std::wstring& username,
    const std::wstring& password,
    const std::wstring& fullName,
    const std::wstring& comment,
    bool   passwordNeverExpires = true,
    bool   userCannotChangePassword = false)
{
    USER_INFO_1 ui = {};
    ui.usri1_name = const_cast<LPWSTR>(username.c_str());
    ui.usri1_password = const_cast<LPWSTR>(password.c_str());
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = nullptr;
    ui.usri1_comment = const_cast<LPWSTR>(comment.c_str());
    ui.usri1_flags = UF_SCRIPT;
    if (passwordNeverExpires)      ui.usri1_flags |= UF_DONT_EXPIRE_PASSWD;
    if (userCannotChangePassword)  ui.usri1_flags |= UF_PASSWD_CANT_CHANGE;
    ui.usri1_script_path = nullptr;

    DWORD errParam = 0;
    NET_API_STATUS st = NetUserAdd(nullptr, 1, (LPBYTE)&ui, &errParam);
    if (st != NERR_Success) {
        printError(L"NetUserAdd", st);
        return false;
    }

    // Set full name (level 2 field)
    USER_INFO_1011 ui1011 = {};
    ui1011.usri1011_full_name = const_cast<LPWSTR>(fullName.c_str());
    NetUserSetInfo(nullptr, username.c_str(), 1011, (LPBYTE)&ui1011, nullptr);

    std::wcout << L"[OK] User '" << username << L"' created.\n";
    return true;
}

// ─────────────────────────────────────────────
//  2. Xóa user
// ─────────────────────────────────────────────
bool DeleteUser(const std::wstring& username) {
    NET_API_STATUS st = NetUserDel(nullptr, username.c_str());
    if (st != NERR_Success) { printError(L"NetUserDel", st); return false; }
    std::wcout << L"[OK] User '" << username << L"' deleted.\n";
    return true;
}

// ─────────────────────────────────────────────
//  3. Tạo local group mới
// ─────────────────────────────────────────────
bool CreateLocalGroup(const std::wstring& groupName, const std::wstring& comment) {
    LOCALGROUP_INFO_1 lgi = {};
    lgi.lgrpi1_name = const_cast<LPWSTR>(groupName.c_str());
    lgi.lgrpi1_comment = const_cast<LPWSTR>(comment.c_str());

    DWORD errParam = 0;
    NET_API_STATUS st = NetLocalGroupAdd(nullptr, 1, (LPBYTE)&lgi, &errParam);
    if (st != NERR_Success) { printError(L"NetLocalGroupAdd", st); return false; }
    std::wcout << L"[OK] Group '" << groupName << L"' created.\n";
    return true;
}

// ─────────────────────────────────────────────
//  4. Thêm user vào local group
// ─────────────────────────────────────────────
bool AddUserToGroup(const std::wstring& groupName, const std::wstring& username) {
    LOCALGROUP_MEMBERS_INFO_3 lgmi = {};
    lgmi.lgrmi3_domainandname = const_cast<LPWSTR>(username.c_str());

    NET_API_STATUS st = NetLocalGroupAddMembers(nullptr, groupName.c_str(),
        3, (LPBYTE)&lgmi, 1);
    if (st != NERR_Success) { printError(L"NetLocalGroupAddMembers", st); return false; }
    std::wcout << L"[OK] '" << username << L"' added to group '" << groupName << L"'.\n";
    return true;
}

// ─────────────────────────────────────────────
//  5. Xóa user khỏi group
// ─────────────────────────────────────────────
bool RemoveUserFromGroup(const std::wstring& groupName, const std::wstring& username) {
    LOCALGROUP_MEMBERS_INFO_3 lgmi = {};
    lgmi.lgrmi3_domainandname = const_cast<LPWSTR>(username.c_str());

    NET_API_STATUS st = NetLocalGroupDelMembers(nullptr, groupName.c_str(),
        3, (LPBYTE)&lgmi, 1);
    if (st != NERR_Success) { printError(L"NetLocalGroupDelMembers", st); return false; }
    std::wcout << L"[OK] '" << username << L"' removed from group '" << groupName << L"'.\n";
    return true;
}

// ─────────────────────────────────────────────
//  6. Cấp / Thu hồi User Rights (LSA)
//     Ví dụ rights: SeDebugPrivilege, SeRemoteInteractiveLogonRight,
//                   SeBatchLogonRight, SeServiceLogonRight, ...
// ─────────────────────────────────────────────

// Lấy SID từ tên account
static bool GetAccountSid(const std::wstring& accountName, PSID* ppSid) {
    DWORD cbSid = 0, cbDomain = 0;
    SID_NAME_USE use;
    LookupAccountNameW(nullptr, accountName.c_str(), nullptr, &cbSid, nullptr, &cbDomain, &use);

    *ppSid = (PSID)LocalAlloc(LPTR, cbSid);
    std::vector<wchar_t> domain(cbDomain);
    if (!LookupAccountNameW(nullptr, accountName.c_str(), *ppSid, &cbSid,
        domain.data(), &cbDomain, &use)) {
        LocalFree(*ppSid); *ppSid = nullptr;
        std::wcerr << L"[ERROR] LookupAccountName failed: " << GetLastError() << L"\n";
        return false;
    }
    return true;
}

// Mở LSA Policy
static LSA_HANDLE OpenLsaPolicy() {
    LSA_OBJECT_ATTRIBUTES oa = {};
    LSA_HANDLE hPolicy = nullptr;
    NTSTATUS st = LsaOpenPolicy(nullptr, &oa, POLICY_ALL_ACCESS, &hPolicy);
    if (st != 0) {
        std::wcerr << L"[ERROR] LsaOpenPolicy NTSTATUS=" << st << L"\n";
    }
    return hPolicy;
}

bool GrantUserRight(const std::wstring& username, const std::wstring& rightName) {
    PSID pSid = nullptr;
    if (!GetAccountSid(username, &pSid)) return false;

    LSA_HANDLE hPolicy = OpenLsaPolicy();
    if (!hPolicy) { LocalFree(pSid); return false; }

    LSA_UNICODE_STRING lsaRight = {};
    lsaRight.Buffer = const_cast<PWSTR>(rightName.c_str());
    lsaRight.Length = (USHORT)(rightName.size() * sizeof(wchar_t));
    lsaRight.MaximumLength = lsaRight.Length + sizeof(wchar_t);

    NTSTATUS st = LsaAddAccountRights(hPolicy, pSid, &lsaRight, 1);
    LsaClose(hPolicy);
    LocalFree(pSid);

    if (st != 0) {
        std::wcerr << L"[ERROR] LsaAddAccountRights NTSTATUS=" << st << L"\n";
        return false;
    }
    std::wcout << L"[OK] Right '" << rightName << L"' granted to '" << username << L"'.\n";
    return true;
}

bool RevokeUserRight(const std::wstring& username, const std::wstring& rightName) {
    PSID pSid = nullptr;
    if (!GetAccountSid(username, &pSid)) return false;

    LSA_HANDLE hPolicy = OpenLsaPolicy();
    if (!hPolicy) { LocalFree(pSid); return false; }

    LSA_UNICODE_STRING lsaRight = {};
    lsaRight.Buffer = const_cast<PWSTR>(rightName.c_str());
    lsaRight.Length = (USHORT)(rightName.size() * sizeof(wchar_t));
    lsaRight.MaximumLength = lsaRight.Length + sizeof(wchar_t);

    NTSTATUS st = LsaRemoveAccountRights(hPolicy, pSid, FALSE, &lsaRight, 1);
    LsaClose(hPolicy);
    LocalFree(pSid);

    if (st != 0) {
        std::wcerr << L"[ERROR] LsaRemoveAccountRights NTSTATUS=" << st << L"\n";
        return false;
    }
    std::wcout << L"[OK] Right '" << rightName << L"' revoked from '" << username << L"'.\n";
    return true;
}

// ─────────────────────────────────────────────
//  7. Liệt kê tất cả rights của user
// ─────────────────────────────────────────────
bool ListUserRights(const std::wstring& username) {
    PSID pSid = nullptr;
    if (!GetAccountSid(username, &pSid)) return false;

    LSA_HANDLE hPolicy = OpenLsaPolicy();
    if (!hPolicy) { LocalFree(pSid); return false; }

    PLSA_UNICODE_STRING rights = nullptr;
    ULONG count = 0;
    NTSTATUS st = LsaEnumerateAccountRights(hPolicy, pSid, &rights, &count);
    LsaClose(hPolicy);
    LocalFree(pSid);

    if (st != 0) {
        std::wcout << L"  (no rights assigned, NTSTATUS=" << st << L")\n";
        return false;
    }

    std::wcout << L"  Rights for '" << username << L"' (" << count << L"):\n";
    for (ULONG i = 0; i < count; i++) {
        std::wcout << L"    - " << std::wstring(rights[i].Buffer,
            rights[i].Length / sizeof(wchar_t)) << L"\n";
    }
    LsaFreeMemory(rights);
    return true;
}

// ─────────────────────────────────────────────
//  8. Liệt kê tất cả local users
// ─────────────────────────────────────────────
void ListLocalUsers() {
    LPUSER_INFO_1 pBuf = nullptr;
    DWORD entries = 0, total = 0;
    DWORD resume = 0;

    std::wcout << L"\n  ┌─────────────────────────────────────────────────────┐\n";
    std::wcout << L"  │  Local Users                                        │\n";
    std::wcout << L"  └─────────────────────────────────────────────────────┘\n";

    NET_API_STATUS st;
    do {
        st = NetUserEnum(nullptr, 1, FILTER_NORMAL_ACCOUNT,
            (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH,
            &entries, &total, &resume);
        if (st == NERR_Success || st == ERROR_MORE_DATA) {
            for (DWORD i = 0; i < entries; i++) {
                BOOL enabled = !(pBuf[i].usri1_flags & UF_ACCOUNTDISABLE);
                std::wcout << L"    [" << (enabled ? L"ON " : L"OFF") << L"] "
                    << std::left << std::setw(24) << pBuf[i].usri1_name
                    << L"  flags=0x" << std::hex << pBuf[i].usri1_flags << std::dec << L"\n";
            }
            NetApiBufferFree(pBuf);
        }
    } while (st == ERROR_MORE_DATA);
}

// ─────────────────────────────────────────────
//  9. Liệt kê tất cả local groups + members
// ─────────────────────────────────────────────
void ListLocalGroups() {
    LPLOCALGROUP_INFO_1 pBuf = nullptr;
    DWORD entries = 0, total = 0;
    DWORD_PTR resume = 0;

    std::wcout << L"\n  ┌─────────────────────────────────────────────────────┐\n";
    std::wcout << L"  │  Local Groups                                       │\n";
    std::wcout << L"  └─────────────────────────────────────────────────────┘\n";

    NET_API_STATUS st;
    do {
        st = NetLocalGroupEnum(nullptr, 1, (LPBYTE*)&pBuf,
            MAX_PREFERRED_LENGTH, &entries, &total, &resume);
        if (st == NERR_Success || st == ERROR_MORE_DATA) {
            for (DWORD i = 0; i < entries; i++) {
                std::wcout << L"  Group: " << pBuf[i].lgrpi1_name
                    << L"  (" << pBuf[i].lgrpi1_comment << L")\n";

                // List members
                LPLOCALGROUP_MEMBERS_INFO_3 pMem = nullptr;
                DWORD mEntries = 0, mTotal = 0;
                DWORD_PTR mResume = 0;
                NetLocalGroupGetMembers(nullptr, pBuf[i].lgrpi1_name, 3,
                    (LPBYTE*)&pMem, MAX_PREFERRED_LENGTH,
                    &mEntries, &mTotal, &mResume);
                for (DWORD j = 0; j < mEntries; j++)
                    std::wcout << L"      -> " << pMem[j].lgrmi3_domainandname << L"\n";
                if (pMem) NetApiBufferFree(pMem);
            }
            NetApiBufferFree(pBuf);
        }
    } while (st == ERROR_MORE_DATA);
}

// ─────────────────────────────────────────────
//  10. Enable / Disable account
// ─────────────────────────────────────────────
bool SetAccountEnabled(const std::wstring& username, bool enabled) {
    LPUSER_INFO_1 pUi = nullptr;
    NET_API_STATUS st = NetUserGetInfo(nullptr, username.c_str(), 1, (LPBYTE*)&pUi);
    if (st != NERR_Success) { printError(L"NetUserGetInfo", st); return false; }

    if (enabled)
        pUi->usri1_flags &= ~UF_ACCOUNTDISABLE;
    else
        pUi->usri1_flags |= UF_ACCOUNTDISABLE;

    DWORD errParam = 0;
    st = NetUserSetInfo(nullptr, username.c_str(), 1, (LPBYTE)pUi, &errParam);
    NetApiBufferFree(pUi);
    if (st != NERR_Success) { printError(L"NetUserSetInfo", st); return false; }
    std::wcout << L"[OK] Account '" << username << L"' " << (enabled ? L"enabled" : L"disabled") << L".\n";
    return true;
}

// ─────────────────────────────────────────────
//  11. Đổi mật khẩu
// ─────────────────────────────────────────────
bool ChangeUserPassword(const std::wstring& username, const std::wstring& newPassword) {
    USER_INFO_1003 ui = {};
    ui.usri1003_password = const_cast<LPWSTR>(newPassword.c_str());
    NET_API_STATUS st = NetUserSetInfo(nullptr, username.c_str(), 1003, (LPBYTE)&ui, nullptr);
    if (st != NERR_Success) { printError(L"NetUserSetInfo(pwd)", st); return false; }
    std::wcout << L"[OK] Password changed for '" << username << L"'.\n";
    return true;
}

// ─────────────────────────────────────────────
//  12. Xem groups của một user cụ thể
// ─────────────────────────────────────────────
void ListUserGroups(const std::wstring& username) {
    LPLOCALGROUP_USERS_INFO_0 pBuf = nullptr;
    DWORD entries = 0, total = 0;
    NET_API_STATUS st = NetUserGetLocalGroups(nullptr, username.c_str(), 0,
        LG_INCLUDE_INDIRECT,
        (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH,
        &entries, &total);
    if (st != NERR_Success) { printError(L"NetUserGetLocalGroups", st); return; }

    std::wcout << L"  Groups of '" << username << L"' (" << entries << L"):\n";
    for (DWORD i = 0; i < entries; i++)
        std::wcout << L"    - " << pBuf[i].lgrui0_name << L"\n";
    NetApiBufferFree(pBuf);
}

// ─────────────────────────────────────────────
//  Interactive Menu
// ─────────────────────────────────────────────
static std::wstring prompt(const wchar_t* msg) {
    std::wcout << msg;
    std::wstring s;
    std::getline(std::wcin, s);
    return s;
}

int main() {
    // Set console to UTF-16
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    printBanner();

    while (true) {
        std::wcout << L"\n┌─ MENU ─────────────────────────────────────┐\n";
        std::wcout << L"│  1. Tạo user mới                            │\n";
        std::wcout << L"│  2. Xóa user                                │\n";
        std::wcout << L"│  3. Enable / Disable account                │\n";
        std::wcout << L"│  4. Đổi mật khẩu                           │\n";
        std::wcout << L"│  5. Tạo local group                         │\n";
        std::wcout << L"│  6. Thêm user vào group                     │\n";
        std::wcout << L"│  7. Xóa user khỏi group                     │\n";
        std::wcout << L"│  8. Cấp User Right (LSA)                    │\n";
        std::wcout << L"│  9. Thu hồi User Right (LSA)                │\n";
        std::wcout << L"│ 10. Liệt kê Rights của user                 │\n";
        std::wcout << L"│ 11. Liệt kê tất cả local users              │\n";
        std::wcout << L"│ 12. Liệt kê tất cả local groups + members   │\n";
        std::wcout << L"│ 13. Xem groups của một user                 │\n";
        std::wcout << L"│  0. Thoát                                   │\n";
        std::wcout << L"└────────────────────────────────────────────┘\n";

        std::wstring choice = prompt(L"Chọn: ");

        if (choice == L"0") break;

        else if (choice == L"1") {
            auto user = prompt(L"  Username   : ");
            auto pass = prompt(L"  Password   : ");
            auto full = prompt(L"  Full Name  : ");
            auto cmt = prompt(L"  Comment    : ");
            auto noexp = prompt(L"  Pwd never expires? [y/n]: ");
            CreateUser(user, pass, full, cmt, noexp == L"y" || noexp == L"Y");
        }
        else if (choice == L"2") {
            auto user = prompt(L"  Username: ");
            DeleteUser(user);
        }
        else if (choice == L"3") {
            auto user = prompt(L"  Username      : ");
            auto en = prompt(L"  Enable? [y/n] : ");
            SetAccountEnabled(user, en == L"y" || en == L"Y");
        }
        else if (choice == L"4") {
            auto user = prompt(L"  Username    : ");
            auto pass = prompt(L"  New Password: ");
            ChangeUserPassword(user, pass);
        }
        else if (choice == L"5") {
            auto grp = prompt(L"  Group name : ");
            auto cmt = prompt(L"  Comment    : ");
            CreateLocalGroup(grp, cmt);
        }
        else if (choice == L"6") {
            auto grp = prompt(L"  Group name : ");
            auto user = prompt(L"  Username   : ");
            AddUserToGroup(grp, user);
        }
        else if (choice == L"7") {
            auto grp = prompt(L"  Group name : ");
            auto user = prompt(L"  Username   : ");
            RemoveUserFromGroup(grp, user);
        }
        else if (choice == L"8") {
            std::wcout << L"  Một số quyền phổ biến:\n"
                << L"    SeDebugPrivilege\n"
                << L"    SeRemoteInteractiveLogonRight\n"
                << L"    SeBatchLogonRight\n"
                << L"    SeServiceLogonRight\n"
                << L"    SeNetworkLogonRight\n"
                << L"    SeShutdownPrivilege\n"
                << L"    SeTakeOwnershipPrivilege\n"
                << L"    SeBackupPrivilege\n"
                << L"    SeRestorePrivilege\n"
                << L"    SeImpersonatePrivilege\n"
                << L"    SeLoadDriverPrivilege\n";
            auto user = prompt(L"  Username : ");
            auto right = prompt(L"  Right    : ");
            GrantUserRight(user, right);
        }
        else if (choice == L"9") {
            auto user = prompt(L"  Username : ");
            auto right = prompt(L"  Right    : ");
            RevokeUserRight(user, right);
        }
        else if (choice == L"10") {
            auto user = prompt(L"  Username: ");
            ListUserRights(user);
        }
        else if (choice == L"11") {
            ListLocalUsers();
        }
        else if (choice == L"12") {
            ListLocalGroups();
        }
        else if (choice == L"13") {
            auto user = prompt(L"  Username: ");
            ListUserGroups(user);
        }
        else {
            std::wcout << L"[!] Lựa chọn không hợp lệ.\n";
        }
    }

    std::wcout << L"\nBye!\n";
    return 0;
}