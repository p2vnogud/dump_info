#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shlwapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

// ─────────────────────────── constants ──────────────────────────────────────

static const BYTE S1[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00";
static const BYTE S2[] = "0123456789012345678901234567890123456789\x00";
static const BYTE S3[] = "NTPASSWORD\x00";

// Registry access flags (mirrors go-smb2 constants)
#define REG_OPTION_BACKUP_RESTORE   0x00000004
#define PERM_MAXIMUM_ALLOWED        MAXIMUM_ALLOWED

// ─────────────────────────── structs ────────────────────────────────────────

#pragma pack(push, 1)

struct lsa_secret {
    uint32_t Version;
    char     EncKeyId[16];
    uint32_t EncAlgorithm;
    uint32_t Flags;
    // EncryptedData follows in raw buffer
};

struct lsa_secret_blob {
    uint32_t Length;
    uint8_t  Unknown[12];
    // Secret of Length bytes follows
};

struct dpapi_system {
    uint32_t Version;
    uint8_t  MachineKey[20];
    uint8_t  UserKey[20];
};

struct sam_key_data_aes {
    uint32_t Revision;
    uint32_t Length;
    uint32_t ChecksumLen;
    uint32_t DataLen;
    uint8_t  Salt[16];
    uint8_t  Data[32];
};

struct sam_key_data {
    uint32_t Revision;
    uint32_t Length;
    uint8_t  Salt[16];
    uint8_t  Key[16];
    uint8_t  Checksum[16];
    uint64_t Reserved;
};

struct nl_record {
    uint16_t UserLength;
    uint16_t DomainNameLength;
    uint16_t EffectiveNameLength;
    uint16_t FullNameLength;
    uint16_t LogonScriptName;
    uint16_t ProfilePathLength;
    uint16_t HomeDirectoryLength;
    uint16_t HomeDirectoryDriveLength;
    uint32_t UserId;
    uint32_t PrimaryGroupId;
    uint32_t GroupCount;
    uint16_t logonDomainNameLength;
    uint16_t Unk0;
    uint64_t LastWrite;
    uint32_t Revision;
    uint32_t SidCount;
    uint32_t Flags;
    uint32_t Unk1;
    uint32_t LogonPackageLength;
    uint16_t DnsDomainNameLength;
    uint16_t UPN;
    uint8_t  IV[16];
    uint8_t  CH[16];
    // EncryptedData follows
};

#pragma pack(pop)

// domain_account_f has variable-length tail; we parse it manually
struct domain_account_f {
    uint16_t Revision;
    uint64_t CreationTime;
    uint64_t DomainModifiedAccount;
    uint64_t MaxPasswordAge;
    uint64_t MinPasswordAge;
    uint64_t ForceLogoff;
    uint64_t LockoutDuration;
    uint64_t LockoutObservationWindow;
    uint64_t ModifiedCountAtLastPromotion;
    uint32_t NextRid;
    uint32_t PasswordProperties;
    uint16_t MinPasswordLength;
    uint16_t PasswordHistoryLength;
    uint16_t LockoutThreshold;
    uint32_t ServerState;
    uint32_t ServerRole;
    uint32_t UasCompatibilityRequired;
    std::vector<uint8_t> Data;
};

// ─────────────────────────── result types ───────────────────────────────────

struct UserCreds {
    std::string          Username;
    std::vector<uint8_t> Data;
    std::vector<uint8_t> IV;
    uint32_t             RID;
    bool                 AES;
};

struct PrintableLSASecret {
    std::string              secretType;
    std::vector<std::string> secrets;
    std::string              extraSecret;
};

// ─────────────────────────── global state ───────────────────────────────────

extern std::vector<uint8_t> g_BootKey;
extern std::vector<uint8_t> g_LSAKey;
extern std::vector<uint8_t> g_NLKMKey;
extern bool                 g_VistaStyle;

// ─────────────────────────── helpers ────────────────────────────────────────

std::string  ToHex(const uint8_t* data, size_t len);
std::string  FromUnicodeString(const uint8_t* data, size_t len);
uint32_t     ReadLE32(const uint8_t* p);
uint16_t     ReadLE16(const uint8_t* p);
uint64_t     ReadLE64(const uint8_t* p);
uint64_t     Pad64(uint64_t v);
bool         UnmarshalDomainAccountF(const uint8_t* data, size_t len, domain_account_f& out);
bool         UnmarshalNLRecord(const uint8_t* data, size_t len, nl_record& hdr, std::vector<uint8_t>& encData);

// ─────────────────────────── crypto ─────────────────────────────────────────

bool  MD5Hash(const uint8_t* data, size_t len, uint8_t out[16]);
bool  MD4Hash(const uint8_t* data, size_t len, uint8_t out[16]);
bool  SHA256Hash(const uint8_t* data, size_t len, uint8_t out[32]);

// SHA256( key || data[:32] ) — mirrors Go's SHA256() helper
std::vector<uint8_t> SHA256Key(const std::vector<uint8_t>& key,
    const uint8_t* encData, size_t encLen,
    int iterations);

bool RC4Crypt(const uint8_t* key, size_t keyLen,
    const uint8_t* in, size_t inLen,
    uint8_t* out);

bool AESCBCDecrypt(const uint8_t* key, size_t keyLen,
    const uint8_t* iv,
    const uint8_t* in, size_t inLen,
    std::vector<uint8_t>& out);

// ─────────────────────────── registry helpers ────────────────────────────────

HKEY  OpenSubKey(HKEY base, const char* path);
HKEY  OpenSubKeyExt(HKEY base, const char* path, DWORD options, REGSAM access);
void  CloseKeyHandle(HKEY h);
bool  QueryValueBinary(HKEY h, const char* name, std::vector<uint8_t>& out);
bool  QueryValueString(HKEY h, const char* name, std::string& out);
bool  QueryKeyClassName(HKEY h, std::string& out);
bool  GetSubKeyNames(HKEY base, const char* path, DWORD options,
    REGSAM access, std::vector<std::string>& out);
bool  GetValueNames(HKEY h, std::vector<std::string>& out);

// ─────────────────────────── public API ──────────────────────────────────────

bool GetBootKey(HKEY base, std::vector<uint8_t>& result);
bool GetSysKey(HKEY base, std::vector<uint8_t>& result);
bool DecryptRC4SysKey(const std::vector<uint8_t>& bootKey,
    const std::vector<uint8_t>& encSysKey,
    const uint8_t* sysKeyIV,
    std::vector<uint8_t>& result);
bool DecryptAESSysKey(const std::vector<uint8_t>& bootKey,
    const std::vector<uint8_t>& encSysKey,
    const uint8_t* sysKeyIV,
    std::vector<uint8_t>& result);

bool GetNTHashes(HKEY base, const std::vector<std::string>& rids,
    std::vector<UserCreds>& result);

// Decrypt an AES-encrypted NT hash from the SAM (post-Win10-Anniversary)
// encData = cred.Data, iv = cred.IV, sysKey = unwrapped syskey, rid = user RID
bool DecryptAESHash(const std::vector<uint8_t>& encData,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& sysKey,
    uint32_t rid,
    std::vector<uint8_t>& result);

// Decrypt an RC4-encrypted NT hash from the SAM (pre-Win10-Anniversary)
// encData = cred.Data, sysKey = unwrapped syskey, rid = user RID
bool DecryptRC4Hash(const std::vector<uint8_t>& encData,
    const std::vector<uint8_t>& sysKey,
    uint32_t rid,
    std::vector<uint8_t>& result);
bool GetLSASecretKey(HKEY base, std::vector<uint8_t>& result);
bool GetLSASecrets(HKEY base, bool history,
    std::vector<PrintableLSASecret>& secrets);
bool GetNLKMSecretKey(HKEY base, std::vector<uint8_t>& result);
bool GetCachedHashes(HKEY base, std::vector<std::string>& result);

bool GetOSVersionBuild(HKEY base, int& build, double& version, bool& isServer);
bool GetHostnameAndDomain(HKEY base, std::string& hostname, std::string& domain);
bool GetServiceUser(HKEY base, const std::string& name, std::string& result);