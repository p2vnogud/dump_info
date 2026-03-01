/*
 * registry_nt.cpp
 *
 * Mirrors registry_nt.go which uses superdeye.SuperdSyscall() –
 * i.e. NT native API called directly from ntdll, resolved at runtime.
 *
 * Key fix from previous version:
 *   - OBJECT_ATTRIBUTES must NOT be #pragma pack(1).
 *     The NT kernel expects the natural-alignment layout.
 *   - REG_UNICODE_STRING (our struct) is passed as PUNICODE_STRING –
 *     the binary layout is identical so the cast is safe.
 *   - RootDirectory in OBJECT_ATTRIBUTES must be NULL when using
 *     an absolute path like \Registry\Machine\...
 *   - Access mask 0x02000000 (MAXIMUM_ALLOWED) works for SYSTEM;
 *     combine with KEY_READ (0x20019) if needed.
 */

#include "registry_nt.h"
#include <cstdio>
#include <cstring>
#include <cassert>

 // ── verify our struct layout matches what the kernel expects ─────────────────
 // REG_UNICODE_STRING must be 8 bytes (x64): Length(2)+MaxLen(2)+pad(4)+Buffer(8)
 // Wait – on x64 UNICODE_STRING is: Length(2)+MaxLen(2)+pad(4)+Buffer(8) = 16 bytes
 // But with #pragma pack(1) it becomes 10 bytes → WRONG.
 // We already removed pack(1) from these two structs in registry_nt.h.
 // Double-check:
static_assert(sizeof(REG_UNICODE_STRING) == sizeof(UNICODE_STRING),
    "REG_UNICODE_STRING phải khớp layout UNICODE_STRING");

// ─────────────────────────── runtime function pointers ───────────────────────

static PFN_NtOpenKeyEx          g_NtOpenKeyEx = nullptr;
static PFN_NtClose g_NtClose = nullptr;
static PFN_NtQueryKey           g_NtQueryKey = nullptr;
static PFN_NtQueryValueKey      g_NtQueryValueKey = nullptr;
static PFN_NtEnumerateKey       g_NtEnumerateKey = nullptr;
static PFN_NtEnumerateValueKey  g_NtEnumerateValueKey = nullptr;
static bool                     g_NtReady = false;

static bool InitNt()
{
    if (g_NtReady) return true;
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (!hNt) hNt = LoadLibraryA("ntdll.dll");
    if (!hNt) return false;

#define LOAD(fn) \
    g_##fn = reinterpret_cast<PFN_##fn>(GetProcAddress(hNt, #fn)); \
    if (!g_##fn) { fprintf(stderr,"[!] GetProcAddress(%s) failed\n",#fn); return false; }

    LOAD(NtOpenKeyEx)
        LOAD(NtClose)
        LOAD(NtQueryKey)
        LOAD(NtQueryValueKey)
        LOAD(NtEnumerateKey)
        LOAD(NtEnumerateValueKey)
#undef LOAD

        g_NtReady = true;
    return true;
}

// ─────────────────────────── UTF-16LE → std::string ──────────────────────────

std::string Utf16LeToString(const uint8_t* buf, size_t byteLen)
{
    if (!buf || byteLen < 2 || (byteLen & 1)) return "";
    size_t nChars = byteLen / 2;
    std::wstring ws(nChars, L'\0');
    for (size_t i = 0; i < nChars; ++i)
        ws[i] = static_cast<WCHAR>(buf[i * 2] | (static_cast<unsigned>(buf[i * 2 + 1]) << 8));
    size_t end = ws.find(L'\0');
    if (end != std::wstring::npos) ws.resize(end);
    if (ws.empty()) return "";
    int need = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(),
        nullptr, 0, nullptr, nullptr);
    if (need <= 0) return "";
    std::string out(need, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(),
        &out[0], need, nullptr, nullptr);
    return out;
}

// ─────────────────────────── helpers ─────────────────────────────────────────

// Build a REG_UNICODE_STRING from a wstring (buffer must outlive the struct)
static void MakeUS(REG_UNICODE_STRING& us, const std::wstring& s)
{
    us.Buffer = const_cast<WCHAR*>(s.c_str());
    us.Length = static_cast<USHORT>(s.size() * sizeof(WCHAR));
    us.MaximumLength = us.Length + sizeof(WCHAR);
}

// "SAM\SAM\..." → L"\Registry\Machine\SAM\SAM\..."
static std::wstring AbsPath(const std::string& rel)
{
    std::wstring w(rel.begin(), rel.end()); // ASCII subkey – safe
    return L"\\Registry\\Machine\\" + w;
}

// ─────────────────────────── NtQueryKeyInfo ──────────────────────────────────

bool NtQueryKeyInfo(HANDLE hKey, NtKeyInfo& out)
{
    if (!InitNt()) return false;

    ULONG bufSize = 512, resultLen = 0;
    std::vector<uint8_t> buf(bufSize);

    NTSTATUS st = g_NtQueryKey(hKey, KEY_FULL_INFO_CLASS,
        buf.data(), bufSize, &resultLen);
    if (st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW) {
        bufSize = resultLen;
        buf.resize(bufSize);
        st = g_NtQueryKey(hKey, KEY_FULL_INFO_CLASS,
            buf.data(), bufSize, &resultLen);
    }
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[!] NtQueryKey failed: 0x%08X\n", (unsigned)st);
        return false;
    }

    auto* info = reinterpret_cast<REG_KEY_FULL_INFORMATION*>(buf.data());
    if (info->ClassLength > 0 && info->ClassOffset > 0) {
        ULONG end = info->ClassOffset + info->ClassLength;
        if (end <= bufSize)
            out.ClassName = Utf16LeToString(buf.data() + info->ClassOffset,
                info->ClassLength);
    }
    out.SubKeys = info->SubKeys;
    out.MaxSubKeyLen = info->MaxNameLen;
    out.MaxClassLen = info->MaxClassLen;
    out.Values = info->Values;
    out.MaxValueNameLen = info->MaxValueNameLen;
    out.MaxValueLen = info->MaxValueDataLen;
    return true;
}

// ─────────────────────────── NtOpenSubKeyExt ─────────────────────────────────

HANDLE NtOpenSubKeyExt(const std::string& subkey,
    ULONG opts, ACCESS_MASK access)
{
    if (!InitNt()) return nullptr;

    std::wstring path = AbsPath(subkey);

    // IMPORTANT: must be natural-alignment (no pack pragma on these structs)
    REG_UNICODE_STRING uName;
    MakeUS(uName, path);

    // OBJECT_ATTRIBUTES – use the Windows SDK OBJECT_ATTRIBUTES, not our own
    // packed version, to guarantee correct kernel ABI.
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa,
        reinterpret_cast<PUNICODE_STRING>(&uName),
        OBJ_CASE_INSENSITIVE,
        NULL,   // RootDirectory = NULL → absolute path
        NULL);  // SecurityDescriptor

    HANDLE hKey = nullptr;
    NTSTATUS st = g_NtOpenKeyEx(&hKey, access, &oa, opts);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[ERROR] NtOpenKeyEx('%s') failed: 0x%08X (opts=0x%X, access=0x%X)\n",
            subkey.c_str(), (unsigned)st, opts, access);
        if (st == 0xC0000022) fprintf(stderr, "     → STATUS_ACCESS_DENIED (cần SeBackupPrivilege enabled)\n");
        return nullptr;
    }
    if (!hKey) return NtOpenSubKeyExt(subkey, opts, access); // rare retry
    return hKey;
}

// ─────────────────────────── NtCloseKeyHandle ────────────────────────────────

void NtCloseKeyHandle(HANDLE hKey)
{
    if (hKey && g_NtReady) g_NtClose(hKey);
}

// ─────────────────────────── NtQueryValue ────────────────────────────────────

bool NtQueryValue(HANDLE hKey, const std::string& valueName,
    std::vector<uint8_t>& dataOut, ULONG& typeOut)
{
    if (!InitNt()) return false;

    std::wstring wName(valueName.begin(), valueName.end());
    REG_UNICODE_STRING uVal;
    MakeUS(uVal, wName);
    if (valueName.empty()) uVal.Length = 0; // default value

    ULONG bufSize = 256, resultLen = 0;
    for (int attempt = 0; attempt < 3; ++attempt) {
        std::vector<uint8_t> buf(bufSize);
        NTSTATUS st = g_NtQueryValueKey(
            hKey,
            reinterpret_cast<PUNICODE_STRING>(&uVal),
            KEY_VALUE_PARTIAL_INFO_CLASS,
            buf.data(), bufSize, &resultLen);

        if (NT_SUCCESS(st)) {
            auto* pvi = reinterpret_cast<REG_KEY_VALUE_PARTIAL_INFORMATION*>(buf.data());
            typeOut = pvi->Type;
            dataOut.assign(&pvi->Data[0], &pvi->Data[0] + pvi->DataLength);
            return true;
        }
        if (st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW) {
            bufSize = (resultLen > bufSize) ? resultLen : bufSize * 2;
            continue;
        }
        fprintf(stderr, "[!] NtQueryValueKey(\"%s\") = 0x%08X\n",
            valueName.c_str(), (unsigned)st);
        return false;
    }
    return false;
}

// ─────────────────────────── NtQueryValueString ──────────────────────────────

bool NtQueryValueString(HANDLE hKey, const std::string& name, std::string& out)
{
    std::vector<uint8_t> data; ULONG type = 0;
    if (!NtQueryValue(hKey, name, data, type)) return false;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return false;
    out = Utf16LeToString(data.data(), data.size());
    return true;
}

// ─────────────────────────── NtEnumValue ─────────────────────────────────────

bool NtEnumValue(HANDLE hKey, ULONG index, std::string& nameOut)
{
    if (!InitNt()) return false;
    ULONG bufSize = 256, resultLen = 0;
    std::vector<uint8_t> buf(bufSize);

    NTSTATUS st = g_NtEnumerateValueKey(hKey, index, KEY_VALUE_BASIC_INFO_CLASS,
        buf.data(), bufSize, &resultLen);
    if (st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW) {
        bufSize = resultLen; buf.resize(bufSize);
        st = g_NtEnumerateValueKey(hKey, index, KEY_VALUE_BASIC_INFO_CLASS,
            buf.data(), bufSize, &resultLen);
    }
    if (!NT_SUCCESS(st)) return false;

    auto* info = reinterpret_cast<REG_KEY_VALUE_BASIC_INFORMATION*>(buf.data());
    size_t off = offsetof(REG_KEY_VALUE_BASIC_INFORMATION, Name);
    nameOut = Utf16LeToString(buf.data() + off, info->NameLength);
    return true;
}

// ─────────────────────────── NtEnumSubKey ────────────────────────────────────

bool NtEnumSubKey(HANDLE hKey, ULONG index, std::string& nameOut)
{
    if (!InitNt()) return false;
    ULONG bufSize = 256, resultLen = 0;
    std::vector<uint8_t> buf(bufSize);

    NTSTATUS st = g_NtEnumerateKey(hKey, index, KEY_BASIC_INFO_CLASS,
        buf.data(), bufSize, &resultLen);
    if (st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW) {
        bufSize = resultLen; buf.resize(bufSize);
        st = g_NtEnumerateKey(hKey, index, KEY_BASIC_INFO_CLASS,
            buf.data(), bufSize, &resultLen);
    }
    if (!NT_SUCCESS(st)) return false;

    auto* info = reinterpret_cast<REG_KEY_BASIC_INFORMATION*>(buf.data());
    size_t off = offsetof(REG_KEY_BASIC_INFORMATION, Name);
    nameOut = Utf16LeToString(buf.data() + off, info->NameLength);
    return true;
}

// ─────────────────────────── NtGetValueNames ─────────────────────────────────

bool NtGetValueNames(HANDLE hKey, std::vector<std::string>& out)
{
    NtKeyInfo info;
    if (!NtQueryKeyInfo(hKey, info)) return false;
    out.reserve(info.Values);
    for (ULONG i = 0; i < info.Values; ++i) {
        std::string name;
        if (!NtEnumValue(hKey, i, name)) return false;
        out.push_back(std::move(name));
    }
    return true;
}

// ─────────────────────────── NtGetSubKeyNames ────────────────────────────────

bool NtGetSubKeyNames(const std::string& subkey,
    ULONG opts, ACCESS_MASK access,
    std::vector<std::string>& out)
{
    HANDLE h = NtOpenSubKeyExt(subkey, opts, access);
    if (!h) return false;

    NtKeyInfo info;
    if (!NtQueryKeyInfo(h, info)) { NtCloseKeyHandle(h); return false; }

    out.reserve(info.SubKeys);
    for (ULONG i = 0; i < info.SubKeys; ++i) {
        std::string name;
        if (!NtEnumSubKey(h, i, name)) { NtCloseKeyHandle(h); return false; }
        out.push_back(std::move(name));
    }
    NtCloseKeyHandle(h);
    return true;
}