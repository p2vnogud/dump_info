#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>    // HANDLE, ULONG, WCHAR, ...
#include <stdint.h>
#include <string>
#include <vector>

// ── Định nghĩa thủ công các struct và macro NT cần thiết ────────────────────────
// (không phụ thuộc winternl.h hoặc ntdef.h)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;          // WCHAR*
} UNICODE_STRING, * PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// Macro chuẩn (copy từ tài liệu Microsoft + cộng đồng)
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
}

// Các flag thường dùng
#define OBJ_CASE_INSENSITIVE            0x00000040L
#define OBJ_KERNEL_HANDLE               0x00000200L   // nếu cần, nhưng ở user-mode thường không dùng

// ── NTSTATUS và các macro thành công ────────────────────────────────────────
#ifndef _NTSTATUS_DEFINED
# define _NTSTATUS_DEFINED
typedef LONG NTSTATUS;
#endif

#ifndef NT_SUCCESS
# define NT_SUCCESS(st) (((NTSTATUS)(st)) >= 0)
#endif

#ifndef STATUS_SUCCESS
# define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
# define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
# define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

// ── Information class (giữ nguyên) ──────────────────────────────────────────
#define KEY_BASIC_INFO_CLASS            0UL
#define KEY_FULL_INFO_CLASS             2UL
#define KEY_VALUE_BASIC_INFO_CLASS      0UL
#define KEY_VALUE_PARTIAL_INFO_CLASS    2UL

// ── REG_UNICODE_STRING ──────────────────────────────────────────────────────
// Giữ nguyên như cũ, nhưng đảm bảo NO #pragma pack quanh nó
typedef struct _REG_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR* Buffer;
} REG_UNICODE_STRING;

// ── Các struct thông tin registry (giữ nguyên) ──────────────────────────────
#pragma pack(push, 1)
typedef struct _REG_KEY_FULL_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG MaxClassLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    WCHAR Class[1];
} REG_KEY_FULL_INFORMATION;

typedef struct _REG_KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} REG_KEY_BASIC_INFORMATION;

typedef struct _REG_KEY_VALUE_BASIC_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} REG_KEY_VALUE_BASIC_INFORMATION;

typedef struct _REG_KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    BYTE Data[1];
} REG_KEY_VALUE_PARTIAL_INFORMATION;
#pragma pack(pop)

// ── Function pointer typedefs (sửa POBJECT_ATTRIBUTES và PUNICODE_STRING) ───
typedef NTSTATUS(NTAPI* PFN_NtOpenKeyEx)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,   // dùng struct tự định nghĩa
    ULONG OpenOptions);

//typedef NTSTATUS(NTAPI* PFN_NtCloseKey)(HANDLE KeyHandle);
typedef NTSTATUS(NTAPI* PFN_NtClose)(HANDLE Handle);

typedef NTSTATUS(NTAPI* PFN_NtQueryKey)(
    HANDLE KeyHandle,
    ULONG KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength);

typedef NTSTATUS(NTAPI* PFN_NtQueryValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,              // dùng UNICODE_STRING*
    ULONG KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength);

typedef NTSTATUS(NTAPI* PFN_NtEnumerateKey)(
    HANDLE KeyHandle,
    ULONG Index,
    ULONG KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength);

typedef NTSTATUS(NTAPI* PFN_NtEnumerateValueKey)(
    HANDLE KeyHandle,
    ULONG Index,
    ULONG KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength);

// ── Result type và public API (giữ nguyên) ──────────────────────────────────
struct NtKeyInfo {
    std::string ClassName;
    uint32_t SubKeys = 0;
    uint32_t MaxSubKeyLen = 0;
    uint32_t MaxClassLen = 0;
    uint32_t Values = 0;
    uint32_t MaxValueNameLen = 0;
    uint32_t MaxValueLen = 0;
};

// Public API declarations (giữ nguyên như cũ)
std::string Utf16LeToString(const uint8_t* buf, size_t byteLen);
bool NtQueryKeyInfo(HANDLE hKey, NtKeyInfo& out);
HANDLE NtOpenSubKeyExt(const std::string& subkey, ULONG opts, ACCESS_MASK access);
void NtCloseKeyHandle(HANDLE hKey);
bool NtQueryValue(HANDLE hKey, const std::string& valueName,
    std::vector<uint8_t>& dataOut, ULONG& typeOut);
bool NtQueryValueString(HANDLE hKey, const std::string& name, std::string& out);
bool NtGetValueNames(HANDLE hKey, std::vector<std::string>& out);
bool NtGetSubKeyNames(const std::string& subkey, ULONG opts, ACCESS_MASK access,
    std::vector<std::string>& out);
bool NtEnumValue(HANDLE hKey, ULONG index, std::string& nameOut);
bool NtEnumSubKey(HANDLE hKey, ULONG index, std::string& nameOut);