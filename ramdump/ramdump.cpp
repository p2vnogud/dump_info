#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <string>
#include <vector>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#define fseek64  _fseeki64
#define ftell64  _ftelli64
#define CLOCK()  ((double)GetTickCount64()/1000.0)
#else
#define fseek64  fseeko
#define ftell64  ftello
#include <sys/time.h>
static double CLOCK() {
    struct timeval tv; gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1e6;
}
#endif

// ============================================================
// Constants
// ============================================================
#define SIG_PAGE      0x45474150UL  // 'PAGE' — Windows crash dump
#define SIG_DUMP      0x504D5544UL  // 'DUMP' — ValidDump field
#define SIG_MDMP      0x504D444DUL  // 'MDMP' — minidump (invalid input)
#define PAGE_SZ       0x1000ULL
#define CR3_MASK      (~(PAGE_SZ - 1))  // mask 12 low bits

// Minidump stream types
#define MDMP_SYSINFO  7
#define MDMP_MODLIST  4
#define MDMP_MEM64    9

// ============================================================
// Crash Dump Header (DUMP_HEADER64) — Windows DDK layout
// Total size = 1 page (0x1000 bytes)
// ============================================================
#pragma pack(push,1)
struct PhysRun {
    uint64_t BasePage;
    uint64_t PageCount;
};
struct DumpHeader {
    uint32_t Signature;           // 0x000 'PAGE'
    uint32_t ValidDump;           // 0x004 'DUMP'
    uint32_t MajorVersion;        // 0x008
    uint32_t MinorVersion;        // 0x00C  e.g. 19045
    uint64_t DirectoryTableBase;  // 0x010  CR3 (with flag bits)
    uint64_t PfnDatabase;         // 0x018
    uint64_t PsLoadedModuleList;  // 0x020  VA
    uint64_t PsActiveProcessHead; // 0x028  VA ← key
    uint32_t MachineImageType;    // 0x030  0x8664=x64
    uint32_t NumberProcessors;    // 0x034
    uint32_t BugCheckCode;        // 0x038
    uint32_t _pad1;
    uint64_t BugCheckParameters[4]; // 0x040
    uint8_t  VersionUser[32];     // 0x060
    uint64_t KdDebuggerDataBlock; // 0x080  VA of KDBG
    // PhysicalMemoryBlock starts at 0x088
    uint32_t PhysNumRuns;         // 0x088
    uint32_t _pad2;               // 0x08C
    uint64_t PhysNumPages;        // 0x090
    PhysRun  PhysRuns[32];        // 0x098  up to 32 runs shown, real array may be larger
};

// KDDEBUGGER_DATA64 — kernel debug data block
struct KdbgBlock {
    uint64_t Flink;               // 0x000
    uint64_t Blink;               // 0x008
    uint8_t  OwnerTag[4];         // 0x010 'KDBG'
    uint16_t Size;                // 0x014
    uint16_t _pad;
    uint64_t KernBase;            // 0x018
    uint64_t BreakpointWithStatus;// 0x020
    uint64_t SavedContext;        // 0x028
    uint8_t  _pad2[16];
    uint64_t PsLoadedModuleList;  // 0x040 (approx — varies)
    uint64_t PsActiveProcessHead; // 0x050 ← better source
};
#pragma pack(pop)

// ============================================================
// EPROCESS offsets — verified with WinDbg on Windows 10/11 x64
// ============================================================
struct EpOff {
    uint32_t DTB;    // KPROCESS.DirectoryTableBase (= EPROCESS+0)
    uint32_t PID;    // EPROCESS.UniqueProcessId
    uint32_t APL;    // EPROCESS.ActiveProcessLinks (LIST_ENTRY.Flink)
    uint32_t IMG;    // EPROCESS.ImageFileName[15]
    uint32_t PEB;    // EPROCESS.Peb
    const char* tag;
};
static const EpOff EP_OFFS[] = {
    { 0x028, 0x2E0, 0x2E8, 0x450, 0x3F8, "Win10 1507-1809 (10240-17763)" },
    { 0x028, 0x440, 0x448, 0x5A8, 0x550, "Win10 1903+ / Win11 / Srv2019+" },
};

// ============================================================
// Memory Run — maps physical address range to file offset
// ============================================================
struct MemRun {
    uint64_t pa;      // physical base address
    uint64_t size;    // byte count
    uint64_t foff;    // file offset
};

// ============================================================
// DumpFile context
// ============================================================
struct Dump {
    FILE* fp = nullptr;
    uint64_t          fsize = 0;
    bool              is_crdp = false;  // crash dump vs raw
    std::vector<MemRun> runs;

    // From crash dump header:
    uint64_t cr3 = 0;   // ALREADY masked (flag bits removed)
    uint64_t pshead = 0;   // VA of PsActiveProcessHead
    uint64_t kdbgva = 0;   // VA of KDBG

    ~Dump() { if (fp) fclose(fp); }

    // PA → file offset (returns false if not in any run)
    bool pa2off(uint64_t pa, uint64_t& off) const {
        for (auto& r : runs)
            if (pa >= r.pa && pa < r.pa + r.size) {
                off = r.foff + (pa - r.pa); return true;
            }
        return false;
    }

    // Read physical memory (handles run boundaries)
    bool rphys(uint64_t pa, void* buf, size_t sz) const {
        uint8_t* p = (uint8_t*)buf;
        while (sz) {
            uint64_t off = 0;
            if (!pa2off(pa, off)) return false;
            // how much fits in this run?
            size_t chunk = sz;
            for (auto& r : runs)
                if (pa >= r.pa && pa < r.pa + r.size) {
                    uint64_t left = r.pa + r.size - pa;
                    if (left < chunk) chunk = (size_t)left;
                    break;
                }
            if (fseek64(fp, (int64_t)off, SEEK_SET)) return false;
            if (fread(p, 1, chunk, fp) != chunk) return false;
            p += chunk; pa += chunk; sz -= chunk;
        }
        return true;
    }
    template<typename T> bool rphysT(uint64_t pa, T& v) const {
        return rphys(pa, &v, sizeof(T));
    }

    uint64_t total_phys() const {
        uint64_t t = 0; for (auto& r : runs) t += r.size; return t;
    }
};

// ============================================================
// x64 4-Level Page Table Walk
// ============================================================
#define PML4I(v) (((v)>>39)&0x1FF)
#define PDPTI(v) (((v)>>30)&0x1FF)
#define PDI(v)   (((v)>>21)&0x1FF)
#define PTI(v)   (((v)>>12)&0x1FF)
#define PGOFF(v) ((v)&0xFFF)
#define PTE_PA(e) ((e)&0x000FFFFFFFFFF000ULL)
#define PTE_P     1ULL
#define PTE_PS    (1ULL<<7)

static bool va2pa(const Dump& d, uint64_t cr3, uint64_t va, uint64_t& pa) {
    uint64_t e = 0;
    // PML4
    if (!d.rphysT(cr3 + PML4I(va) * 8, e) || !(e & PTE_P)) return false;
    // PDPT
    if (!d.rphysT(PTE_PA(e) + PDPTI(va) * 8, e) || !(e & PTE_P)) return false;
    if (e & PTE_PS) { pa = (e & 0xFFFFFC0000000ULL) | (va & 0x3FFFFFFF); return true; }
    // PD
    if (!d.rphysT(PTE_PA(e) + PDI(va) * 8, e) || !(e & PTE_P)) return false;
    if (e & PTE_PS) { pa = (e & 0xFFFFFFFE00000ULL) | (va & 0x1FFFFF); return true; }
    // PT
    if (!d.rphysT(PTE_PA(e) + PTI(va) * 8, e) || !(e & PTE_P)) return false;
    pa = PTE_PA(e) | PGOFF(va); return true;
}

static bool rvirt(const Dump& d, uint64_t cr3, uint64_t va,
    void* buf, size_t sz) {
    uint8_t* p = (uint8_t*)buf;
    while (sz) {
        uint64_t pa = 0;
        if (!va2pa(d, cr3, va, pa)) return false;
        size_t n = (std::min)(sz, (size_t)(PAGE_SZ - (va & 0xFFF)));
        if (!d.rphys(pa, p, n)) return false;
        p += n; va += n; sz -= n;
    }
    return true;
}
template<typename T>
static bool rvirtT(const Dump& d, uint64_t cr3, uint64_t va, T& v) {
    return rvirt(d, cr3, va, &v, sizeof(T));
}

// ============================================================
// Open dump — detect format, parse runs
// ============================================================
static bool open_dump(Dump& d, const char* path) {
    d.fp = fopen(path, "rb");
    if (!d.fp) { printf("[-] Cannot open: %s\n", path); return false; }
    fseek64(d.fp, 0, SEEK_END); d.fsize = (uint64_t)ftell64(d.fp);
    fseek64(d.fp, 0, SEEK_SET);
    printf("[+] File: %s  (%.2f GB)\n", path, (double)d.fsize / 1024 / 1024 / 1024);

    // Read 512 bytes for detection (header is always ≥ this)
    uint8_t peek[512] = {};
    fread(peek, 1, 512, d.fp);
    fseek64(d.fp, 0, SEEK_SET);

    uint32_t sig = *(uint32_t*)(peek + 0);
    uint32_t sig2 = *(uint32_t*)(peek + 4);

    // Print first 16 bytes for diagnosis
    printf("[*] Header bytes: ");
    for (int i = 0; i < 16; i++) printf("%02X ", peek[i]);
    printf("\n");
    printf("[*] As ASCII:     ");
    for (int i = 0; i < 16; i++) printf("%c", (peek[i] >= 0x20 && peek[i] < 0x7F) ? peek[i] : '.');
    printf("\n");

    if (sig == SIG_MDMP) {
        printf("[-] Input is a Minidump — need Full Memory Dump from DumpIt\n");
        return false;
    }

    if (sig == SIG_PAGE && sig2 == SIG_DUMP) {
        // --------------------------------------------------------
        // Standard Windows Full Memory Dump (DumpIt default output)
        // --------------------------------------------------------
        d.is_crdp = true;
        printf("[+] Format: Windows Full Memory Dump (PAGE+DUMP)\n");

        // Read full 4KB header
        std::vector<uint8_t> hb(0x1000, 0);
        fseek64(d.fp, 0, SEEK_SET);
        fread(hb.data(), 1, 0x1000, d.fp);
        auto* h = (DumpHeader*)hb.data();

        // *** CRITICAL: mask CR3 flag bits ***
        // Windows stores CR3 with PML4 entry flags (bits 0-11)
        // Real CR3 = address of PML4 table = value & ~0xFFF
        d.cr3 = h->DirectoryTableBase & CR3_MASK;
        d.pshead = h->PsActiveProcessHead;
        d.kdbgva = h->KdDebuggerDataBlock;

        // DumpType is at 0xF8, NOT 0xF0
        uint32_t dumptype = *(uint32_t*)(hb.data() + 0xF8);

        printf("[+] Windows %u.%u | DumpType=%u | CPUs=%u\n",
            h->MajorVersion, h->MinorVersion,
            dumptype, h->NumberProcessors);
        printf("[+] CR3 raw:   0x%016llX\n", h->DirectoryTableBase);
        printf("[+] CR3 clean: 0x%016llX  (flag bits masked)\n", d.cr3);
        printf("[+] PsActiveProcessHead: 0x%016llX\n", d.pshead);
        printf("[+] KdDebuggerDataBlock: 0x%016llX\n", d.kdbgva);

        // Parse run array at 0x088
        // File layout: [header 4KB][pages from run[0]][pages from run[1]]...
        uint32_t nruns = h->PhysNumRuns;
        uint64_t cursor = 0x1000;  // first byte after header

        printf("[+] Physical runs: %u  (%.2f GB)\n",
            nruns, (double)h->PhysNumPages * PAGE_SZ / 1024 / 1024 / 1024);

        // If nruns > 32 we need to read from file directly
        // Header struct only has PhysRuns[32], but array can be larger
        // Read raw bytes for safety
        uint32_t max_runs = (std::min)(nruns, (uint32_t)256);
        for (uint32_t i = 0; i < max_runs; i++) {
            uint64_t run_off = 0x098 + i * 16;
            if (run_off + 16 > hb.size()) break;
            uint64_t bpage = *(uint64_t*)(hb.data() + run_off);
            uint64_t bcount = *(uint64_t*)(hb.data() + run_off + 8);
            if (bpage == 0 && bcount == 0) break;

            MemRun r;
            r.pa = bpage * PAGE_SZ;
            r.size = bcount * PAGE_SZ;
            r.foff = cursor;
            d.runs.push_back(r);
            cursor += r.size;

            printf("    [%u] PA=0x%010llX  size=%.1fMB  foff=0x%llX\n",
                i, r.pa, (double)r.size / 1024 / 1024, r.foff);
        }

    }
    else {
        // --------------------------------------------------------
        // Raw flat dump or unknown
        // --------------------------------------------------------
        d.is_crdp = false;
        printf("[+] Format: Raw / unknown (no PAGE+DUMP header)\n");
        printf("[*] Treating as flat raw memory\n");
        MemRun r; r.pa = 0; r.size = d.fsize; r.foff = 0;
        d.runs.push_back(r);
    }

    printf("[+] Mapped: %.2f GB\n\n", (double)d.total_phys() / 1024 / 1024 / 1024);
    return true;
}

// ============================================================
// Try to read KDBG and get accurate PsActiveProcessHead
// ============================================================
static void try_kdbg(Dump& d) {
    if (!d.kdbgva || !d.cr3) return;
    printf("[*] Reading KDBG at VA 0x%llX...\n", d.kdbgva);
    uint64_t kpa = 0;
    if (!va2pa(d, d.cr3, d.kdbgva, kpa)) {
        printf("[!] VaToPhys(KDBG) failed — using PsActiveHead from header\n");
        return;
    }
    KdbgBlock kb = {};
    if (!d.rphys(kpa, &kb, sizeof(kb))) {
        printf("[!] ReadPhys(KDBG) failed\n"); return;
    }
    if (memcmp(kb.OwnerTag, "KDBG", 4) != 0) {
        printf("[!] KDBG tag mismatch (may be XOR-encoded) — using header value\n");
        return;
    }
    printf("[+] KDBG OK: KernBase=0x%llX\n", kb.KernBase);
    // PsActiveProcessHead at fixed offset 0x050 in the struct
    // (offset may vary — use only if in kernel VA range)
    if (kb.PsActiveProcessHead > 0xFFFF000000000000ULL) {
        printf("[+] PsActiveProcessHead (KDBG): 0x%llX\n", kb.PsActiveProcessHead);
        d.pshead = kb.PsActiveProcessHead;
    }
}

// ============================================================
// Detect EPROCESS offsets
// ============================================================
static bool detect_offsets(const Dump& d, const EpOff*& best) {
    printf("[*] Detecting EPROCESS offsets...\n");
    for (auto& o : EP_OFFS) {
        uint64_t flink = 0;
        if (!rvirtT(d, d.cr3, d.pshead, flink) || !flink || flink == d.pshead) continue;
        uint64_t ep = flink - o.APL;
        uint64_t pid = 0;
        if (!rvirtT(d, d.cr3, ep + o.PID, pid)) continue;
        if (pid != 0 && pid != 4 && pid != 8) continue;
        char nm[16] = {};
        rvirt(d, d.cr3, ep + o.IMG, nm, 15);
        if (pid == 4 || strstr(nm, "System") || strstr(nm, "Idle")) {
            printf("[+] Offsets: %s  (first proc PID=%llu '%s')\n", o.tag, pid, nm);
            best = &o; return true;
        }
    }
    printf("[!] Offset detect failed — defaulting to Win10 1903+\n");
    best = &EP_OFFS[1]; return false;
}

// ============================================================
// Process struct + walk EPROCESS list
// ============================================================
struct Proc {
    uint64_t cr3; // MASKED
    uint64_t pid;
    uint64_t peb;
    char     name[16];
};

static bool walk_procs(const Dump& d, const EpOff& o,
    std::vector<Proc>& out) {
    printf("[*] Walking EPROCESS list...\n");
    uint64_t flink = 0;
    if (!rvirtT(d, d.cr3, d.pshead, flink)) {
        printf("[-] Cannot read PsActiveProcessHead.Flink\n");
        // Diagnostic
        uint64_t pa = 0; bool ok = va2pa(d, d.cr3, d.pshead, pa);
        printf("    va2pa(0x%llX) = %s  PA=0x%llX\n", d.pshead, ok ? "OK" : "FAIL", pa);
        if (ok) { uint64_t fo = 0; printf("    in_run=%s\n", d.pa2off(pa, fo) ? "YES" : "NO"); }
        return false;
    }
    uint64_t cur = flink, head = d.pshead;
    for (int lim = 2048; lim-- && cur && cur != head;) {
        uint64_t ep = cur - o.APL;
        Proc p = {};
        rvirtT(d, d.cr3, ep + o.PID, p.pid);
        rvirtT(d, d.cr3, ep + o.DTB, p.cr3); p.cr3 &= CR3_MASK;
        rvirtT(d, d.cr3, ep + o.PEB, p.peb);
        rvirt(d, d.cr3, ep + o.IMG, p.name, 15); p.name[15] = 0;
        out.push_back(p);
        uint64_t nx = 0;
        if (!rvirtT(d, d.cr3, cur, nx) || !nx || nx == cur) break;
        cur = nx;
    }
    printf("[+] Found %zu processes\n", out.size());
    return !out.empty();
}

// ============================================================
// Scan physical memory for EPROCESS (fallback for raw dumps)
// Scans page-aligned (every 4KB) — much faster than byte-by-byte
// ============================================================
static bool scan_eprocess(Dump& d, const char* target,
    const EpOff& o, Proc& found) {
    printf("[*] Scanning physical memory for '%s' EPROCESS...\n", target);
    printf("    (Page-aligned scan, 4KB steps)\n");

    std::string tgt(target);
    std::transform(tgt.begin(), tgt.end(), tgt.begin(), ::tolower);

    const size_t BUF_PAGES = 4096;  // 4096 pages = 16MB buffer
    const size_t BUF = BUF_PAGES * PAGE_SZ;
    std::vector<uint8_t> buf(BUF);

    uint64_t total_scanned = 0;
    double   last_print = CLOCK();
    bool     any_found = false;

    // Scan per run, aligned to PAGE_SZ
    for (auto& run : d.runs) {
        uint64_t pa = run.pa;
        uint64_t foff = run.foff;
        uint64_t fend = run.foff + run.size;

        while (foff < fend) {
            size_t toRead = (size_t)(std::min)((uint64_t)BUF, fend - foff);
            // Align to page boundary
            toRead = (toRead / PAGE_SZ) * PAGE_SZ;
            if (!toRead) break;

            if (fseek64(d.fp, (int64_t)foff, SEEK_SET)) break;
            size_t rd = fread(buf.data(), 1, toRead, d.fp);
            if (!rd) break;

            // Scan each page (ImageFileName is always within one page if well-aligned)
            for (size_t pg = 0; pg + o.IMG + 16 < rd; pg += PAGE_SZ) {
                // ImageFileName is at ep+IMG_OFFSET — but EPROCESS spans multiple pages
                // Strategy: treat each page start as potential EPROCESS base
                // Check if name at +IMG_OFFSET is readable and matches target
                if (pg + o.IMG + 15 >= rd) continue;
                char* nm = (char*)(buf.data() + pg + o.IMG);

                // Quick reject: first char must be printable ASCII
                if (nm[0] < 0x20 || nm[0]>0x7E) continue;

                // Build lowercase name
                char lname[16] = {};
                int nlen = 0;
                while (nlen < 14 && nm[nlen] >= 0x20 && nm[nlen] < 0x7F) lname[nlen] = tolower(nm[nlen++]);
                if (nlen < 2 || nm[nlen] != 0) continue;

                // Does it match target?
                if (!strstr(lname, tgt.c_str())) continue;

                // Validate PID: must be non-zero, multiple of 4, <1M
                if (pg + o.PID + 8 > rd) continue;
                uint64_t pid = *(uint64_t*)(buf.data() + pg + o.PID);
                if (pid == 0 || pid % 4 != 0 || pid > 0x100000) continue;

                // Validate CR3: page-aligned, within physical range
                if (pg + o.DTB + 8 > rd) continue;
                uint64_t cr3 = *(uint64_t*)(buf.data() + pg + o.DTB) & CR3_MASK;
                if (!cr3) continue;
                bool cr3ok = false;
                for (auto& r2 : d.runs)
                    if (cr3 >= r2.pa && cr3 < r2.pa + r2.size) { cr3ok = true; break; }
                if (!cr3ok) continue;

                uint64_t epa = pa + (foff - run.foff) + pg;
                printf("[+] Found '%s' PA=0x%llX  PID=%llu  CR3=0x%llX\n",
                    nm, epa, pid, cr3);

                found.pid = pid; found.cr3 = cr3;
                memcpy(found.name, nm, 15); found.name[15] = 0;
                return true;
            }

            foff += rd; pa += rd;
            total_scanned += rd;

            // Progress every 2 seconds
            double now = CLOCK();
            if (now - last_print >= 2.0) {
                printf("[*]   Scanned %.1f / %.1f GB ...\n",
                    (double)total_scanned / 1024 / 1024 / 1024,
                    (double)d.total_phys() / 1024 / 1024 / 1024);
                fflush(stdout);
                last_print = now;
            }
        }
    }
    printf("[-] Process '%s' not found by scan\n", target);
    return false;
}

// ============================================================
// Scan VA space of process — fast using page table hierarchy
// ============================================================
struct Seg { uint64_t va; uint64_t sz; };

static std::vector<Seg> scan_va(const Dump& d, uint64_t cr3, uint64_t pid) {
    printf("[*] Mapping VA space of PID=%llu (CR3=0x%llX)...\n", pid, cr3);

    std::vector<Seg> segs;
    const uint64_t UEND = 0x00007FFFFFFFFFFFULL;
    uint64_t va = 0x10000;
    Seg cur = { 0,0 };
    uint64_t pages_mapped = 0;
    double last_print = CLOCK();

    while (va <= UEND) {
        // -- PML4 level: if entry absent → skip 512GB --
        uint64_t e = 0;
        if (!d.rphysT(cr3 + PML4I(va) * 8, e) || !(e & PTE_P)) {
            if (cur.sz) { segs.push_back(cur); cur = { 0,0 }; }
            uint64_t skip = 512ULL * 1024 * 1024 * 1024;
            va = (va + skip) & ~(skip - 1); continue;
        }
        // -- PDPT level: if absent → skip 1GB --
        uint64_t pdpt = PTE_PA(e);
        if (!d.rphysT(pdpt + PDPTI(va) * 8, e) || !(e & PTE_P)) {
            if (cur.sz) { segs.push_back(cur); cur = { 0,0 }; }
            uint64_t skip = 1ULL * 1024 * 1024 * 1024;
            va = (va + skip) & ~(skip - 1); continue;
        }
        if (e & PTE_PS) { // 1GB page
            if (!cur.sz) cur.va = va; cur.sz += 1ULL * 1024 * 1024 * 1024;
            pages_mapped += 262144; va += 1ULL * 1024 * 1024 * 1024; goto progress;
        }
        // -- PD level: if absent → skip 2MB --
        {
            uint64_t pd = PTE_PA(e);
            if (!d.rphysT(pd + PDI(va) * 8, e) || !(e & PTE_P)) {
                if (cur.sz) { segs.push_back(cur); cur = { 0,0 }; }
                uint64_t skip = 2ULL * 1024 * 1024;
                va = (va + skip) & ~(skip - 1); continue;
            }
            if (e & PTE_PS) { // 2MB page
                if (!cur.sz) cur.va = va; cur.sz += 2ULL * 1024 * 1024;
                pages_mapped += 512; va += 2ULL * 1024 * 1024; goto progress;
            }
            // -- PT level: read all 512 PTEs at once --
            uint64_t pt = PTE_PA(e);
            uint64_t ptes[512] = {};
            bool pt_ok = d.rphys(pt, ptes, 4096);
            uint64_t pt_base = va & ~((512 * PAGE_SZ) - 1);
            for (int i = (int)PTI(va); i < 512; i++) {
                uint64_t pv = pt_base + (uint64_t)i * PAGE_SZ;
                if (pv > UEND) break;
                bool mapped = pt_ok && (ptes[i] & PTE_P);
                if (mapped) {
                    if (!cur.sz) cur.va = pv; cur.sz += PAGE_SZ; pages_mapped++;
                }
                else {
                    if (cur.sz) { segs.push_back(cur); cur = { 0,0 }; }
                }
            }
            va = pt_base + 512 * PAGE_SZ;
        }
    progress:
        {
            double now = CLOCK();
            if (now - last_print >= 2.0) {
                printf("[*]   VA 0x%010llX  mapped=%.1fMB  segs=%zu\n",
                    va, (double)pages_mapped * PAGE_SZ / 1024 / 1024, segs.size());
                fflush(stdout); last_print = now;
            }
        }
    }
    if (cur.sz) segs.push_back(cur);

    printf("[+] VA scan done: %.1f MB in %zu segments\n",
        (double)pages_mapped * PAGE_SZ / 1024 / 1024, segs.size());
    return segs;
}

// ============================================================
// Write Minidump (Memory64List format)
// Compatible with pypykatz, Mimikatz, WinDbg
// ============================================================
static bool write_minidump(const Dump& d, const Proc& proc,
    const std::vector<Seg>& segs,
    const char* path) {
    FILE* f = fopen(path, "wb");
    if (!f) { printf("[-] Cannot create: %s\n", path); return false; }

    auto w2 = [&](uint16_t v) {fwrite(&v, 2, 1, f); };
    auto w4 = [&](uint32_t v) {fwrite(&v, 4, 1, f); };
    auto w8 = [&](uint64_t v) {fwrite(&v, 8, 1, f); };

    // Offsets:
    //  0    : MINIDUMP_HEADER (32)
    //  32   : DIRECTORY × 3  (36)
    //  68   : SystemInfo     (56)
    //  124  : ModuleList     (4)
    //  128  : Memory64 hdr   (16 + 16*N)
    //  128+…: bulk data
    const uint32_t SI_OFF = 68, SI_SZ = 56;
    const uint32_t ML_OFF = 124, ML_SZ = 4;
    const uint32_t M64_OFF = 128;
    const uint32_t M64_HDR = (uint32_t)(16 + segs.size() * 16);
    const uint64_t BULK = M64_OFF + M64_HDR;

    // Header
    w4(0x504D444D); w4(0x0000A793); w4(3); w4(32);
    w4(0); w4((uint32_t)time(NULL)); w8(0x21);

    // Directory
    w4(MDMP_SYSINFO); w4(SI_SZ);  w4(SI_OFF);
    w4(MDMP_MODLIST); w4(ML_SZ);  w4(ML_OFF);
    w4(MDMP_MEM64);   w4(M64_HDR); w4(M64_OFF);

    // SystemInfo (56 bytes)
    w2(9); w2(6); w2(0x9E0A); w2(0x0401);  // arch/level/rev/nproc+type
    w4(10); w4(0); w4(19041); w4(2);        // major/minor/build/platform
    w4(0); w4(0x0300);                       // CSDRva / SuiteMask+Rsv
    fwrite("GenuineIntel", 12, 1, f);
    w4(0x000906EA); w4(0xBFEBFBFF); w4(0);

    // ModuleList
    w4(0);

    // Memory64List header
    w8((uint64_t)segs.size()); w8(BULK);
    for (auto& s : segs) { w8(s.va); w8(s.sz); }

    // Bulk pages
    printf("[*] Writing pages...\n");
    std::vector<uint8_t> pg(PAGE_SZ, 0);
    uint64_t ok = 0, zp = 0;
    double last_print = CLOCK();

    for (auto& seg : segs) {
        for (uint64_t va = seg.va; va < seg.va + seg.sz; va += PAGE_SZ) {
            uint64_t pa = 0;
            if (va2pa(d, proc.cr3, va, pa) && d.rphys(pa, pg.data(), PAGE_SZ)) {
                fwrite(pg.data(), 1, PAGE_SZ, f); ok++;
            }
            else {
                memset(pg.data(), 0, PAGE_SZ);
                fwrite(pg.data(), 1, PAGE_SZ, f); zp++;
            }
            double now = CLOCK();
            if (now - last_print >= 2.0) {
                printf("[*]   %.0f MB  (ok=%llu zero=%llu)\n",
                    (double)(ok + zp) * PAGE_SZ / 1024 / 1024, ok, zp);
                fflush(stdout); last_print = now;
            }
        }
    }
    printf("\n");
    fclose(f);
    printf("[+] %s written — %.0f MB  (%llu ok pages, %llu zero)\n",
        path, (double)(ok + zp) * PAGE_SZ / 1024 / 1024, ok, zp);
    return ok > 0;
}

// ============================================================
// main
// ============================================================
int main(int argc, char* argv[]) {
    printf("=== ramdump_extract ===\n\n");
    if (argc < 2) {
        printf("Usage: %s <ram.dmp> [out.dmp] [process]\n", argv[0]);
        printf("  %s memory.dmp                  (lsass -> lsass_out.dmp)\n", argv[0]);
        printf("  %s memory.dmp lsass.dmp\n", argv[0]);
        printf("  %s memory.dmp svc.dmp svchost\n\n", argv[0]);
        printf("Parse:  pypykatz lsa minidump lsass_out.dmp\n");
        return 1;
    }
    const char* in = argv[1];
    const char* out = argc >= 3 ? argv[2] : "lsass_out.dmp";
    const char* tgt = argc >= 4 ? argv[3] : "lsass";

    printf("[*] In:  %s\n[*] Out: %s\n[*] Tgt: %s\n\n", in, out, tgt);

    Dump d;
    if (!open_dump(d, in)) return 1;

    Proc found = {};
    bool got_proc = false;

    // ---- Path A: crash dump with valid header ----
    if (d.is_crdp && d.cr3 && d.pshead) {
        try_kdbg(d);
        const EpOff* offs = nullptr;
        detect_offsets(d, offs);

        std::vector<Proc> procs;
        if (walk_procs(d, *offs, procs)) {
            // print table
            printf("\n  %-6s  %-20s  %s\n", "PID", "Name", "CR3");
            printf("  %s\n", std::string(54, '-').c_str());
            for (auto& p : procs)
                printf("  %-6llu  %-20s  0x%016llX\n", p.pid, p.name, p.cr3);
            printf("\n");

            // find target (partial, case-insensitive)
            std::string tl(tgt);
            std::transform(tl.begin(), tl.end(), tl.begin(), ::tolower);
            for (auto& p : procs) {
                std::string pn(p.name);
                std::transform(pn.begin(), pn.end(), pn.begin(), ::tolower);
                if (pn.find(tl) != std::string::npos) { found = p; got_proc = true; break; }
            }
        }
    }

    // ---- Path B: fallback scan (raw dump or walk failed) ----
    if (!got_proc) {
        printf("[*] Trying physical scan fallback...\n");
        for (auto& o : EP_OFFS) {
            if (scan_eprocess(d, tgt, o, found)) { got_proc = true; break; }
        }
    }

    if (!got_proc) {
        printf("[-] Process '%s' not found\n", tgt);
        return 1;
    }

    printf("[+] Target: '%s'  PID=%llu  CR3=0x%016llX\n\n",
        found.name, found.pid, found.cr3);

    auto segs = scan_va(d, found.cr3, found.pid);
    if (segs.empty()) { printf("[-] No mapped VA found\n"); return 1; }

    if (!write_minidump(d, found, segs, out)) return 1;

    printf("\n=== Done ===\n");
    printf("Parse:  pypykatz lsa minidump %s\n", out);
    printf("        python3 -m pypykatz lsa minidump %s --json\n", out);
    return 0;
}