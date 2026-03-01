#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#define fseek64 _fseeki64
#define ftell64 _ftelli64
#else
#define fseek64 fseeko
#define ftell64 ftello
#endif

void hexdump(const uint8_t* buf, size_t len, uint64_t base_off) {
    for (size_t i = 0; i < len; i += 16) {
        printf("  %04llX: ", (unsigned long long)(base_off + i));
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02X ", buf[i + j]);
            else printf("   ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = buf[i + j];
            printf("%c", (c >= 0x20 && c < 0x7F) ? c : '.');
        }
        printf("|\n");
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <dump.dmp>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) { printf("[-] Cannot open: %s\n", argv[1]); return 1; }

    fseek64(f, 0, SEEK_END);
    uint64_t fsz = (uint64_t)ftell64(f);
    fseek64(f, 0, SEEK_SET);
    printf("[+] File: %s\n", argv[1]);
    printf("[+] Size: %llu bytes (%.2f GB)\n\n", fsz, (double)fsz / 1024 / 1024 / 1024);

    // Đọc 256 bytes đầu
    uint8_t hdr[256] = {};
    size_t rd = fread(hdr, 1, 256, f);
    printf("=== First 256 bytes (hex + ASCII) ===\n");
    hexdump(hdr, rd, 0);

    // Interpret known signatures
    printf("\n=== Signature Analysis ===\n");
    uint32_t sig = *(uint32_t*)(hdr + 0);
    uint32_t sig2 = *(uint32_t*)(hdr + 4);

    printf("Bytes [0..3]:  0x%08X  ASCII: '%c%c%c%c'\n",
        sig, hdr[0], hdr[1], hdr[2], hdr[3]);
    printf("Bytes [4..7]:  0x%08X  ASCII: '%c%c%c%c'\n",
        sig2, hdr[4], hdr[5], hdr[6], hdr[7]);

    if (sig == 0x45474150 && sig2 == 0x504D5544)
        printf("--> Windows Full Memory Dump (PAGE+DUMP) ✓\n");
    else if (sig == 0x504D444D)
        printf("--> Windows Minidump (MDMP) — không dùng làm input!\n");
    else if (sig == 0x45474150)
        printf("--> 'PAGE' signature nhưng ValidDump khác DUMP: 0x%08X\n", sig2);
    else
        printf("--> Unknown / Raw format\n");

    // Nếu là crash dump — print các fields quan trọng
    if (sig == 0x45474150) {
        printf("\n=== DUMP_HEADER64 Fields ===\n");
        uint32_t major = *(uint32_t*)(hdr + 8);
        uint32_t minor = *(uint32_t*)(hdr + 12);
        uint64_t cr3 = *(uint64_t*)(hdr + 16);
        uint64_t psmod = *(uint64_t*)(hdr + 32);
        uint64_t psact = *(uint64_t*)(hdr + 40);
        printf("  [0x008] MajorVersion:         %u\n", major);
        printf("  [0x00C] MinorVersion:          %u\n", minor);
        printf("  [0x010] DirectoryTableBase:    0x%016llX  (CR3 raw)\n", cr3);
        printf("  [0x010] CR3 masked:             0x%016llX  (& ~0xFFF)\n",
            cr3 & 0xFFFFFFFFFFFFF000ULL);
        printf("  [0x020] PsLoadedModuleList:    0x%016llX\n", psmod);
        printf("  [0x028] PsActiveProcessHead:   0x%016llX\n", psact);

        uint64_t kdbg = *(uint64_t*)(hdr + 0x80);
        printf("  [0x080] KdDebuggerDataBlock:   0x%016llX\n", kdbg);

        // PhysicalMemoryBlock at 0x88
        if (rd >= 0x98 + 16) {
            uint32_t nruns = *(uint32_t*)(hdr + 0x88);
            uint32_t _pad = *(uint32_t*)(hdr + 0x8C);
            uint64_t npages = *(uint64_t*)(hdr + 0x90);
            printf("  [0x088] PhysNumRuns:           %u\n", nruns);
            printf("  [0x090] PhysNumPages:           %llu  (%.2f GB)\n",
                npages, (double)npages * 4096 / 1024 / 1024 / 1024);
            for (uint32_t i = 0; i < nruns && i < 8; i++) {
                uint64_t bpage = *(uint64_t*)(hdr + 0x98 + i * 16);
                uint64_t bcount = *(uint64_t*)(hdr + 0x98 + i * 16 + 8);
                printf("  Run[%u]: BasePage=0x%llX PageCount=0x%llX"
                    "  PA=0x%010llX  size=%.1fMB\n",
                    i, bpage, bcount,
                    bpage * 4096, (double)bcount * 4096 / 1024 / 1024);
            }
        }

        // DumpType tại 0xF8
        if (rd > 0xFC) {
            uint32_t dtype = *(uint32_t*)(hdr + 0xF8);
            printf("  [0x0F8] DumpType:              %u", dtype);
            const char* dtnames[] = { "?","Full","Kernel","Header","Triage","Bitmap","Auto" };
            if (dtype <= 6) printf(" (%s)", dtnames[dtype]);
            printf("\n");
        }
    }

    // Đọc thêm offset 0x1000 (bắt đầu physical data nếu là crash dump)
    if (fsz > 0x1000) {
        printf("\n=== Bytes at offset 0x1000 (start of physical data) ===\n");
        uint8_t pg0[64] = {};
        fseek64(f, 0x1000, SEEK_SET);
        fread(pg0, 1, 64, f);
        hexdump(pg0, 64, 0x1000);
    }

    fclose(f);
    return 0;
}