/*
 * custom_at.c  -  Full AT.exe replacement using NetScheduleJob* WinAPI
 *
 * REQUIREMENT on target machine (run once as admin):
 *   reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
 *           /v SubmitControl /t REG_DWORD /d 1 /f
 *   sc stop schedule & sc start schedule
 *
 * Build (MSVC):
 *   cl custom_at.c /W3 /O2 /link netapi32.lib mpr.lib
 *
 * Build (MinGW):
 *   gcc custom_at.c -o custom_at.exe -lnetapi32 -lmpr
 *
 * -----------------------------------------------------------------------
 * COMMANDS
 * -----------------------------------------------------------------------
 *
 *  LIST   -- list all jobs on a machine
 *    custom_at [\\server] [/user:U /pass:P [/domain:D]]
 *
 *  QUERY  -- show details of one job
 *    custom_at [\\server] <id> [/user:U /pass:P]
 *
 *  ADD    -- create a new job
 *    custom_at [\\server] <HH:MM> [/interactive]
 *              [/every:day[,...] | /next:day[,...]]
 *              [/user:U /pass:P [/domain:D]]
 *              "command"
 *
 *  DELETE -- remove job(s)
 *    custom_at [\\server] [id] /delete [/yes] [/user:U /pass:P]
 *
 *  RUN    -- trigger a job immediately
 *    custom_at [\\server] <id> /run [/user:U /pass:P]
 *
 *  CONFIG -- modify an existing job
 *    custom_at [\\server] <id> /config
 *              [/time:HH:MM] [/interactive | /nointeractive]
 *              [/every:day[,...] | /next:day[,...]]
 *              [/cmd:"newcommand"]
 *              [/user:U /pass:P]
 *
 * -----------------------------------------------------------------------
 * Day values  (used in /every and /next)
 *   1-31              -> day of month
 *   M,T,W,Th,F,Sa,Su  -> day of week
 * -----------------------------------------------------------------------
 *
 * Examples:
 *   custom_at \\192.168.1.5 /user:Administrator /pass:Secret
 *   custom_at \\192.168.1.5 23:45 /every:1,4,8,12 "bkprtn.bat" /user:Admin /pass:P@ss
 *   custom_at \\192.168.1.5 1 /run  /user:Admin /pass:P@ss
 *   custom_at \\192.168.1.5 1 /config /time:08:00 /cmd:"newcmd.bat" /user:Admin /pass:P@ss
 *   custom_at \\192.168.1.5 1 /delete /user:Admin /pass:P@ss
 *   custom_at \\192.168.1.5 /delete /yes /user:Admin /pass:P@ss
 */

#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0501

#include <windows.h>
#include <lm.h>
#include <lmat.h>
#include <winnetwk.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "mpr.lib")

 /* ------------------------------------------------------------------ */
 /* DaysOfWeek bitmask                                                   */
 /* ------------------------------------------------------------------ */
#define DOW_MON  0x01
#define DOW_TUE  0x02
#define DOW_WED  0x04
#define DOW_THU  0x08
#define DOW_FRI  0x10
#define DOW_SAT  0x20
#define DOW_SUN  0x40

/* ================================================================== */
/* Utility                                                              */
/* ================================================================== */

static const char* netErrStr(DWORD st)
{
    static char buf[128];
    switch (st)
    {
    case ERROR_SUCCESS:           return "OK";
    case ERROR_ACCESS_DENIED:     return "ACCESS_DENIED (5) - need admin credential";
    case ERROR_BAD_NETPATH:       return "BAD_NETPATH (53)  - host unreachable or firewall blocking";
    case ERROR_NOT_SUPPORTED:
        return "NOT_SUPPORTED (50) - on target run:\n"
            "         reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\n"
            "                 /v SubmitControl /t REG_DWORD /d 1 /f\n"
            "         sc stop schedule & sc start schedule";
    case ERROR_INVALID_PARAMETER: return "INVALID_PARAMETER (87)";
    case ERROR_SESSION_CREDENTIAL_CONFLICT:
        return "CREDENTIAL_CONFLICT (1219) - run: net use \\\\server\\IPC$ /delete";
    case 1722: return "RPC_SERVER_UNAVAILABLE (1722) - Schedule service not running on target";
    case 1753: return "EPT_NOT_REGISTERED (1753)";
    case 2184: return "NERR_ServiceNotInstalled (2184)";
    default:
        sprintf(buf, "error code %lu", (unsigned long)st);
        return buf;
    }
}

static const char* wToA(const wchar_t* w)
{
    static char buf[1024];
    if (!w) return "(null)";
    WideCharToMultiByte(CP_ACP, 0, w, -1, buf, (int)sizeof(buf), NULL, NULL);
    return buf;
}

static const char* dowToStr(UCHAR dow)
{
    static char buf[32];
    static const struct { UCHAR bit; const char* s; } map[] = {
        {DOW_MON,"Mo"},{DOW_TUE,"Tu"},{DOW_WED,"We"},{DOW_THU,"Th"},
        {DOW_FRI,"Fr"},{DOW_SAT,"Sa"},{DOW_SUN,"Su"}
    };
    int i, pos = 0;
    buf[0] = '\0';
    for (i = 0; i < 7; i++)
        if (dow & map[i].bit)
        {
            if (pos) buf[pos++] = ' ';
            buf[pos++] = map[i].s[0];
            buf[pos++] = map[i].s[1];
            buf[pos] = '\0';
        }
    return buf[0] ? buf : "--";
}

/* ================================================================== */
/* SMB Authentication (IPC$)                                           */
/* ================================================================== */

static BOOL  g_smbConnected = FALSE;
static wchar_t g_smbIPC[256] = { 0 };

static BOOL smbConnect(const wchar_t* server,
    const wchar_t* user,
    const wchar_t* domain,
    const wchar_t* pass)
{
    if (!user || !pass)
    {
        printf("[*] No credential supplied - using current user token.\n");
        return TRUE;
    }

    swprintf(g_smbIPC, 256, L"%s\\IPC$", server);

    wchar_t fullUser[256];
    if (domain && wcslen(domain) > 0)
        swprintf(fullUser, 256, L"%s\\%s", domain, user);
    else
        wcsncpy(fullUser, user, 255);

    NETRESOURCEW nr = { 0 };
    nr.dwType = RESOURCETYPE_ANY;
    nr.lpLocalName = NULL;
    nr.lpRemoteName = g_smbIPC;
    nr.lpProvider = NULL;

    printf("[*] Authenticating to %s as %s ...\n",
        wToA(g_smbIPC), wToA(fullUser));

    DWORD st = WNetAddConnection2W(&nr, pass, fullUser, 0);

    if (st == ERROR_SUCCESS)
    {
        printf("[+] SMB session established.\n");
        g_smbConnected = TRUE;
        return TRUE;
    }
    if (st == ERROR_ALREADY_ASSIGNED || st == ERROR_DEVICE_ALREADY_REMEMBERED
        || st == ERROR_SESSION_CREDENTIAL_CONFLICT)
    {
        /* A session to IPC$ already exists (e.g. from prior net use).
           This is fine - the existing token will be used by RPC.     */
        printf("[*] SMB session already exists (reusing).\n");
        return TRUE;
    }

    fprintf(stderr, "[!] SMB auth failed: %s\n", netErrStr(st));
    return FALSE;
}

static void smbDisconnect(void)
{
    if (g_smbConnected && g_smbIPC[0])
    {
        WNetCancelConnection2W(g_smbIPC, 0, FALSE);
        printf("[*] SMB session released.\n");
        g_smbConnected = FALSE;
    }
}

/* ================================================================== */
/* Parse helpers                                                        */
/* ================================================================== */

static BOOL parseTime(const wchar_t* s, DWORD* pMs)
{
    int h = 0, m = 0;
    if (swscanf(s, L"%d:%d", &h, &m) != 2) return FALSE;
    if (h < 0 || h > 23 || m < 0 || m > 59) return FALSE;
    *pMs = (DWORD)(h * 3600 + m * 60) * 1000;
    return TRUE;
}

static BOOL parseDays(const wchar_t* s, DWORD* pDom, UCHAR* pDow)
{
    static const wchar_t* dowNames[] =
    { L"M", L"T", L"W", L"Th", L"F", L"Sa", L"Su" };
    static const UCHAR dowBits[] =
    { DOW_MON, DOW_TUE, DOW_WED, DOW_THU, DOW_FRI, DOW_SAT, DOW_SUN };

    wchar_t  buf[256];
    wchar_t* tok, * ctx;
    *pDom = 0; *pDow = 0;
    wcsncpy(buf, s, 255); buf[255] = L'\0';
    tok = wcstok(buf, L",", &ctx);
    while (tok)
    {
        BOOL found = FALSE;
        int  k;
        for (k = 0; k < 7; k++)
            if (_wcsicmp(tok, dowNames[k]) == 0)
            {
                *pDow |= dowBits[k]; found = TRUE; break;
            }
        if (!found)
        {
            wchar_t* end;
            long n = wcstol(tok, &end, 10);
            if (*end != L'\0' || n < 1 || n > 31)
            {
                fprintf(stderr, "Invalid day: %s\n", wToA(tok)); return FALSE;
            }
            *pDom |= (1UL << (n - 1));
        }
        tok = wcstok(NULL, L",", &ctx);
    }
    return TRUE;
}

/* ================================================================== */
/* LIST                                                                 */
/* ================================================================== */

static void cmdList(const wchar_t* server)
{
    AT_ENUM* buf = NULL;
    DWORD           nRead = 0, nTotal = 0, resume = 0;
    NET_API_STATUS  st;
    BOOL            any = FALSE;

    printf("\nJobs on: %s\n", server ? wToA(server) : "(local)");
    printf("%-6s  %-8s  %-14s  %-12s  %-6s  %s\n",
        "ID", "Time", "DaysOfWeek", "DaysOfMonth", "Mode", "Command");
    printf("------  --------  --------------  ------------  ------  --------------------\n");

    do {
        st = NetScheduleJobEnum(
            (LPCWSTR)server, (LPBYTE*)&buf,
            MAX_PREFERRED_LENGTH, &nRead, &nTotal, &resume);
        if (st != NERR_Success && st != ERROR_MORE_DATA)
        {
            fprintf(stderr, "NetScheduleJobEnum failed: %s\n", netErrStr(st)); break;
        }

        DWORD i;
        for (i = 0; i < nRead; i++)
        {
            any = TRUE;
            DWORD ms = buf[i].JobTime;
            int   h = (int)(ms / 3600000);
            int   m = (int)((ms % 3600000) / 60000);
            /* Mode column: P/N = periodic/next, I/S = interactive/system */
            char  mode[8];
            sprintf(mode, "%s/%s",
                (buf[i].Flags & JOB_RUN_PERIODICALLY) ? "every" : "next",
                (buf[i].Flags & JOB_NONINTERACTIVE) ? "sys" : "int");
            printf("%-6lu  %02d:%02d     %-14s  0x%08lX    %-6s  %s\n",
                (unsigned long)buf[i].JobId, h, m,
                dowToStr(buf[i].DaysOfWeek),
                (unsigned long)buf[i].DaysOfMonth,
                mode,
                buf[i].Command ? wToA(buf[i].Command) : "");
        }
        NetApiBufferFree(buf); buf = NULL;
    } while (st == ERROR_MORE_DATA);

    if (!any) printf("  (no jobs scheduled)\n");
}

/* ================================================================== */
/* QUERY                                                                */
/* ================================================================== */

static void cmdQuery(const wchar_t* server, DWORD jobId)
{
    AT_INFO* info = NULL;
    NET_API_STATUS  st;

    st = NetScheduleJobGetInfo(server, jobId, (LPBYTE*)&info);
    if (st != NERR_Success)
    {
        fprintf(stderr, "NetScheduleJobGetInfo failed: %s\n", netErrStr(st)); return;
    }

    DWORD ms = info->JobTime;
    int   h = (int)(ms / 3600000);
    int   m = (int)((ms % 3600000) / 60000);

    printf("\n--- Job %lu ---\n", (unsigned long)jobId);
    printf("Run time    : %02d:%02d\n", h, m);
    printf("DaysOfWeek  : 0x%02X  (%s)\n",
        (unsigned)info->DaysOfWeek, dowToStr(info->DaysOfWeek));
    printf("DaysOfMonth : 0x%08lX\n", (unsigned long)info->DaysOfMonth);
    printf("Schedule    : %s\n",
        (info->Flags & JOB_RUN_PERIODICALLY) ? "periodic (/every)" : "one-shot (/next)");
    printf("Interactive : %s\n",
        (info->Flags & JOB_NONINTERACTIVE) ? "no (runs as SYSTEM)" : "yes");
    printf("Flags (raw) : 0x%04X\n", (unsigned)info->Flags);
    printf("Command     : %s\n",
        info->Command ? wToA(info->Command) : "(none)");
    NetApiBufferFree(info);
}

/* ================================================================== */
/* ADD                                                                  */
/* ================================================================== */

static DWORD cmdAdd(const wchar_t* server,
    DWORD          jobTimeMs,
    DWORD          daysOfMonth,
    UCHAR          daysOfWeek,
    BOOL           periodic,
    BOOL           interactive,
    const wchar_t* command)
{
    AT_INFO        info = { 0 };
    DWORD          newId = 0;
    NET_API_STATUS st;

    info.JobTime = jobTimeMs;
    info.DaysOfMonth = daysOfMonth;
    info.DaysOfWeek = daysOfWeek;
    info.Command = (LPWSTR)command;
    info.Flags = 0;
    if (periodic)     info.Flags |= JOB_RUN_PERIODICALLY;
    if (!interactive) info.Flags |= JOB_NONINTERACTIVE;

    printf("\nAdding job:\n");
    printf("  Server      : %s\n", server ? wToA(server) : "(local)");
    printf("  Time        : %02lu:%02lu\n",
        (unsigned long)(jobTimeMs / 3600000),
        (unsigned long)((jobTimeMs % 3600000) / 60000));
    printf("  DaysOfMonth : 0x%08lX\n", (unsigned long)daysOfMonth);
    printf("  DaysOfWeek  : 0x%02X (%s)\n",
        (unsigned)daysOfWeek, dowToStr(daysOfWeek));
    printf("  Schedule    : %s\n", periodic ? "periodic (/every)" : "one-shot (/next)");
    printf("  Interactive : %s\n", interactive ? "yes" : "no (SYSTEM)");
    printf("  Command     : %s\n", wToA(command));

    st = NetScheduleJobAdd(server, (LPBYTE)&info, &newId);
    if (st == NERR_Success)
    {
        printf("[+] Job added. ID = %lu\n", (unsigned long)newId); return newId;
    }
    else
    {
        fprintf(stderr, "[-] NetScheduleJobAdd failed: %s\n", netErrStr(st)); return 0;
    }
}

/* ================================================================== */
/* DELETE                                                               */
/* ================================================================== */

static void cmdDelete(const wchar_t* server, DWORD jobId, BOOL all, BOOL yes)
{
    NET_API_STATUS st;

    if (all)
    {
        if (!yes)
        {
            printf("Delete ALL jobs on %s? (Y/N): ",
                server ? wToA(server) : "(local)");
            fflush(stdout);
            int c = getchar();
            if (c != 'Y' && c != 'y') { printf("Cancelled.\n"); return; }
        }

        AT_ENUM* buf = NULL;
        DWORD    nRead = 0, nTotal = 0, resume = 0;
        DWORD    ids[4096], cnt = 0;
        do {
            st = NetScheduleJobEnum(server, (LPBYTE*)&buf,
                MAX_PREFERRED_LENGTH, &nRead, &nTotal, &resume);
            if (st != NERR_Success && st != ERROR_MORE_DATA) break;
            DWORD i;
            for (i = 0; i < nRead && cnt < 4096; i++)
                ids[cnt++] = buf[i].JobId;
            NetApiBufferFree(buf); buf = NULL;
        } while (st == ERROR_MORE_DATA);

        if (cnt == 0) { printf("  No jobs to delete.\n"); return; }

        DWORD i;
        for (i = 0; i < cnt; i++)
        {
            st = NetScheduleJobDel(server, ids[i], ids[i]);
            printf(st == NERR_Success
                ? "[+] Deleted job %lu\n"
                : "[-] Failed  job %lu\n", (unsigned long)ids[i]);
        }
    }
    else
    {
        st = NetScheduleJobDel(server, jobId, jobId);
        if (st == NERR_Success)
            printf("[+] Deleted job %lu\n", (unsigned long)jobId);
        else
            fprintf(stderr, "[-] NetScheduleJobDel failed: %s\n", netErrStr(st));
    }
}

/* ================================================================== */
/* RUN  (trigger immediately)                                           */
/*                                                                      */
/* AT has no /run verb. Technique:                                      */
/*   1. Read original job config                                        */
/*   2. Delete it                                                       */
/*   3. Re-add as one-shot at (now + 70 seconds)                       */
/*   4. Wait 75 seconds for the scheduler to fire it                   */
/*   5. Delete the temp job, restore original config                   */
/* ================================================================== */

static void cmdRun(const wchar_t* server, DWORD jobId)
{
    AT_INFO* orig = NULL;
    NET_API_STATUS  st;

    /* 1. Read original */
    st = NetScheduleJobGetInfo(server, jobId, (LPBYTE*)&orig);
    if (st != NERR_Success)
    {
        fprintf(stderr, "NetScheduleJobGetInfo failed: %s\n", netErrStr(st)); return;
    }

    wchar_t savedCmd[1024] = { 0 };
    if (orig->Command) wcsncpy(savedCmd, orig->Command, 1023);
    DWORD savedTime = orig->JobTime;
    DWORD savedDom = orig->DaysOfMonth;
    UCHAR savedDow = orig->DaysOfWeek;
    WORD  savedFlags = orig->Flags;
    NetApiBufferFree(orig);

    /* 2. Delete original */
    st = NetScheduleJobDel(server, jobId, jobId);
    if (st != NERR_Success)
    {
        fprintf(stderr, "NetScheduleJobDel failed: %s\n", netErrStr(st)); return;
    }

    /* 3. Compute now + 70 seconds */
    SYSTEMTIME lt;
    GetLocalTime(&lt);
    DWORD nowMs = (DWORD)(lt.wHour * 3600UL + lt.wMinute * 60UL + lt.wSecond) * 1000UL;
    DWORD fireMs = (nowMs + 70000UL) % 86400000UL;

    printf("[*] Scheduling immediate run at %02lu:%02lu:%02lu ...\n",
        (unsigned long)(fireMs / 3600000),
        (unsigned long)((fireMs % 3600000) / 60000),
        (unsigned long)((fireMs % 60000) / 1000));

    AT_INFO tmp = { 0 };
    tmp.JobTime = fireMs;
    tmp.DaysOfMonth = 0;
    tmp.DaysOfWeek = 0;
    tmp.Flags = JOB_NONINTERACTIVE;   /* one-shot, no JOB_RUN_PERIODICALLY */
    tmp.Command = savedCmd;
    DWORD tmpId = 0;

    st = NetScheduleJobAdd(server, (LPBYTE)&tmp, &tmpId);
    if (st != NERR_Success)
    {
        fprintf(stderr, "Re-add for run failed: %s\n", netErrStr(st));
        goto restore;
    }
    printf("[+] Temp job %lu created. Waiting 75 s for scheduler to fire...\n",
        (unsigned long)tmpId);

    /* 4. Wait with countdown */
    {
        int secs;
        for (secs = 75; secs > 0; secs -= 5)
        {
            printf("    %2d s remaining...\r", secs);
            fflush(stdout);
            Sleep(5000);
        }
        printf("\n[+] Wait complete.\n");
    }

    /* Clean up temp job (may already be gone after firing) */
    NetScheduleJobDel(server, tmpId, tmpId);

restore:
    /* 5. Restore original */
    {
        AT_INFO r = { 0 };
        r.JobTime = savedTime;
        r.DaysOfMonth = savedDom;
        r.DaysOfWeek = savedDow;
        r.Flags = savedFlags;
        r.Command = savedCmd;
        DWORD restoredId = 0;
        st = NetScheduleJobAdd(server, (LPBYTE)&r, &restoredId);
        if (st == NERR_Success)
            printf("[+] Original job restored as ID %lu\n", (unsigned long)restoredId);
        else
            fprintf(stderr, "[-] Restore failed: %s\n", netErrStr(st));
    }
}

/* ================================================================== */
/* CONFIG  (modify existing job = delete + re-add with overrides)      */
/* ================================================================== */

static void cmdConfig(const wchar_t* server,
    DWORD          jobId,
    const wchar_t* newTimeStr,
    const wchar_t* newEveryStr,
    const wchar_t* newNextStr,
    const wchar_t* newCmd,
    int            newInteractive)  /* -1=keep 0=no 1=yes */
{
    AT_INFO* orig = NULL;
    NET_API_STATUS  st;

    /* Read current */
    st = NetScheduleJobGetInfo(server, jobId, (LPBYTE*)&orig);
    if (st != NERR_Success)
    {
        fprintf(stderr, "NetScheduleJobGetInfo failed: %s\n", netErrStr(st)); return;
    }

    wchar_t savedCmd[1024] = { 0 };
    if (orig->Command) wcsncpy(savedCmd, orig->Command, 1023);
    DWORD savedTime = orig->JobTime;
    DWORD savedDom = orig->DaysOfMonth;
    UCHAR savedDow = orig->DaysOfWeek;
    WORD  savedFlags = orig->Flags;
    NetApiBufferFree(orig);

    /* Apply overrides */
    DWORD newTime = savedTime;
    DWORD newDom = savedDom;
    UCHAR newDow = savedDow;
    WORD  newFlags = savedFlags;
    const wchar_t* finalCmd = (newCmd && wcslen(newCmd)) ? newCmd : savedCmd;

    if (newTimeStr && wcslen(newTimeStr))
    {
        if (!parseTime(newTimeStr, &newTime))
        {
            fprintf(stderr, "Invalid /time value: %s\n", wToA(newTimeStr)); return;
        }
    }
    if (newEveryStr && wcslen(newEveryStr))
    {
        if (!parseDays(newEveryStr, &newDom, &newDow)) return;
        newFlags |= JOB_RUN_PERIODICALLY;
    }
    else if (newNextStr && wcslen(newNextStr))
    {
        if (!parseDays(newNextStr, &newDom, &newDow)) return;
        newFlags &= ~JOB_RUN_PERIODICALLY;
    }
    if (newInteractive == 1) newFlags &= ~JOB_NONINTERACTIVE;
    else if (newInteractive == 0) newFlags |= JOB_NONINTERACTIVE;

    /* Print diff */
    printf("\nReconfiguring job %lu:\n", (unsigned long)jobId);
    printf("  %-12s  %-30s  ->  %s\n", "Time",
        "", "");  /* spacer */
    printf("  %-12s  %02lu:%02lu  ->  %02lu:%02lu\n", "Time",
        (unsigned long)(savedTime / 3600000), (unsigned long)((savedTime % 3600000) / 60000),
        (unsigned long)(newTime / 3600000), (unsigned long)((newTime % 3600000) / 60000));
    printf("  %-12s  0x%08lX  ->  0x%08lX\n", "DaysOfMonth",
        (unsigned long)savedDom, (unsigned long)newDom);
    printf("  %-12s  0x%02X        ->  0x%02X\n", "DaysOfWeek",
        (unsigned)savedDow, (unsigned)newDow);
    printf("  %-12s  0x%04X      ->  0x%04X\n", "Flags",
        (unsigned)savedFlags, (unsigned)newFlags);
    printf("  %-12s  %s\n             ->  %s\n", "Command",
        wToA(savedCmd), wToA(finalCmd));

    /* Delete then re-add */
    st = NetScheduleJobDel(server, jobId, jobId);
    if (st != NERR_Success)
    {
        fprintf(stderr, "Delete failed: %s\n", netErrStr(st)); return;
    }

    AT_INFO info = { 0 };
    info.JobTime = newTime;
    info.DaysOfMonth = newDom;
    info.DaysOfWeek = newDow;
    info.Flags = newFlags;
    info.Command = (LPWSTR)finalCmd;
    DWORD newId = 0;
    st = NetScheduleJobAdd(server, (LPBYTE)&info, &newId);
    if (st == NERR_Success)
        printf("[+] Job reconfigured. New ID = %lu\n", (unsigned long)newId);
    else
        fprintf(stderr, "[-] NetScheduleJobAdd failed: %s\n", netErrStr(st));
}

/* ================================================================== */
/* Usage                                                                */
/* ================================================================== */

static void usage(void)
{
    puts(
        "\ncustom_at - AT.exe replacement (NetScheduleJob* WinAPI)\n"
        "\nCOMMANDS:\n"
        "\n  LIST (default):\n"
        "    custom_at [\\\\server] [/user:U /pass:P [/domain:D]]\n"
        "\n  QUERY one job:\n"
        "    custom_at [\\\\server] <id> [/user:U /pass:P]\n"
        "\n  ADD new job:\n"
        "    custom_at [\\\\server] <HH:MM> [/every:days | /next:days]\n"
        "              [/interactive] [/user:U /pass:P] \"command\"\n"
        "\n  DELETE job(s):\n"
        "    custom_at [\\\\server] [id] /delete [/yes] [/user:U /pass:P]\n"
        "\n  RUN immediately:\n"
        "    custom_at [\\\\server] <id> /run [/user:U /pass:P]\n"
        "\n  CONFIG (modify):\n"
        "    custom_at [\\\\server] <id> /config\n"
        "              [/time:HH:MM] [/every:days | /next:days]\n"
        "              [/interactive | /nointeractive]\n"
        "              [/cmd:\"newcommand\"] [/user:U /pass:P]\n"
        "\n  Day values: 1-31  or  M,T,W,Th,F,Sa,Su\n"
        "\nExamples:\n"
        "  custom_at \\\\192.168.1.5 /user:Administrator /pass:Secret\n"
        "  custom_at \\\\192.168.1.5 23:45 /every:1,4,8,12 \"bkprtn.bat\" /user:Admin /pass:P@ss\n"
        "  custom_at \\\\192.168.1.5 1 /run   /user:Admin /pass:P@ss\n"
        "  custom_at \\\\192.168.1.5 1 /config /time:08:00 /cmd:\"newjob.bat\" /user:Admin /pass:P@ss\n"
        "  custom_at \\\\192.168.1.5 1 /delete /user:Admin /pass:P@ss\n"
        "  custom_at \\\\192.168.1.5 /delete /yes /user:Admin /pass:P@ss\n"
    );
}

/* ================================================================== */
/* wmain                                                                */
/* ================================================================== */

int wmain(int argc, wchar_t* argv[])
{
    wchar_t* server = NULL;
    wchar_t* userArg = NULL;
    wchar_t* passArg = NULL;
    wchar_t* domainArg = NULL;
    wchar_t* timeStr = NULL;
    wchar_t* everyStr = NULL;
    wchar_t* nextStr = NULL;
    wchar_t* command = NULL;
    wchar_t* cfgTimeStr = NULL;
    wchar_t* cfgEvery = NULL;
    wchar_t* cfgNext = NULL;
    wchar_t* cfgCmd = NULL;
    int      cfgInter = -1;

    BOOL  doDelete = FALSE;
    BOOL  doRun = FALSE;
    BOOL  doConfig = FALSE;
    BOOL  doYes = FALSE;
    BOOL  interactive = FALSE;
    BOOL  hasJobId = FALSE;
    DWORD jobId = 0;

    if (argc == 1) { usage(); return 0; }

    int i;
    for (i = 1; i < argc; i++)
    {
        wchar_t* a = argv[i];

        if (wcsncmp(a, L"\\\\", 2) == 0) { server = a;    continue; }
        if (_wcsnicmp(a, L"/user:", 6) == 0) { userArg = a + 6;  continue; }
        if (_wcsnicmp(a, L"/pass:", 6) == 0) { passArg = a + 6;  continue; }
        if (_wcsnicmp(a, L"/domain:", 8) == 0) { domainArg = a + 8;  continue; }
        if (_wcsicmp(a, L"/delete") == 0) { doDelete = TRUE; continue; }
        if (_wcsicmp(a, L"/yes") == 0) { doYes = TRUE; continue; }
        if (_wcsicmp(a, L"/run") == 0) { doRun = TRUE; continue; }
        if (_wcsicmp(a, L"/config") == 0) { doConfig = TRUE; continue; }
        if (_wcsicmp(a, L"/interactive") == 0) { interactive = TRUE; cfgInter = 1; continue; }
        if (_wcsicmp(a, L"/nointeractive") == 0) { cfgInter = 0;    continue; }

        if (_wcsnicmp(a, L"/every:", 7) == 0)
        {
            if (doConfig) cfgEvery = a + 7; else everyStr = a + 7; continue;
        }
        if (_wcsnicmp(a, L"/next:", 6) == 0)
        {
            if (doConfig) cfgNext = a + 6; else nextStr = a + 6; continue;
        }

        if (_wcsnicmp(a, L"/time:", 6) == 0) { cfgTimeStr = a + 6;  continue; }
        if (_wcsnicmp(a, L"/cmd:", 5) == 0) { cfgCmd = a + 5;  continue; }

        /* HH:MM */
        if (wcschr(a, L':') && !timeStr && !hasJobId)
        {
            timeStr = a; continue;
        }

        /* numeric job ID */
        {
            wchar_t* end;
            long v = wcstol(a, &end, 10);
            if (*end == L'\0' && v > 0 && !hasJobId && !timeStr)
            {
                jobId = (DWORD)v; hasJobId = TRUE; continue;
            }
        }

        if (!command) { command = a; continue; }

        fprintf(stderr, "Unknown argument: %s\n", wToA(a));
        usage(); return 1;
    }

    /* SMB auth */
    if (server && userArg)
        if (!smbConnect(server, userArg, domainArg, passArg))
            return 1;

    /* Dispatch */
    int ret = 0;

    if (doRun)
    {
        if (!hasJobId)
        {
            fprintf(stderr, "Error: /run requires a job ID\n"); ret = 1; goto done;
        }
        cmdRun(server, jobId);
    }
    else if (doConfig)
    {
        if (!hasJobId)
        {
            fprintf(stderr, "Error: /config requires a job ID\n"); ret = 1; goto done;
        }
        cmdConfig(server, jobId, cfgTimeStr, cfgEvery, cfgNext, cfgCmd, cfgInter);
    }
    else if (doDelete)
    {
        cmdDelete(server, jobId, !hasJobId, doYes);
    }
    else if (hasJobId && !timeStr)
    {
        cmdQuery(server, jobId);
    }
    else if (!timeStr && !command)
    {
        cmdList(server);
    }
    else
    {
        /* ADD */
        if (!timeStr)
        {
            fprintf(stderr, "Error: missing HH:MM\n"); ret = 1; goto done;
        }
        if (!command)
        {
            fprintf(stderr, "Error: missing command\n"); ret = 1; goto done;
        }

        DWORD jobTimeMs = 0;
        if (!parseTime(timeStr, &jobTimeMs))
        {
            fprintf(stderr, "Invalid time: %s\n", wToA(timeStr)); ret = 1; goto done;
        }

        DWORD daysOfMonth = 0;
        UCHAR daysOfWeek = 0;
        BOOL  periodic = FALSE;
        if (everyStr)
        {
            periodic = TRUE;
            if (!parseDays(everyStr, &daysOfMonth, &daysOfWeek))
            {
                ret = 1; goto done;
            }
        }
        else if (nextStr)
        {
            periodic = FALSE;
            if (!parseDays(nextStr, &daysOfMonth, &daysOfWeek))
            {
                ret = 1; goto done;
            }
        }
        cmdAdd(server, jobTimeMs, daysOfMonth, daysOfWeek,
            periodic, interactive, command);
    }

done:
    smbDisconnect();
    return ret;
}