/*
 * remote_task_manager.cpp  (fixed)
 *
 * Build (MSVC):
 *   cl remote_task_manager.cpp /W3 /O2 /EHsc /link mpr.lib ole32.lib oleaut32.lib
 *
 * Usage:
 *   remote_task_manager.exe --host <IP/Host> --user <user> --pass <pass>
 *                           --task <TaskName>
 *                           --action <create|run|delete|query|enable|disable|list>
 *                           [--domain <domain>]
 *                           [--folder <\Path>]         default: backslash
 *
 *   (for create):
 *                           --exe <"C:\path\to.exe">
 *                           [--args <"args">]
 *                           [--trigger <once|daily|weekly|onstart|onlogon>]
 *                           [--startdate <YYYY-MM-DD>] default: 1970-01-01
 *                           [--starttime <HH:MM>]      default: 00:00
 *                           [--runas <SYSTEM|user>]    default: SYSTEM
 *                           [--hidden]
 *
 * Examples:
 *   remote_task_manager.exe --host 192.168.47.136 --user Administrator --pass P@ssw0rd123
 *       --task MyTask --exe "C:\Users\wintest\Desktop\service.exe"
 *       --trigger once --startdate 1970-01-01 --starttime 00:00 --runas SYSTEM --action create
 *
 *   remote_task_manager.exe --host 192.168.47.136 --user Administrator --pass P@ssw0rd123
 *       --task MyTask --action run
 *
 *   remote_task_manager.exe --host 192.168.47.136 --user Administrator --pass P@ssw0rd123
 *       --task MyTask --action delete
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_DCOM
#include <windows.h>
#include <winnetwk.h>
#include <comdef.h>
#include <taskschd.h>   // Task Scheduler 2.0 – ships with Windows SDK 6.0+
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "taskschd.lib")

 // ---------------------------------------------------------------------------
 // Một số constant / interface có thể thiếu tuỳ SDK version – khai báo lại
 // ---------------------------------------------------------------------------
#ifndef TASK_MONDAY
#define TASK_MONDAY   0x2
#endif

// ICalendarTrigger không phải lúc nào cũng có trong taskschd.h cũ.
// Ta KHÔNG dùng ICalendarTrigger nữa – chỉ dùng IDailyTrigger / IWeeklyTrigger
// vốn có trong mọi SDK hỗ trợ Task Scheduler 2.0.

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
struct Config {
    WCHAR host[256];
    WCHAR user[256];
    WCHAR pass[256];
    WCHAR domain[256];
    WCHAR taskName[512];
    WCHAR exePath[1024];
    WCHAR exeArgs[1024];
    WCHAR trigger[64];      // once | daily | weekly | onstart | onlogon
    WCHAR startTime[32];    // HH:MM
    WCHAR startDate[32];    // YYYY-MM-DD
    WCHAR runAs[256];       // SYSTEM or <username>
    WCHAR folder[256];      // \ or \SubFolder
    WCHAR action[64];       // create|run|delete|query|enable|disable|list
    BOOL  hidden;
    BOOL  localMode;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static void PrintHR(const wchar_t* msg, HRESULT hr)
{
    _com_error e(hr);
    wprintf(L"[-] %s: 0x%08lX - %s\n", msg, (unsigned long)hr, e.ErrorMessage());
}

static void PrintWin32Error(const wchar_t* msg, DWORD err)
{
    LPWSTR buf = NULL;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, 0, (LPWSTR)&buf, 0, NULL);
    wprintf(L"[-] %s (Error %lu): %s\n", msg, err, buf ? buf : L"Unknown");
    if (buf) LocalFree(buf);
}

static const wchar_t* TaskStateStr(TASK_STATE s)
{
    switch (s) {
    case TASK_STATE_UNKNOWN:  return L"Unknown";
    case TASK_STATE_DISABLED: return L"Disabled";
    case TASK_STATE_QUEUED:   return L"Queued";
    case TASK_STATE_READY:    return L"Ready";
    case TASK_STATE_RUNNING:  return L"Running";
    default:                  return L"?";
    }
}

static BOOL IsLocalHost(const WCHAR* h)
{
    return (_wcsicmp(h, L"localhost") == 0 ||
        wcscmp(h, L"127.0.0.1") == 0 ||
        wcscmp(h, L"::1") == 0);
}

// ---------------------------------------------------------------------------
// IPC$ session management
// ---------------------------------------------------------------------------
static BOOL CheckSessionExists(const WCHAR* host)
{
    WCHAR path[512];
    swprintf_s(path, 512, L"\\\\%s\\IPC$", host);
    WCHAR user[256]; DWORD len = 256;
    DWORD r = WNetGetUserW(path, user, &len);
    if (r == NO_ERROR) {
        wprintf(L"[*] Session to %s already exists (user: %s).\n", host, user);
        return TRUE;
    }
    return FALSE;
}

static BOOL EstablishSession(const Config& cfg)
{
    if (IsLocalHost(cfg.host)) return TRUE;
    if (CheckSessionExists(cfg.host)) return TRUE;

    WCHAR remoteName[512];
    swprintf_s(remoteName, 512, L"\\\\%s\\IPC$", cfg.host);

    WCHAR fullUser[512];
    if (cfg.domain[0])
        swprintf_s(fullUser, 512, L"%s\\%s", cfg.domain, cfg.user);
    else
        wcscpy_s(fullUser, 512, cfg.user);

    wprintf(L"[*] Creating IPC$ session to %s as [%s] ...\n", remoteName, fullUser);

    NETRESOURCEW nr = {};
    nr.dwType = RESOURCETYPE_ANY;
    nr.lpRemoteName = remoteName;

    DWORD ret = WNetAddConnection2W(&nr, cfg.pass, fullUser, CONNECT_TEMPORARY);

    if (ret == ERROR_SESSION_CREDENTIAL_CONFLICT) {
        wprintf(L"[!] Credential conflict - disconnecting old session...\n");
        WNetCancelConnection2W(remoteName, 0, TRUE);
        ret = WNetAddConnection2W(&nr, cfg.pass, fullUser, CONNECT_TEMPORARY);
    }

    if (ret == NO_ERROR || ret == ERROR_ALREADY_ASSIGNED) {
        wprintf(L"[+] IPC$ session established.\n");
        return TRUE;
    }
    PrintWin32Error(L"WNetAddConnection2W failed", ret);
    return FALSE;
}

// ---------------------------------------------------------------------------
// Connect ITaskService
// ---------------------------------------------------------------------------
static HRESULT ConnectTaskService(const Config& cfg, ITaskService** ppSvc)
{
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService, (void**)ppSvc);
    if (FAILED(hr)) { PrintHR(L"CoCreateInstance(TaskScheduler)", hr); return hr; }

    _variant_t vHost, vUser, vDomain, vPass;

    if (!IsLocalHost(cfg.host)) {
        vHost = cfg.host;
        vUser = cfg.user[0] ? cfg.user : L"";
        vDomain = cfg.domain[0] ? cfg.domain : L"";
        vPass = cfg.pass[0] ? cfg.pass : L"";
    }

    hr = (*ppSvc)->Connect(vHost, vUser, vDomain, vPass);
    if (FAILED(hr)) {
        PrintHR(L"ITaskService::Connect", hr);
        (*ppSvc)->Release();
        *ppSvc = NULL;
    }
    return hr;
}

// ---------------------------------------------------------------------------
// Get or create task folder
// ---------------------------------------------------------------------------
static HRESULT GetOrCreateFolder(ITaskService* pSvc, const WCHAR* path,
    ITaskFolder** ppF)
{
    HRESULT hr = pSvc->GetFolder(_bstr_t(path), ppF);
    if (SUCCEEDED(hr)) return hr;

    ITaskFolder* pRoot = NULL;
    hr = pSvc->GetFolder(_bstr_t(L"\\"), &pRoot);
    if (FAILED(hr)) return hr;
    hr = pRoot->CreateFolder(_bstr_t(path), _variant_t(L""), ppF);
    pRoot->Release();
    return hr;
}

// ---------------------------------------------------------------------------
// ACTION: create
// ---------------------------------------------------------------------------
static HRESULT ActionCreate(ITaskService* pSvc, const Config& cfg)
{
    wprintf(L"[*] Creating task '%s' on %s ...\n", cfg.taskName, cfg.host);

    ITaskFolder* pFolder = NULL;
    HRESULT hr = GetOrCreateFolder(pSvc, cfg.folder, &pFolder);
    if (FAILED(hr)) { PrintHR(L"GetFolder", hr); return hr; }

    ITaskDefinition* pDef = NULL;
    hr = pSvc->NewTask(0, &pDef);
    if (FAILED(hr)) { PrintHR(L"NewTask", hr); pFolder->Release(); return hr; }

    // -- RegistrationInfo --
    IRegistrationInfo* pInfo = NULL;
    if (SUCCEEDED(pDef->get_RegistrationInfo(&pInfo)) && pInfo) {
        pInfo->put_Author(_bstr_t(L"remote_task_manager"));
        pInfo->Release();
    }

    // -- Principal --
    IPrincipal* pPrinc = NULL;
    if (SUCCEEDED(pDef->get_Principal(&pPrinc)) && pPrinc) {
        if (_wcsicmp(cfg.runAs, L"SYSTEM") == 0) {
            pPrinc->put_UserId(_bstr_t(L"S-1-5-18"));
            pPrinc->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
        }
        else if (cfg.runAs[0]) {
            pPrinc->put_UserId(_bstr_t(cfg.runAs));
            pPrinc->put_LogonType(TASK_LOGON_PASSWORD);
        }
        else {
            pPrinc->put_UserId(_bstr_t(L"S-1-5-18"));
            pPrinc->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
        }
        pPrinc->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
        pPrinc->Release();
    }

    // -- Settings --
    ITaskSettings* pSet = NULL;
    if (SUCCEEDED(pDef->get_Settings(&pSet)) && pSet) {
        pSet->put_Enabled(VARIANT_TRUE);
        pSet->put_Hidden(cfg.hidden ? VARIANT_TRUE : VARIANT_FALSE);
        pSet->put_StartWhenAvailable(VARIANT_TRUE);
        pSet->put_ExecutionTimeLimit(_bstr_t(L"PT0S"));   // no time limit
        pSet->put_MultipleInstances(TASK_INSTANCES_PARALLEL);
        pSet->Release();
    }

    // -- Trigger --
    // Fix: KHÔNG dùng TASK_TRIGGER_CALENDAR / ICalendarTrigger
    // Dùng trực tiếp TASK_TRIGGER_DAILY / TASK_TRIGGER_WEEKLY / TASK_TRIGGER_TIME
    ITriggerCollection* pTrigColl = NULL;
    if (SUCCEEDED(pDef->get_Triggers(&pTrigColl)) && pTrigColl) {

        TASK_TRIGGER_TYPE2 trigType = TASK_TRIGGER_TIME;     // default: once
        if (_wcsicmp(cfg.trigger, L"daily") == 0) trigType = TASK_TRIGGER_DAILY;
        else if (_wcsicmp(cfg.trigger, L"weekly") == 0) trigType = TASK_TRIGGER_WEEKLY;
        else if (_wcsicmp(cfg.trigger, L"onstart") == 0) trigType = TASK_TRIGGER_BOOT;
        else if (_wcsicmp(cfg.trigger, L"onlogon") == 0) trigType = TASK_TRIGGER_LOGON;

        ITrigger* pTrig = NULL;
        hr = pTrigColl->Create(trigType, &pTrig);
        if (SUCCEEDED(hr) && pTrig) {

            WCHAR startDT[64];
            swprintf_s(startDT, 64, L"%sT%s:00", cfg.startDate, cfg.startTime);

            pTrig->put_StartBoundary(_bstr_t(startDT));
            pTrig->put_Enabled(VARIANT_TRUE);

            // Cấu hình riêng mỗi loại – QI sang interface cụ thể, KHÔNG dùng ICalendarTrigger
            if (trigType == TASK_TRIGGER_DAILY) {
                IDailyTrigger* pDaily = NULL;
                if (SUCCEEDED(pTrig->QueryInterface(IID_IDailyTrigger, (void**)&pDaily)) && pDaily) {
                    pDaily->put_DaysInterval(1);
                    pDaily->Release();
                }
            }
            else if (trigType == TASK_TRIGGER_WEEKLY) {
                IWeeklyTrigger* pWeekly = NULL;
                if (SUCCEEDED(pTrig->QueryInterface(IID_IWeeklyTrigger, (void**)&pWeekly)) && pWeekly) {
                    pWeekly->put_WeeksInterval(1);
                    pWeekly->put_DaysOfWeek((short)TASK_MONDAY);
                    pWeekly->Release();
                }
            }
            // TASK_TRIGGER_TIME / BOOT / LOGON: không cần thêm gì

            pTrig->Release();
        }
        else if (FAILED(hr)) {
            PrintHR(L"ITriggerCollection::Create", hr);
        }
        pTrigColl->Release();
    }

    // -- Action --
    IActionCollection* pActColl = NULL;
    if (SUCCEEDED(pDef->get_Actions(&pActColl)) && pActColl) {
        IAction* pAct = NULL;
        if (SUCCEEDED(pActColl->Create(TASK_ACTION_EXEC, &pAct)) && pAct) {
            IExecAction* pExec = NULL;
            if (SUCCEEDED(pAct->QueryInterface(IID_IExecAction, (void**)&pExec)) && pExec) {
                pExec->put_Path(_bstr_t(cfg.exePath));
                if (cfg.exeArgs[0])
                    pExec->put_Arguments(_bstr_t(cfg.exeArgs));
                pExec->Release();
            }
            pAct->Release();
        }
        pActColl->Release();
    }

    // -- Register --
    _variant_t vPass;
    TASK_LOGON_TYPE logon = TASK_LOGON_SERVICE_ACCOUNT;

    if (_wcsicmp(cfg.runAs, L"SYSTEM") == 0) {
        logon = TASK_LOGON_SERVICE_ACCOUNT;
    }
    else if (cfg.runAs[0]) {
        logon = TASK_LOGON_PASSWORD;
        vPass = cfg.pass;
    }

    _variant_t vUser = (_wcsicmp(cfg.runAs, L"SYSTEM") == 0)
        ? _variant_t(L"S-1-5-18")
        : _variant_t(cfg.runAs);

    IRegisteredTask* pRegTask = NULL;
    hr = pFolder->RegisterTaskDefinition(
        _bstr_t(cfg.taskName),
        pDef,
        TASK_CREATE_OR_UPDATE,
        vUser, vPass,
        logon,
        _variant_t(L""),
        &pRegTask);

    if (SUCCEEDED(hr)) {
        wprintf(L"[+] Task '%s' created/updated successfully.\n", cfg.taskName);
        pRegTask->Release();
    }
    else {
        PrintHR(L"RegisterTaskDefinition", hr);
    }

    pDef->Release();
    pFolder->Release();
    return hr;
}

// ---------------------------------------------------------------------------
// ACTION: run
// ---------------------------------------------------------------------------
static HRESULT ActionRun(ITaskService* pSvc, const Config& cfg)
{
    wprintf(L"[*] Running task '%s' on %s ...\n", cfg.taskName, cfg.host);

    ITaskFolder* pFolder = NULL;
    HRESULT hr = pSvc->GetFolder(_bstr_t(cfg.folder), &pFolder);
    if (FAILED(hr)) { PrintHR(L"GetFolder", hr); return hr; }

    IRegisteredTask* pTask = NULL;
    hr = pFolder->GetTask(_bstr_t(cfg.taskName), &pTask);
    pFolder->Release();
    if (FAILED(hr)) { PrintHR(L"GetTask", hr); return hr; }

    IRunningTask* pRunning = NULL;
    hr = pTask->Run(_variant_t(), &pRunning);
    pTask->Release();

    if (SUCCEEDED(hr)) {
        wprintf(L"[+] Task '%s' triggered.\n", cfg.taskName);
        if (pRunning) {
            BSTR guid = NULL;
            pRunning->get_InstanceGuid(&guid);
            if (guid) { wprintf(L"    GUID: %s\n", guid); SysFreeString(guid); }
            pRunning->Release();
        }
    }
    else {
        PrintHR(L"IRegisteredTask::Run", hr);
    }
    return hr;
}

// ---------------------------------------------------------------------------
// ACTION: delete
// ---------------------------------------------------------------------------
static HRESULT ActionDelete(ITaskService* pSvc, const Config& cfg)
{
    wprintf(L"[*] Deleting task '%s' on %s ...\n", cfg.taskName, cfg.host);

    ITaskFolder* pFolder = NULL;
    HRESULT hr = pSvc->GetFolder(_bstr_t(cfg.folder), &pFolder);
    if (FAILED(hr)) { PrintHR(L"GetFolder", hr); return hr; }

    hr = pFolder->DeleteTask(_bstr_t(cfg.taskName), 0);
    pFolder->Release();

    if (SUCCEEDED(hr))
        wprintf(L"[+] Task '%s' deleted.\n", cfg.taskName);
    else
        PrintHR(L"DeleteTask", hr);
    return hr;
}

// ---------------------------------------------------------------------------
// ACTION: enable / disable
// ---------------------------------------------------------------------------
static HRESULT ActionSetEnabled(ITaskService* pSvc, const Config& cfg, BOOL enable)
{
    wprintf(L"[*] %s task '%s' ...\n", enable ? L"Enabling" : L"Disabling", cfg.taskName);

    ITaskFolder* pFolder = NULL;
    HRESULT hr = pSvc->GetFolder(_bstr_t(cfg.folder), &pFolder);
    if (FAILED(hr)) { PrintHR(L"GetFolder", hr); return hr; }

    IRegisteredTask* pTask = NULL;
    hr = pFolder->GetTask(_bstr_t(cfg.taskName), &pTask);
    pFolder->Release();
    if (FAILED(hr)) { PrintHR(L"GetTask", hr); return hr; }

    hr = pTask->put_Enabled(enable ? VARIANT_TRUE : VARIANT_FALSE);
    pTask->Release();

    if (SUCCEEDED(hr))
        wprintf(L"[+] Task '%s' %s.\n", cfg.taskName, enable ? L"enabled" : L"disabled");
    else
        PrintHR(L"put_Enabled", hr);
    return hr;
}

// ---------------------------------------------------------------------------
// ACTION: query
// ---------------------------------------------------------------------------
static HRESULT ActionQuery(ITaskService* pSvc, const Config& cfg)
{
    wprintf(L"[*] Querying task '%s' on %s ...\n", cfg.taskName, cfg.host);

    ITaskFolder* pFolder = NULL;
    HRESULT hr = pSvc->GetFolder(_bstr_t(cfg.folder), &pFolder);
    if (FAILED(hr)) { PrintHR(L"GetFolder", hr); return hr; }

    IRegisteredTask* pTask = NULL;
    hr = pFolder->GetTask(_bstr_t(cfg.taskName), &pTask);
    pFolder->Release();
    if (FAILED(hr)) { PrintHR(L"GetTask", hr); return hr; }

    wprintf(L"\n");

    BSTR bName = NULL; pTask->get_Name(&bName);
    BSTR bPath = NULL; pTask->get_Path(&bPath);
    TASK_STATE state;  pTask->get_State(&state);
    VARIANT_BOOL enabled; pTask->get_Enabled(&enabled);
    HRESULT lastResult;   pTask->get_LastTaskResult(&lastResult);

    wprintf(L"  Name         : %s\n", bName ? bName : L"?");
    wprintf(L"  Path         : %s\n", bPath ? bPath : L"?");
    wprintf(L"  State        : %s\n", TaskStateStr(state));
    wprintf(L"  Enabled      : %s\n", enabled ? L"Yes" : L"No");
    wprintf(L"  Last Result  : 0x%08lX\n", (unsigned long)lastResult);

    if (bName) SysFreeString(bName);
    if (bPath) SysFreeString(bPath);

    auto PrintDate = [](const wchar_t* label, DATE d) {
        if (d == 0) { wprintf(L"  %-13s: (never)\n", label); return; }
        SYSTEMTIME st = {};
        VariantTimeToSystemTime(d, &st);
        wprintf(L"  %-13s: %04d-%02d-%02d %02d:%02d:%02d\n",
            label, st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
        };
    DATE d; pTask->get_LastRunTime(&d); PrintDate(L"Last Run", d);
    pTask->get_NextRunTime(&d); PrintDate(L"Next Run", d);

    ITaskDefinition* pDef = NULL;
    if (SUCCEEDED(pTask->get_Definition(&pDef)) && pDef) {

        IPrincipal* pPrinc = NULL;
        if (SUCCEEDED(pDef->get_Principal(&pPrinc)) && pPrinc) {
            BSTR uid = NULL; pPrinc->get_UserId(&uid);
            if (uid) { wprintf(L"  Run As       : %s\n", uid); SysFreeString(uid); }
            pPrinc->Release();
        }

        IActionCollection* pActs = NULL;
        if (SUCCEEDED(pDef->get_Actions(&pActs)) && pActs) {
            LONG cnt = 0; pActs->get_Count(&cnt);
            wprintf(L"  Actions (%ld):\n", cnt);
            for (LONG i = 1; i <= cnt; i++) {
                IAction* pA = NULL;
                if (SUCCEEDED(pActs->get_Item(i, &pA)) && pA) {
                    TASK_ACTION_TYPE at; pA->get_Type(&at);
                    if (at == TASK_ACTION_EXEC) {
                        IExecAction* pE = NULL;
                        if (SUCCEEDED(pA->QueryInterface(IID_IExecAction, (void**)&pE)) && pE) {
                            BSTR bp = NULL, ba = NULL;
                            pE->get_Path(&bp); pE->get_Arguments(&ba);
                            wprintf(L"    [%ld] EXEC: %s %s\n", i,
                                bp ? bp : L"", ba ? ba : L"");
                            if (bp) SysFreeString(bp);
                            if (ba) SysFreeString(ba);
                            pE->Release();
                        }
                    }
                    pA->Release();
                }
            }
            pActs->Release();
        }

        ITriggerCollection* pTrigs = NULL;
        if (SUCCEEDED(pDef->get_Triggers(&pTrigs)) && pTrigs) {
            LONG cnt = 0; pTrigs->get_Count(&cnt);
            wprintf(L"  Triggers (%ld):\n", cnt);
            for (LONG i = 1; i <= cnt; i++) {
                ITrigger* pTrig = NULL;
                if (SUCCEEDED(pTrigs->get_Item(i, &pTrig)) && pTrig) {
                    TASK_TRIGGER_TYPE2 tt; pTrig->get_Type(&tt);
                    BSTR bStart = NULL; pTrig->get_StartBoundary(&bStart);
                    VARIANT_BOOL en; pTrig->get_Enabled(&en);

                    const wchar_t* tname = L"Unknown";
                    // Fix: dùng if/else thay vì switch để tránh lỗi "not constant"
                    if (tt == TASK_TRIGGER_TIME)    tname = L"Once(Time)";
                    else if (tt == TASK_TRIGGER_DAILY)   tname = L"Daily";
                    else if (tt == TASK_TRIGGER_WEEKLY)  tname = L"Weekly";
                    else if (tt == TASK_TRIGGER_MONTHLY) tname = L"Monthly";
                    else if (tt == TASK_TRIGGER_BOOT)    tname = L"OnBoot";
                    else if (tt == TASK_TRIGGER_LOGON)   tname = L"OnLogon";
                    else if (tt == TASK_TRIGGER_EVENT)   tname = L"OnEvent";

                    wprintf(L"    [%ld] %-12s  Start: %-24s  Enabled: %s\n",
                        i, tname,
                        bStart ? bStart : L"N/A",
                        en ? L"Yes" : L"No");
                    if (bStart) SysFreeString(bStart);
                    pTrig->Release();
                }
            }
            pTrigs->Release();
        }
        pDef->Release();
    }

    wprintf(L"\n");
    pTask->Release();
    return S_OK;
}

// ---------------------------------------------------------------------------
// ACTION: list
// ---------------------------------------------------------------------------
static HRESULT ActionList(ITaskService* pSvc, const Config& cfg)
{
    wprintf(L"[*] Listing tasks in '%s' on %s ...\n\n", cfg.folder, cfg.host);

    ITaskFolder* pFolder = NULL;
    HRESULT hr = pSvc->GetFolder(_bstr_t(cfg.folder), &pFolder);
    if (FAILED(hr)) { PrintHR(L"GetFolder", hr); return hr; }

    IRegisteredTaskCollection* pColl = NULL;
    hr = pFolder->GetTasks(TASK_ENUM_HIDDEN, &pColl);
    if (FAILED(hr)) { PrintHR(L"GetTasks", hr); pFolder->Release(); return hr; }

    LONG cnt = 0; pColl->get_Count(&cnt);
    wprintf(L"  %-44s %-12s %s\n", L"TaskName", L"State", L"LastResult");
    wprintf(L"  %-44s %-12s %s\n",
        L"--------------------------------------------",
        L"------------", L"----------");

    for (LONG i = 1; i <= cnt; i++) {
        IRegisteredTask* pT = NULL;
        if (SUCCEEDED(pColl->get_Item(_variant_t(i), &pT)) && pT) {
            BSTR bN = NULL;         pT->get_Name(&bN);
            TASK_STATE st;          pT->get_State(&st);
            HRESULT lr;             pT->get_LastTaskResult(&lr);
            wprintf(L"  %-44s %-12s 0x%08lX\n",
                bN ? bN : L"?", TaskStateStr(st), (unsigned long)lr);
            if (bN) SysFreeString(bN);
            pT->Release();
        }
    }
    wprintf(L"\n  Total: %ld task(s)\n\n", cnt);

    pColl->Release();
    pFolder->Release();
    return S_OK;
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------
static void Usage(const wchar_t* prog)
{
    wprintf(
        L"\nUsage:\n"
        L"  %s --host <IP> --user <u> --pass <p>\n"
        L"           --task <n> --action <create|run|delete|query|enable|disable|list>\n"
        L"           [--domain <d>] [--folder <\\Path>]\n\n"
        L"  (create only)\n"
        L"           --exe <path>  [--args <args>]\n"
        L"           [--trigger <once|daily|weekly|onstart|onlogon>]\n"
        L"           [--startdate <YYYY-MM-DD>]  [--starttime <HH:MM>]\n"
        L"           [--runas <SYSTEM|user>]     [--hidden]\n\n"
        L"Examples:\n"
        L"  %s --host 192.168.47.136 --user Administrator --pass P@ssw0rd123\n"
        L"       --task MyTask --exe \"C:\\shell.exe\" --trigger once --runas SYSTEM\n"
        L"       --action create\n\n"
        L"  %s --host 192.168.47.136 --user Administrator --pass P@ssw0rd123\n"
        L"       --task MyTask --action run\n\n"
        L"  %s --host 192.168.47.136 --user Administrator --pass P@ssw0rd123\n"
        L"       --task MyTask --action delete\n\n",
        prog, prog, prog, prog);
}

static bool ParseArgs(int argc, wchar_t** argv, Config& cfg)
{
    memset(&cfg, 0, sizeof(cfg));
    wcscpy_s(cfg.trigger, L"once");
    wcscpy_s(cfg.startDate, L"1970-01-01");
    wcscpy_s(cfg.startTime, L"00:00");
    wcscpy_s(cfg.runAs, L"SYSTEM");
    wcscpy_s(cfg.folder, L"\\");

    for (int i = 1; i < argc; i++) {
#define MATCH(x) (_wcsicmp(argv[i], x) == 0 && i+1 < argc)
        if (MATCH(L"--host"))      wcscpy_s(cfg.host, argv[++i]);
        else if (MATCH(L"--user"))      wcscpy_s(cfg.user, argv[++i]);
        else if (MATCH(L"--pass"))      wcscpy_s(cfg.pass, argv[++i]);
        else if (MATCH(L"--domain"))    wcscpy_s(cfg.domain, argv[++i]);
        else if (MATCH(L"--task"))      wcscpy_s(cfg.taskName, argv[++i]);
        else if (MATCH(L"--exe"))       wcscpy_s(cfg.exePath, argv[++i]);
        else if (MATCH(L"--args"))      wcscpy_s(cfg.exeArgs, argv[++i]);
        else if (MATCH(L"--trigger"))   wcscpy_s(cfg.trigger, argv[++i]);
        else if (MATCH(L"--startdate")) wcscpy_s(cfg.startDate, argv[++i]);
        else if (MATCH(L"--starttime")) wcscpy_s(cfg.startTime, argv[++i]);
        else if (MATCH(L"--runas"))     wcscpy_s(cfg.runAs, argv[++i]);
        else if (MATCH(L"--folder"))    wcscpy_s(cfg.folder, argv[++i]);
        else if (MATCH(L"--action"))    wcscpy_s(cfg.action, argv[++i]);
        else if (_wcsicmp(argv[i], L"--hidden") == 0) cfg.hidden = TRUE;
#undef MATCH
    }

    if (!cfg.host[0] || !cfg.action[0]) {
        wprintf(L"[-] Missing required: --host and --action\n");
        return false;
    }
    bool isList = (_wcsicmp(cfg.action, L"list") == 0);
    if (!isList && !cfg.taskName[0]) {
        wprintf(L"[-] Missing --task\n"); return false;
    }
    if (_wcsicmp(cfg.action, L"create") == 0 && !cfg.exePath[0]) {
        wprintf(L"[-] Missing --exe for create\n"); return false;
    }
    cfg.localMode = IsLocalHost(cfg.host);
    return true;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int wmain(int argc, wchar_t** argv)
{
    wprintf(L"=== Remote Task Manager (COM/WinAPI) ===\n\n");

    Config cfg;
    if (!ParseArgs(argc, argv, cfg)) { Usage(argv[0]); return 1; }

    // Step 1 - IPC$ session
    if (!cfg.localMode) {
        if (!EstablishSession(cfg)) {
            wprintf(L"[-] Cannot establish SMB session.\n");
            return 2;
        }
    }
    else {
        wprintf(L"[*] Local mode - skipping IPC$ session.\n");
    }

    // Step 2 - COM init
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) { PrintHR(L"CoInitializeEx", hr); return 3; }

    CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, 0, NULL);

    // Step 3 - connect Task Scheduler
    ITaskService* pSvc = NULL;
    hr = ConnectTaskService(cfg, &pSvc);
    if (FAILED(hr)) {
        wprintf(L"[-] Cannot connect Task Scheduler on %s\n", cfg.host);
        CoUninitialize(); return 4;
    }
    wprintf(L"[+] Connected to Task Scheduler on %s.\n\n", cfg.host);

    // Step 4 - dispatch action
    HRESULT result = E_FAIL;
    if (_wcsicmp(cfg.action, L"create") == 0) result = ActionCreate(pSvc, cfg);
    else if (_wcsicmp(cfg.action, L"run") == 0) result = ActionRun(pSvc, cfg);
    else if (_wcsicmp(cfg.action, L"delete") == 0) result = ActionDelete(pSvc, cfg);
    else if (_wcsicmp(cfg.action, L"query") == 0) result = ActionQuery(pSvc, cfg);
    else if (_wcsicmp(cfg.action, L"enable") == 0) result = ActionSetEnabled(pSvc, cfg, TRUE);
    else if (_wcsicmp(cfg.action, L"disable") == 0) result = ActionSetEnabled(pSvc, cfg, FALSE);
    else if (_wcsicmp(cfg.action, L"list") == 0) result = ActionList(pSvc, cfg);
    else { wprintf(L"[-] Unknown action: %s\n", cfg.action); Usage(argv[0]); }

    pSvc->Release();
    CoUninitialize();
    return SUCCEEDED(result) ? 0 : 5;
}