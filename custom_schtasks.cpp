/**
 * TaskScheduler.cpp
 * Windows Task Scheduler management program using pure WinAPI
 * Equivalent to schtasks.exe, using Task Scheduler 2.0 COM API
 *
 * Compile: g++ -o TaskScheduler.exe TaskScheduler.cpp -lole32 -loleaut32 -ltaskschd
 * Or with MSVC: cl TaskScheduler.cpp /link ole32.lib oleaut32.lib taskschd.lib
 */
#define _WIN32_WINNT 0x0600
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <comdef.h>
#include <taskschd.h>
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

 // ==================== DATA STRUCTURE ====================
typedef struct {
    WCHAR taskName[256];
    WCHAR taskPath[512];        // Full path in Task Scheduler
    WCHAR programPath[512];     // Program to execute
    WCHAR arguments[512];       // Command-line arguments
    WCHAR workingDir[512];      // Working directory
    WCHAR description[512];     // Task description
    WCHAR author[256];          // Author
    WCHAR runAsUser[256];       // Run as user (default: SYSTEM)
    WCHAR password[256];        // Password (if required)

    // Trigger
    int triggerType;            // 0=ONCE, 1=DAILY, 2=WEEKLY, 3=MONTHLY, 4=ONLOGON, 5=ONSTARTUP, 6=ONIDLE
    WCHAR startTime[32];        // Start time: "2024-12-31T08:00:00"
    WCHAR endTime[32];          // End time
    int intervalDays;           // Days interval (DAILY)
    int daysOfWeek;             // Weekly bitmask: Sun=1,Mon=2,Tue=4,Wed=8,Thu=16,Fri=32,Sat=64
    int daysOfMonth;            // Days of month (MONTHLY)
    int weeksInterval;          // Weeks interval (WEEKLY)
    WCHAR randomDelay[32];      // Random delay: "PT30M"

    // Settings
    BOOL enabled;               // Task enabled
    BOOL runOnDemand;           // Allow manual start
    BOOL startOnBatteries;      // Run on battery
    BOOL stopOnBatteries;       // Stop on low battery
    BOOL wakeToRun;             // Wake computer to run
    BOOL runOnlyIfIdle;         // Run only when idle
    BOOL runOnlyIfNetwork;      // Run only if network available
    int idleMinutes;            // Idle time in minutes
    int execTimeLimit;          // Execution time limit (hours), 0 = unlimited
    int deleteAfterDays;        // Delete task after N days if no schedule
    int restartCount;           // Restart count on failure
    int restartIntervalMinutes; // Restart interval (minutes)

    // Privileges
    int runLevel;               // 0=LUA, 1=HighestAvailable, 2=RequireAdministrator
    BOOL hidden;                // Hide task
    BOOL multipleInstances;     // 0=IgnoreNew, 1=Parallel, 2=Queue, 3=StopExisting
} TaskConfig;

// ==================== UTILITIES ====================
void PrintError(const WCHAR* msg, HRESULT hr) {
    WCHAR buf[512];
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buf, 512, NULL);
    wprintf(L"[ERROR] %s (0x%08X): %s\n", msg, hr, buf);
}

void PrintSuccess(const WCHAR* msg) {
    wprintf(L"[OK] %s\n", msg);
}

void PrintInfo(const WCHAR* msg) {
    wprintf(L"[INFO] %s\n", msg);
}

// Convert TASK_STATE to string
const WCHAR* TaskStateToString(TASK_STATE state) {
    switch (state) {
    case TASK_STATE_UNKNOWN:    return L"Unknown";
    case TASK_STATE_DISABLED:   return L"Disabled";
    case TASK_STATE_QUEUED:     return L"Queued";
    case TASK_STATE_READY:      return L"Ready";
    case TASK_STATE_RUNNING:    return L"Running";
    default:                    return L"Unknown";
    }
}

// ==================== TASK SCHEDULER MANAGER CLASS ====================
class CTaskScheduler {
private:
    ITaskService* m_pService;
    ITaskFolder* m_pRootFolder;
    BOOL m_bInitialized;

public:
    CTaskScheduler() : m_pService(NULL), m_pRootFolder(NULL), m_bInitialized(FALSE) {}
    ~CTaskScheduler() {
        Cleanup();
    }

    // Initialize connection to Task Scheduler
    HRESULT Initialize() {
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
            PrintError(L"Failed to initialize COM", hr);
            return hr;
        }

        hr = CoInitializeSecurity(
            NULL, -1, NULL, NULL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL, 0, NULL);
        // Ignore error if security already set

        hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
            IID_ITaskService, (void**)&m_pService);
        if (FAILED(hr)) {
            PrintError(L"Failed to create ITaskService", hr);
            return hr;
        }

        hr = m_pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        if (FAILED(hr)) {
            PrintError(L"Failed to connect to Task Scheduler", hr);
            return hr;
        }

        hr = m_pService->GetFolder(_bstr_t(L"\\"), &m_pRootFolder);
        if (FAILED(hr)) {
            PrintError(L"Failed to get root folder", hr);
            return hr;
        }

        m_bInitialized = TRUE;
        return S_OK;
    }

    void Cleanup() {
        if (m_pRootFolder) { m_pRootFolder->Release(); m_pRootFolder = NULL; }
        if (m_pService) { m_pService->Release();    m_pService = NULL; }
        if (m_bInitialized) { CoUninitialize(); m_bInitialized = FALSE; }
    }

    // Get or create folder in Task Scheduler
    HRESULT GetOrCreateFolder(const WCHAR* folderPath, ITaskFolder** ppFolder) {
        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), ppFolder);
        if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
            hr = m_pRootFolder->CreateFolder(_bstr_t(folderPath), _variant_t(L""), ppFolder);
        }
        return hr;
    }

    // ==================== CREATE TASK ====================
    HRESULT CreateTask(const TaskConfig* cfg) {
        if (!m_bInitialized) return E_FAIL;

        HRESULT hr;
        ITaskDefinition* pTask = NULL;
        IRegistrationInfo* pRegInfo = NULL;
        ITriggerCollection* pTriggerColl = NULL;
        ITrigger* pTrigger = NULL;
        IActionCollection* pActionColl = NULL;
        IAction* pAction = NULL;
        IExecAction* pExecAction = NULL;
        ITaskSettings* pSettings = NULL;
        IPrincipal* pPrincipal = NULL;
        IRegisteredTask* pRegisteredTask = NULL;

        hr = m_pService->NewTask(0, &pTask);
        if (FAILED(hr)) { PrintError(L"Failed to create task definition", hr); goto cleanup; }

        // ---- Registration Info ----
        hr = pTask->get_RegistrationInfo(&pRegInfo);
        if (SUCCEEDED(hr)) {
            if (wcslen(cfg->description) > 0)
                pRegInfo->put_Description(_bstr_t(cfg->description));
            if (wcslen(cfg->author) > 0)
                pRegInfo->put_Author(_bstr_t(cfg->author));
            pRegInfo->Release(); pRegInfo = NULL;
        }

        // ---- Principal (run privileges) ----
        hr = pTask->get_Principal(&pPrincipal);
        if (SUCCEEDED(hr)) {
            if (wcslen(cfg->runAsUser) > 0)
                pPrincipal->put_UserId(_bstr_t(cfg->runAsUser));

            switch (cfg->runLevel) {
            case 1: pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST); break;
            case 2: pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST); break;
            default: pPrincipal->put_RunLevel(TASK_RUNLEVEL_LUA); break;
            }

            if (wcscmp(cfg->runAsUser, L"SYSTEM") == 0 ||
                wcscmp(cfg->runAsUser, L"NT AUTHORITY\\SYSTEM") == 0) {
                pPrincipal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
            }
            else if (wcslen(cfg->password) > 0) {
                pPrincipal->put_LogonType(TASK_LOGON_PASSWORD);
            }
            else {
                pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
            }
            pPrincipal->Release(); pPrincipal = NULL;
        }

        // ---- Settings ----
        hr = pTask->get_Settings(&pSettings);
        if (SUCCEEDED(hr)) {
            pSettings->put_Enabled(cfg->enabled ? VARIANT_TRUE : VARIANT_FALSE);
            pSettings->put_AllowDemandStart(cfg->runOnDemand ? VARIANT_TRUE : VARIANT_FALSE);
            pSettings->put_DisallowStartIfOnBatteries(cfg->startOnBatteries ? VARIANT_FALSE : VARIANT_TRUE);
            pSettings->put_StopIfGoingOnBatteries(cfg->stopOnBatteries ? VARIANT_TRUE : VARIANT_FALSE);
            pSettings->put_WakeToRun(cfg->wakeToRun ? VARIANT_TRUE : VARIANT_FALSE);
            pSettings->put_Hidden(cfg->hidden ? VARIANT_TRUE : VARIANT_FALSE);
            pSettings->put_RunOnlyIfNetworkAvailable(cfg->runOnlyIfNetwork ? VARIANT_TRUE : VARIANT_FALSE);

            // Execution time limit
            if (cfg->execTimeLimit > 0) {
                WCHAR buf[64];
                swprintf_s(buf, L"PT%dH", cfg->execTimeLimit);
                pSettings->put_ExecutionTimeLimit(_bstr_t(buf));
            }
            else {
                pSettings->put_ExecutionTimeLimit(_bstr_t(L"PT0S"));
            }

            // Restart on failure
            if (cfg->restartCount > 0) {
                pSettings->put_RestartCount(cfg->restartCount);
                WCHAR buf[64];
                swprintf_s(buf, L"PT%dM", cfg->restartIntervalMinutes);
                pSettings->put_RestartInterval(_bstr_t(buf));
            }

            // Delete expired task after
            if (cfg->deleteAfterDays > 0) {
                WCHAR buf[64];
                swprintf_s(buf, L"P%dD", cfg->deleteAfterDays);
                pSettings->put_DeleteExpiredTaskAfter(_bstr_t(buf));
            }

            // Multiple instances policy
            switch (cfg->multipleInstances) {
            case 1: pSettings->put_MultipleInstances(TASK_INSTANCES_PARALLEL); break;
            case 2: pSettings->put_MultipleInstances(TASK_INSTANCES_QUEUE); break;
            case 3: pSettings->put_MultipleInstances(TASK_INSTANCES_STOP_EXISTING); break;
            default: pSettings->put_MultipleInstances(TASK_INSTANCES_IGNORE_NEW); break;
            }

            pSettings->Release(); pSettings = NULL;
        }

        // ---- Triggers ----
        hr = pTask->get_Triggers(&pTriggerColl);
        if (FAILED(hr)) { PrintError(L"Failed to get trigger collection", hr); goto cleanup; }

        {
            TASK_TRIGGER_TYPE2 trigType;
            switch (cfg->triggerType) {
            case 1: trigType = TASK_TRIGGER_DAILY;   break;
            case 2: trigType = TASK_TRIGGER_WEEKLY;  break;
            case 3: trigType = TASK_TRIGGER_MONTHLY; break;
            case 4: trigType = TASK_TRIGGER_LOGON;   break;
            case 5: trigType = TASK_TRIGGER_BOOT;    break;
            case 6: trigType = TASK_TRIGGER_IDLE;    break;
            default: trigType = TASK_TRIGGER_TIME;   break;
            }

            hr = pTriggerColl->Create(trigType, &pTrigger);
            if (FAILED(hr)) { PrintError(L"Failed to create trigger", hr); goto cleanup; }

            if (wcslen(cfg->startTime) > 0)
                pTrigger->put_StartBoundary(_bstr_t(cfg->startTime));
            if (wcslen(cfg->endTime) > 0)
                pTrigger->put_EndBoundary(_bstr_t(cfg->endTime));

            pTrigger->put_Enabled(VARIANT_TRUE);

            if (wcslen(cfg->randomDelay) > 0)
                pTrigger->put_ExecutionTimeLimit(_bstr_t(cfg->randomDelay));  // Note: usually used for random delay

            switch (cfg->triggerType) {
            case 1: { // DAILY
                IDailyTrigger* pDaily = NULL;
                if (SUCCEEDED(pTrigger->QueryInterface(IID_IDailyTrigger, (void**)&pDaily))) {
                    pDaily->put_DaysInterval((short)(cfg->intervalDays > 0 ? cfg->intervalDays : 1));
                    pDaily->Release();
                }
                break;
            }
            case 2: { // WEEKLY
                IWeeklyTrigger* pWeekly = NULL;
                if (SUCCEEDED(pTrigger->QueryInterface(IID_IWeeklyTrigger, (void**)&pWeekly))) {
                    pWeekly->put_DaysOfWeek((short)(cfg->daysOfWeek > 0 ? cfg->daysOfWeek : 0x02)); // Mon default
                    pWeekly->put_WeeksInterval((short)(cfg->weeksInterval > 0 ? cfg->weeksInterval : 1));
                    pWeekly->Release();
                }
                break;
            }
            case 3: { // MONTHLY (by day of month)
                IMonthlyTrigger* pMonthly = NULL;
                if (SUCCEEDED(pTrigger->QueryInterface(IID_IMonthlyTrigger, (void**)&pMonthly))) {
                    pMonthly->put_DaysOfMonth(cfg->daysOfMonth > 0 ? cfg->daysOfMonth : 1);
                    pMonthly->put_MonthsOfYear(0xFFF); // All months
                    pMonthly->Release();
                }
                break;
            }
            }

            pTrigger->Release(); pTrigger = NULL;
        }
        pTriggerColl->Release(); pTriggerColl = NULL;

        // ---- Actions ----
        hr = pTask->get_Actions(&pActionColl);
        if (FAILED(hr)) { PrintError(L"Failed to get action collection", hr); goto cleanup; }

        hr = pActionColl->Create(TASK_ACTION_EXEC, &pAction);
        if (FAILED(hr)) { PrintError(L"Failed to create action", hr); goto cleanup; }

        hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
        if (FAILED(hr)) { PrintError(L"Failed to query IExecAction", hr); goto cleanup; }

        pExecAction->put_Path(_bstr_t(cfg->programPath));
        if (wcslen(cfg->arguments) > 0)
            pExecAction->put_Arguments(_bstr_t(cfg->arguments));
        if (wcslen(cfg->workingDir) > 0)
            pExecAction->put_WorkingDirectory(_bstr_t(cfg->workingDir));

        pExecAction->Release(); pExecAction = NULL;
        pAction->Release(); pAction = NULL;
        pActionColl->Release(); pActionColl = NULL;

        // ---- Register Task ----
        {
            WCHAR folderPath[512] = L"\\";
            WCHAR taskNameOnly[256];
            wcscpy_s(taskNameOnly, cfg->taskName);

            if (wcslen(cfg->taskPath) > 0) {
                const WCHAR* lastSlash = wcsrchr(cfg->taskPath, L'\\');
                if (lastSlash && lastSlash != cfg->taskPath) {
                    size_t len = lastSlash - cfg->taskPath;
                    wcsncpy_s(folderPath, cfg->taskPath, len);
                    wcscpy_s(taskNameOnly, lastSlash + 1);
                }
                else if (lastSlash) {
                    wcscpy_s(taskNameOnly, lastSlash + 1);
                }
            }

            ITaskFolder* pFolder = NULL;
            hr = GetOrCreateFolder(folderPath, &pFolder);
            if (FAILED(hr)) {
                PrintError(L"Failed to get/create task folder", hr);
                goto cleanup;
            }

            _variant_t password_var;
            if (wcslen(cfg->password) > 0)
                password_var = cfg->password;

            TASK_LOGON_TYPE logonType = (wcslen(cfg->password) > 0) ? TASK_LOGON_PASSWORD : TASK_LOGON_INTERACTIVE_TOKEN;

            hr = pFolder->RegisterTaskDefinition(
                _bstr_t(taskNameOnly),
                pTask,
                TASK_CREATE_OR_UPDATE,
                _variant_t(cfg->runAsUser),
                password_var,
                logonType,
                _variant_t(L""),
                &pRegisteredTask);

            pFolder->Release();

            if (FAILED(hr)) {
                PrintError(L"Failed to register task", hr);
                goto cleanup;
            }

            wprintf(L"[OK] Task '%s' created successfully!\n", cfg->taskName);
        }

    cleanup:
        if (pRegisteredTask) pRegisteredTask->Release();
        if (pExecAction)     pExecAction->Release();
        if (pAction)         pAction->Release();
        if (pActionColl)     pActionColl->Release();
        if (pTrigger)        pTrigger->Release();
        if (pTriggerColl)    pTriggerColl->Release();
        if (pSettings)       pSettings->Release();
        if (pPrincipal)      pPrincipal->Release();
        if (pRegInfo)        pRegInfo->Release();
        if (pTask)           pTask->Release();

        return hr;
    }

    // ==================== DELETE TASK ====================
    HRESULT DeleteTask(const WCHAR* taskName, const WCHAR* folderPath = L"\\") {
        ITaskFolder* pFolder = NULL;
        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) {
            PrintError(L"Folder not found", hr);
            return hr;
        }

        hr = pFolder->DeleteTask(_bstr_t(taskName), 0);
        pFolder->Release();

        if (FAILED(hr))
            PrintError(L"Failed to delete task", hr);
        else
            wprintf(L"[OK] Task '%s' has been deleted!\n", taskName);

        return hr;
    }

    // ==================== RUN TASK ====================
    HRESULT RunTask(const WCHAR* taskName, const WCHAR* folderPath = L"\\") {
        ITaskFolder* pFolder = NULL;
        IRegisteredTask* pTask = NULL;
        IRunningTask* pRunning = NULL;

        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) { PrintError(L"Folder not found", hr); return hr; }

        hr = pFolder->GetTask(_bstr_t(taskName), &pTask);
        pFolder->Release();
        if (FAILED(hr)) { PrintError(L"Task not found", hr); return hr; }

        hr = pTask->Run(_variant_t(L""), &pRunning);
        pTask->Release();

        if (FAILED(hr))
            PrintError(L"Failed to run task", hr);
        else {
            wprintf(L"[OK] Task '%s' has been started!\n", taskName);
            if (pRunning) pRunning->Release();
        }
        return hr;
    }

    // ==================== STOP TASK ====================
    HRESULT StopTask(const WCHAR* taskName, const WCHAR* folderPath = L"\\") {
        ITaskFolder* pFolder = NULL;
        IRegisteredTask* pTask = NULL;

        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) { PrintError(L"Folder not found", hr); return hr; }

        hr = pFolder->GetTask(_bstr_t(taskName), &pTask);
        pFolder->Release();
        if (FAILED(hr)) { PrintError(L"Task not found", hr); return hr; }

        hr = pTask->Stop(0);
        pTask->Release();

        if (FAILED(hr))
            PrintError(L"Failed to stop task", hr);
        else
            wprintf(L"[OK] Task '%s' has been stopped!\n", taskName);

        return hr;
    }

    // ==================== ENABLE / DISABLE TASK ====================
    HRESULT EnableTask(const WCHAR* taskName, BOOL enable, const WCHAR* folderPath = L"\\") {
        ITaskFolder* pFolder = NULL;
        IRegisteredTask* pTask = NULL;
        ITaskDefinition* pDef = NULL;
        ITaskSettings* pSettings = NULL;
        IRegisteredTask* pUpdated = NULL;

        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) { PrintError(L"Folder not found", hr); return hr; }

        hr = pFolder->GetTask(_bstr_t(taskName), &pTask);
        if (FAILED(hr)) { pFolder->Release(); PrintError(L"Task not found", hr); return hr; }

        hr = pTask->get_Definition(&pDef);
        if (SUCCEEDED(hr)) {
            hr = pDef->get_Settings(&pSettings);
            if (SUCCEEDED(hr)) {
                pSettings->put_Enabled(enable ? VARIANT_TRUE : VARIANT_FALSE);
                pSettings->Release();

                pFolder->RegisterTaskDefinition(
                    _bstr_t(taskName), pDef,
                    TASK_UPDATE, _variant_t(), _variant_t(),
                    TASK_LOGON_NONE, _variant_t(L""),
                    &pUpdated);

                if (pUpdated) pUpdated->Release();
            }
            pDef->Release();
        }

        pTask->Release();
        pFolder->Release();

        wprintf(L"[OK] Task '%s' has been %s!\n", taskName, enable ? L"enabled" : L"disabled");
        return hr;
    }

    // ==================== LIST TASKS ====================
    HRESULT ListTasks(const WCHAR* folderPath = L"\\", BOOL recursive = TRUE) {
        ITaskFolder* pFolder = NULL;
        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) {
            PrintError(L"Folder not found", hr);
            return hr;
        }

        hr = ListTasksInFolder(pFolder, folderPath, recursive);
        pFolder->Release();
        return hr;
    }

    HRESULT ListTasksInFolder(ITaskFolder* pFolder, const WCHAR* folderPath, BOOL recursive) {
        IRegisteredTaskCollection* pColl = NULL;
        LONG count = 0;

        HRESULT hr = pFolder->GetTasks(TASK_ENUM_HIDDEN, &pColl);
        if (FAILED(hr)) return hr;

        pColl->get_Count(&count);

        if (count > 0) {
            wprintf(L"\n[Folder: %s] (%ld task(s))\n", folderPath, count);
            wprintf(L"%-40s %-15s %-25s %-20s\n",
                L"Task Name", L"State", L"Next Run Time", L"Last Run Time");
            wprintf(L"%-40s %-15s %-25s %-20s\n",
                L"----------------------------------------",
                L"---------------",
                L"-------------------------",
                L"--------------------");
        }

        for (LONG i = 1; i <= count; ++i) {
            IRegisteredTask* pTask = NULL;
            hr = pColl->get_Item(_variant_t(i), &pTask);
            if (FAILED(hr)) continue;

            BSTR name = NULL;
            TASK_STATE state;
            DATE nextRun, lastRun;

            pTask->get_Name(&name);
            pTask->get_State(&state);
            pTask->get_NextRunTime(&nextRun);
            pTask->get_LastRunTime(&lastRun);

            WCHAR nextStr[64] = L"N/A";
            WCHAR lastStr[64] = L"N/A";

            if (nextRun != 0) {
                SYSTEMTIME st;
                VariantTimeToSystemTime(nextRun, &st);
                swprintf_s(nextStr, L"%04d-%02d-%02d %02d:%02d",
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
            }
            if (lastRun != 0) {
                SYSTEMTIME st;
                VariantTimeToSystemTime(lastRun, &st);
                swprintf_s(lastStr, L"%04d-%02d-%02d %02d:%02d",
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
            }

            wprintf(L"%-40s %-15s %-25s %-20s\n",
                name ? name : L"(null)",
                TaskStateToString(state),
                nextStr,
                lastStr);

            if (name) SysFreeString(name);
            pTask->Release();
        }

        pColl->Release();

        // Recurse subfolders
        if (recursive) {
            ITaskFolderCollection* pSubFolders = NULL;
            hr = pFolder->GetFolders(0, &pSubFolders);
            if (SUCCEEDED(hr)) {
                LONG fc = 0;
                pSubFolders->get_Count(&fc);
                for (LONG i = 1; i <= fc; ++i) {
                    ITaskFolder* pSub = NULL;
                    hr = pSubFolders->get_Item(_variant_t(i), &pSub);
                    if (SUCCEEDED(hr)) {
                        BSTR path = NULL;
                        pSub->get_Path(&path);
                        if (path) {
                            ListTasksInFolder(pSub, path, recursive);
                            SysFreeString(path);
                        }
                        pSub->Release();
                    }
                }
                pSubFolders->Release();
            }
        }

        return S_OK;
    }

    // ==================== QUERY TASK DETAILS ====================
    HRESULT QueryTask(const WCHAR* taskName, const WCHAR* folderPath = L"\\") {
        ITaskFolder* pFolder = NULL;
        IRegisteredTask* pTask = NULL;

        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) { PrintError(L"Folder not found", hr); return hr; }

        hr = pFolder->GetTask(_bstr_t(taskName), &pTask);
        pFolder->Release();
        if (FAILED(hr)) { PrintError(L"Task not found", hr); return hr; }

        BSTR name = NULL, path = NULL;
        TASK_STATE state;
        DATE nextRun, lastRun;
        HRESULT lastResult;

        pTask->get_Name(&name);
        pTask->get_Path(&path);
        pTask->get_State(&state);
        pTask->get_NextRunTime(&nextRun);
        pTask->get_LastRunTime(&lastRun);
        pTask->get_LastTaskResult(&lastResult);

        wprintf(L"\n========== TASK DETAILS ==========\n");
        wprintf(L"Name: %s\n", name);
        wprintf(L"Path: %s\n", path);
        wprintf(L"State: %s\n", TaskStateToString(state));
        wprintf(L"Last result: 0x%08X\n", lastResult);

        if (nextRun != 0) {
            SYSTEMTIME st;
            VariantTimeToSystemTime(nextRun, &st);
            wprintf(L"Next run: %04d-%02d-%02d %02d:%02d:%02d\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        }
        if (lastRun != 0) {
            SYSTEMTIME st;
            VariantTimeToSystemTime(lastRun, &st);
            wprintf(L"Last run: %04d-%02d-%02d %02d:%02d:%02d\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        }

        ITaskDefinition* pDef = NULL;
        if (SUCCEEDED(pTask->get_Definition(&pDef))) {
            // Registration Info
            IRegistrationInfo* pReg = NULL;
            if (SUCCEEDED(pDef->get_RegistrationInfo(&pReg))) {
                BSTR desc = NULL, auth = NULL;
                pReg->get_Description(&desc);
                pReg->get_Author(&auth);
                if (desc) { wprintf(L"Description: %s\n", desc); SysFreeString(desc); }
                if (auth) { wprintf(L"Author: %s\n", auth); SysFreeString(auth); }
                pReg->Release();
            }

            // Principal
            IPrincipal* pPrin = NULL;
            if (SUCCEEDED(pDef->get_Principal(&pPrin))) {
                BSTR user = NULL;
                pPrin->get_UserId(&user);
                if (user) { wprintf(L"Run as: %s\n", user); SysFreeString(user); }
                pPrin->Release();
            }

            // Actions
            IActionCollection* pActs = NULL;
            if (SUCCEEDED(pDef->get_Actions(&pActs))) {
                LONG count = 0;
                pActs->get_Count(&count);
                wprintf(L"\n--- Actions (%ld) ---\n", count);
                for (LONG i = 1; i <= count; ++i) {
                    IAction* pAct = NULL;
                    pActs->get_Item(_variant_t(i), &pAct);
                    if (pAct) {
                        TASK_ACTION_TYPE type;
                        pAct->get_Type(&type);
                        if (type == TASK_ACTION_EXEC) {
                            IExecAction* pExec = NULL;
                            if (SUCCEEDED(pAct->QueryInterface(IID_IExecAction, (void**)&pExec))) {
                                BSTR path = NULL, args = NULL, dir = NULL;
                                pExec->get_Path(&path);
                                pExec->get_Arguments(&args);
                                pExec->get_WorkingDirectory(&dir);

                                wprintf(L" Program: %s\n", path ? path : L"");
                                if (args && wcslen(args)) wprintf(L" Arguments: %s\n", args);
                                if (dir && wcslen(dir))  wprintf(L" Directory: %s\n", dir);

                                if (path) SysFreeString(path);
                                if (args) SysFreeString(args);
                                if (dir)  SysFreeString(dir);
                                pExec->Release();
                            }
                        }
                        pAct->Release();
                    }
                }
                pActs->Release();
            }

            // Triggers
            ITriggerCollection* pTrigs = NULL;
            if (SUCCEEDED(pDef->get_Triggers(&pTrigs))) {
                LONG count = 0;
                pTrigs->get_Count(&count);
                wprintf(L"\n--- Triggers (%ld) ---\n", count);
                for (LONG i = 1; i <= count; ++i) {
                    ITrigger* pTrig = NULL;
                    pTrigs->get_Item(_variant_t(i), &pTrig);
                    if (pTrig) {
                        TASK_TRIGGER_TYPE2 type;
                        BSTR start = NULL;
                        pTrig->get_Type(&type);
                        pTrig->get_StartBoundary(&start);

                        const WCHAR* typeName = L"Unknown";
                        switch (type) {
                        case TASK_TRIGGER_TIME:    typeName = L"One time"; break;
                        case TASK_TRIGGER_DAILY:   typeName = L"Daily";    break;
                        case TASK_TRIGGER_WEEKLY:  typeName = L"Weekly";   break;
                        case TASK_TRIGGER_MONTHLY: typeName = L"Monthly";  break;
                        case TASK_TRIGGER_LOGON:   typeName = L"At log on"; break;
                        case TASK_TRIGGER_BOOT:    typeName = L"At startup"; break;
                        case TASK_TRIGGER_IDLE:    typeName = L"On idle";  break;
                        case TASK_TRIGGER_EVENT:   typeName = L"On event"; break;
                        }

                        wprintf(L" Type: %s\n", typeName);
                        if (start && wcslen(start)) wprintf(L" Start: %s\n", start);
                        if (start) SysFreeString(start);
                        pTrig->Release();
                    }
                }
                pTrigs->Release();
            }

            pDef->Release();
        }

        wprintf(L"====================================\n");

        if (name) SysFreeString(name);
        if (path) SysFreeString(path);
        pTask->Release();

        return S_OK;
    }

    // ==================== EXPORT TASK TO XML ====================
    HRESULT ExportTaskXML(const WCHAR* taskName, const WCHAR* outputFile, const WCHAR* folderPath = L"\\") {
        ITaskFolder* pFolder = NULL;
        IRegisteredTask* pTask = NULL;

        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) { PrintError(L"Folder not found", hr); return hr; }

        hr = pFolder->GetTask(_bstr_t(taskName), &pTask);
        pFolder->Release();
        if (FAILED(hr)) { PrintError(L"Task not found", hr); return hr; }

        ITaskDefinition* pDef = NULL;
        hr = pTask->get_Definition(&pDef);
        pTask->Release();
        if (FAILED(hr)) { PrintError(L"Failed to get definition", hr); return hr; }

        BSTR xml = NULL;
        hr = pDef->get_XmlText(&xml);
        pDef->Release();
        if (FAILED(hr)) { PrintError(L"Failed to get XML text", hr); return hr; }

        HANDLE hFile = CreateFileW(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            PrintError(L"Cannot create output file", HRESULT_FROM_WIN32(GetLastError()));
            SysFreeString(xml);
            return E_FAIL;
        }

        // Write UTF-16LE BOM
        WORD bom = 0xFEFF;
        DWORD written;
        WriteFile(hFile, &bom, 2, &written, NULL);
        WriteFile(hFile, xml, SysStringLen(xml) * sizeof(WCHAR), &written, NULL);

        CloseHandle(hFile);
        wprintf(L"[OK] Exported task '%s' to '%s'\n", taskName, outputFile);

        SysFreeString(xml);
        return S_OK;
    }

    // ==================== IMPORT TASK FROM XML ====================
    HRESULT ImportTaskXML(const WCHAR* taskName, const WCHAR* xmlFile, const WCHAR* folderPath = L"\\") {
        HANDLE hFile = CreateFileW(xmlFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            PrintError(L"Cannot open XML file", HRESULT_FROM_WIN32(GetLastError()));
            return E_FAIL;
        }

        DWORD size = GetFileSize(hFile, NULL);
        BYTE* buf = (BYTE*)malloc(size + 2);
        if (!buf) { CloseHandle(hFile); return E_OUTOFMEMORY; }

        DWORD read;
        ReadFile(hFile, buf, size, &read, NULL);
        CloseHandle(hFile);

        buf[size] = 0;
        buf[size + 1] = 0;

        WCHAR* xmlText = (WCHAR*)buf;
        if (buf[0] == 0xFF && buf[1] == 0xFE) xmlText++;

        ITaskFolder* pFolder = NULL;
        IRegisteredTask* pRegTask = NULL;

        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) {
            hr = m_pRootFolder->CreateFolder(_bstr_t(folderPath), _variant_t(L""), &pFolder);
            if (FAILED(hr)) { free(buf); return hr; }
        }

        hr = pFolder->RegisterTask(
            _bstr_t(taskName),
            _bstr_t(xmlText),
            TASK_CREATE_OR_UPDATE,
            _variant_t(), _variant_t(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            _variant_t(L""),
            &pRegTask);

        pFolder->Release();
        free(buf);

        if (FAILED(hr))
            PrintError(L"Failed to import task from XML", hr);
        else {
            if (pRegTask) pRegTask->Release();
            wprintf(L"[OK] Imported task '%s' from '%s'\n", taskName, xmlFile);
        }

        return hr;
    }
};

// ==================== COMMAND LINE HANDLING ====================
void PrintHelp() {
    wprintf(L"\n");
    wprintf(L"TaskScheduler.exe - Windows Task Scheduler Manager (WinAPI)\n");
    wprintf(L"==============================================================\n\n");
    wprintf(L"Usage:\n");
    wprintf(L" TaskScheduler.exe /CREATE [options]     - Create a new task\n");
    wprintf(L" TaskScheduler.exe /DELETE /TN name      - Delete task\n");
    wprintf(L" TaskScheduler.exe /RUN /TN name         - Run task immediately\n");
    wprintf(L" TaskScheduler.exe /END /TN name         - Stop running task\n");
    wprintf(L" TaskScheduler.exe /ENABLE /TN name      - Enable task\n");
    wprintf(L" TaskScheduler.exe /DISABLE /TN name     - Disable task\n");
    wprintf(L" TaskScheduler.exe /QUERY [/TN name]     - Query task(s)\n");
    wprintf(L" TaskScheduler.exe /EXPORT /TN name /XML file - Export task to XML\n");
    wprintf(L" TaskScheduler.exe /IMPORT /TN name /XML file - Import task from XML\n");
    wprintf(L"\n");
    wprintf(L"Options for /CREATE:\n");
    wprintf(L" /TN name          Task name (required)\n");
    wprintf(L" /TR program       Program to run (required)\n");
    wprintf(L" /SC type          Schedule: ONCE|DAILY|WEEKLY|MONTHLY|ONLOGON|ONSTART|ONIDLE\n");
    wprintf(L" /ST HH:MM         Start time (e.g. 08:00)\n");
    wprintf(L" /SD YYYY-MM-DD    Start date\n");
    wprintf(L" /ED YYYY-MM-DD    End date\n");
    wprintf(L" /MO number        Modifier (interval)\n");
    wprintf(L" /D days           Days of week: MON,TUE,WED,THU,FRI,SAT,SUN\n");
    wprintf(L" /RU user          Run as user (default: SYSTEM)\n");
    wprintf(L" /RP password      Password\n");
    wprintf(L" /RL level         Run level: HIGHEST|LIMITED\n");
    wprintf(L" /A arguments      Command-line arguments\n");
    wprintf(L" /WD directory     Working directory\n");
    wprintf(L" /FOLDER path      Folder in Task Scheduler\n");
    wprintf(L" /DESC text        Description\n");
    wprintf(L" /AUTHOR name      Author\n");
    wprintf(L" /ET hours         Execution time limit (hours)\n");
    wprintf(L" /DELAY minutes    Random delay (minutes)\n");
    wprintf(L" /RC count         Restart count on failure\n");
    wprintf(L" /RI minutes       Restart interval (minutes)\n");
    wprintf(L" /F                Force overwrite if exists\n");
    wprintf(L" /HIDE             Hide task\n");
    wprintf(L"\n");
    wprintf(L"Examples:\n");
    wprintf(L" TaskScheduler.exe /CREATE /TN \"MyBackup\" /TR \"C:\\backup.bat\" /SC DAILY /ST 02:00\n");
    wprintf(L" TaskScheduler.exe /CREATE /TN \"WeeklyClean\" /TR \"cleantemp.bat\" /SC WEEKLY /D MON /ST 03:00\n");
    wprintf(L" TaskScheduler.exe /QUERY\n");
    wprintf(L" TaskScheduler.exe /QUERY /TN \"MyBackup\"\n");
    wprintf(L" TaskScheduler.exe /DELETE /TN \"MyBackup\"\n");
    wprintf(L" TaskScheduler.exe /RUN /TN \"MyBackup\"\n");
    wprintf(L" TaskScheduler.exe /EXPORT /TN \"MyBackup\" /XML C:\\task.xml\n");
    wprintf(L"\n");
}

const WCHAR* GetParam(int argc, WCHAR** argv, int index) {
    if (index < argc && argv[index][0] != L'/') return argv[index];
    return NULL;
}

bool HasFlag(int argc, WCHAR** argv, const WCHAR* flag) {
    for (int i = 1; i < argc; ++i)
        if (_wcsicmp(argv[i], flag) == 0) return true;
    return false;
}

const WCHAR* GetArg(int argc, WCHAR** argv, const WCHAR* flag) {
    for (int i = 1; i < argc - 1; ++i)
        if (_wcsicmp(argv[i], flag) == 0) return argv[i + 1];
    return NULL;
}

// Build ISO 8601 datetime
void BuildStartTime(const WCHAR* date, const WCHAR* time, WCHAR* out, int outLen) {
    WCHAR d[32] = L"2024-01-01";
    WCHAR t[32] = L"08:00:00";

    if (date && wcslen(date) == 10) wcscpy_s(d, date);
    else {
        SYSTEMTIME st;
        GetLocalTime(&st);
        swprintf_s(d, L"%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
    }

    if (time && wcslen(time) == 5) swprintf_s(t, L"%s:00", time);

    swprintf_s(out, outLen, L"%sT%s", d, t);
}

int wmain(int argc, WCHAR** argv) {
    if (argc < 2) {
        PrintHelp();
        return 0;
    }

    SetConsoleOutputCP(CP_UTF8);

    CTaskScheduler scheduler;
    HRESULT hr = scheduler.Initialize();
    if (FAILED(hr)) {
        wprintf(L"Failed to initialize Task Scheduler. Please run as Administrator.\n");
        return 1;
    }

    // ==================== /QUERY ====================
    if (HasFlag(argc, argv, L"/QUERY") || HasFlag(argc, argv, L"/query")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER") ? GetArg(argc, argv, L"/FOLDER") : L"\\";

        if (tn) {
            scheduler.QueryTask(tn, folder);
        }
        else {
            scheduler.ListTasks(folder, TRUE);
        }
        return 0;
    }

    // ==================== /DELETE ====================
    if (HasFlag(argc, argv, L"/DELETE") || HasFlag(argc, argv, L"/delete")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER") ? GetArg(argc, argv, L"/FOLDER") : L"\\";
        if (!tn) { wprintf(L"Missing /TN\n"); return 1; }
        scheduler.DeleteTask(tn, folder);
        return 0;
    }

    // ==================== /RUN ====================
    if (HasFlag(argc, argv, L"/RUN") || HasFlag(argc, argv, L"/run")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER") ? GetArg(argc, argv, L"/FOLDER") : L"\\";
        if (!tn) { wprintf(L"Missing /TN\n"); return 1; }
        scheduler.RunTask(tn, folder);
        return 0;
    }

    // ==================== /END ====================
    if (HasFlag(argc, argv, L"/END") || HasFlag(argc, argv, L"/end")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER") ? GetArg(argc, argv, L"/FOLDER") : L"\\";
        if (!tn) { wprintf(L"Missing /TN\n"); return 1; }
        scheduler.StopTask(tn, folder);
        return 0;
    }

    // ==================== /ENABLE ====================
    if (HasFlag(argc, argv, L"/ENABLE") || HasFlag(argc, argv, L"/enable")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER") ? GetArg(argc, argv, L"/FOLDER") : L"\\";
        if (!tn) { wprintf(L"Missing /TN\n"); return 1; }
        scheduler.EnableTask(tn, TRUE, folder);
        return 0;
    }

    // ==================== /DISABLE ====================
    if (HasFlag(argc, argv, L"/DISABLE") || HasFlag(argc, argv, L"/disable")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER") ? GetArg(argc, argv, L"/FOLDER") : L"\\";
        if (!tn) { wprintf(L"Missing /TN\n"); return 1; }
        scheduler.EnableTask(tn, FALSE, folder);
        return 0;
    }

    // ==================== /EXPORT ====================
    if (HasFlag(argc, argv, L"/EXPORT") || HasFlag(argc, argv, L"/export")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* xml = GetArg(argc, argv, L"/XML");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER") ? GetArg(argc, argv, L"/FOLDER") : L"\\";
        if (!tn || !xml) { wprintf(L"Missing /TN or /XML\n"); return 1; }
        scheduler.ExportTaskXML(tn, xml, folder);
        return 0;
    }

    // ==================== /IMPORT ====================
    if (HasFlag(argc, argv, L"/IMPORT") || HasFlag(argc, argv, L"/import")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* xml = GetArg(argc, argv, L"/XML");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER") ? GetArg(argc, argv, L"/FOLDER") : L"\\";
        if (!tn || !xml) { wprintf(L"Missing /TN or /XML\n"); return 1; }
        scheduler.ImportTaskXML(tn, xml, folder);
        return 0;
    }

    // ==================== /CREATE ====================
    if (HasFlag(argc, argv, L"/CREATE") || HasFlag(argc, argv, L"/create")) {
        TaskConfig cfg = {};

        // Defaults
        cfg.enabled = TRUE;
        cfg.runOnDemand = TRUE;
        cfg.startOnBatteries = TRUE;
        cfg.stopOnBatteries = FALSE;
        cfg.runLevel = 0;
        cfg.execTimeLimit = 0;
        cfg.restartCount = 0;
        cfg.restartIntervalMinutes = 1;
        cfg.deleteAfterDays = 0;
        cfg.intervalDays = 1;
        cfg.weeksInterval = 1;
        wcscpy_s(cfg.runAsUser, L"SYSTEM");

        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        if (!tn) { wprintf(L"Error: /TN (task name) is required\n"); return 1; }
        wcscpy_s(cfg.taskName, tn);
        wcscpy_s(cfg.taskPath, tn);

        const WCHAR* tr = GetArg(argc, argv, L"/TR");
        if (!tr) { wprintf(L"Error: /TR (program path) is required\n"); return 1; }
        wcscpy_s(cfg.programPath, tr);

        const WCHAR* sc = GetArg(argc, argv, L"/SC");
        if (sc) {
            if (_wcsicmp(sc, L"ONCE") == 0) cfg.triggerType = 0;
            else if (_wcsicmp(sc, L"DAILY") == 0) cfg.triggerType = 1;
            else if (_wcsicmp(sc, L"WEEKLY") == 0) cfg.triggerType = 2;
            else if (_wcsicmp(sc, L"MONTHLY") == 0) cfg.triggerType = 3;
            else if (_wcsicmp(sc, L"ONLOGON") == 0) cfg.triggerType = 4;
            else if (_wcsicmp(sc, L"ONSTART") == 0 || _wcsicmp(sc, L"ONSTARTUP") == 0) cfg.triggerType = 5;
            else if (_wcsicmp(sc, L"ONIDLE") == 0) cfg.triggerType = 6;
        }

        const WCHAR* st = GetArg(argc, argv, L"/ST");
        const WCHAR* sd = GetArg(argc, argv, L"/SD");
        const WCHAR* ed = GetArg(argc, argv, L"/ED");

        BuildStartTime(sd, st, cfg.startTime, 32);
        if (ed) BuildStartTime(ed, L"23:59", cfg.endTime, 32);

        const WCHAR* mo = GetArg(argc, argv, L"/MO");
        if (mo) {
            cfg.intervalDays = _wtoi(mo);
            cfg.weeksInterval = _wtoi(mo);
        }

        const WCHAR* days = GetArg(argc, argv, L"/D");
        if (days) {
            cfg.daysOfWeek = 0;
            if (wcsstr(days, L"SUN")) cfg.daysOfWeek |= 0x01;
            if (wcsstr(days, L"MON")) cfg.daysOfWeek |= 0x02;
            if (wcsstr(days, L"TUE")) cfg.daysOfWeek |= 0x04;
            if (wcsstr(days, L"WED")) cfg.daysOfWeek |= 0x08;
            if (wcsstr(days, L"THU")) cfg.daysOfWeek |= 0x10;
            if (wcsstr(days, L"FRI")) cfg.daysOfWeek |= 0x20;
            if (wcsstr(days, L"SAT")) cfg.daysOfWeek |= 0x40;
        }
        if (cfg.daysOfWeek == 0 && cfg.triggerType == 2)
            cfg.daysOfWeek = 0x02; // Monday default

        const WCHAR* ru = GetArg(argc, argv, L"/RU");
        if (ru) wcscpy_s(cfg.runAsUser, ru);

        const WCHAR* rp = GetArg(argc, argv, L"/RP");
        if (rp) wcscpy_s(cfg.password, rp);

        const WCHAR* rl = GetArg(argc, argv, L"/RL");
        if (rl) {
            cfg.runLevel = (_wcsicmp(rl, L"HIGHEST") == 0) ? 1 : 0;
        }

        const WCHAR* args = GetArg(argc, argv, L"/A");
        if (args) wcscpy_s(cfg.arguments, args);

        const WCHAR* wdir = GetArg(argc, argv, L"/WD");
        if (wdir) wcscpy_s(cfg.workingDir, wdir);

        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER");
        if (folder) {
            swprintf_s(cfg.taskPath, L"%s\\%s", folder, tn);
        }

        const WCHAR* desc = GetArg(argc, argv, L"/DESC");
        if (desc) wcscpy_s(cfg.description, desc);

        const WCHAR* author = GetArg(argc, argv, L"/AUTHOR");
        if (author) wcscpy_s(cfg.author, author);

        const WCHAR* et = GetArg(argc, argv, L"/ET");
        if (et) cfg.execTimeLimit = _wtoi(et);

        const WCHAR* delay = GetArg(argc, argv, L"/DELAY");
        if (delay) swprintf_s(cfg.randomDelay, L"PT%sM", delay);

        const WCHAR* rc = GetArg(argc, argv, L"/RC");
        if (rc) cfg.restartCount = _wtoi(rc);

        const WCHAR* ri = GetArg(argc, argv, L"/RI");
        if (ri) cfg.restartIntervalMinutes = _wtoi(ri);

        if (HasFlag(argc, argv, L"/HIDE")) cfg.hidden = TRUE;

        hr = scheduler.CreateTask(&cfg);
        return SUCCEEDED(hr) ? 0 : 1;
    }

    PrintHelp();
    return 0;
}