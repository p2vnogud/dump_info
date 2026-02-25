/**
 * TaskScheduler.cpp
 * Chương trình quản lý Task Scheduler Windows sử dụng WinAPI thuần túy
 * Tương đương với schtasks.exe, sử dụng Task Scheduler 2.0 COM API
 *
 * Compile: g++ -o TaskScheduler.exe TaskScheduler.cpp -lole32 -loleaut32 -ltaskschd
 * Hoặc với MSVC: cl TaskScheduler.cpp /link ole32.lib oleaut32.lib taskschd.lib
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

 // ==================== CẤU TRÚC DỮ LIỆU ====================

typedef struct {
    WCHAR taskName[256];
    WCHAR taskPath[512];       // Đường dẫn đầy đủ trong Task Scheduler
    WCHAR programPath[512];    // Chương trình cần chạy
    WCHAR arguments[512];      // Tham số
    WCHAR workingDir[512];     // Thư mục làm việc
    WCHAR description[512];    // Mô tả
    WCHAR author[256];         // Tác giả
    WCHAR runAsUser[256];      // Tài khoản chạy (mặc định: SYSTEM)
    WCHAR password[256];       // Mật khẩu (nếu cần)

    // Trigger
    int triggerType;           // 0=ONCE, 1=DAILY, 2=WEEKLY, 3=MONTHLY, 4=ONLOGON, 5=ONSTARTUP, 6=ONIDLE
    WCHAR startTime[32];       // Thời gian bắt đầu: "2024-12-31T08:00:00"
    WCHAR endTime[32];         // Thời gian kết thúc
    int intervalDays;          // Số ngày giữa các lần chạy (DAILY)
    int daysOfWeek;            // Bitmask ngày trong tuần (WEEKLY): Sun=1,Mon=2,Tue=4,Wed=8,Thu=16,Fri=32,Sat=64
    int daysOfMonth;           // Ngày trong tháng (MONTHLY)
    int weeksInterval;         // Số tuần giữa các lần chạy (WEEKLY)
    WCHAR randomDelay[32];     // Độ trễ ngẫu nhiên: "PT30M"

    // Settings
    BOOL enabled;              // Cho phép task
    BOOL runOnDemand;          // Cho phép chạy thủ công
    BOOL startOnBatteries;     // Chạy khi dùng pin
    BOOL stopOnBatteries;      // Dừng khi pin yếu
    BOOL wakeToRun;            // Đánh thức máy để chạy
    BOOL runOnlyIfIdle;        // Chỉ chạy khi máy rảnh
    BOOL runOnlyIfNetwork;     // Chỉ chạy khi có mạng
    int idleMinutes;           // Số phút rảnh
    int execTimeLimit;         // Giới hạn thời gian chạy (giờ), 0 = không giới hạn
    int deleteAfterDays;       // Xóa task sau N ngày nếu không còn lịch
    int restartCount;          // Số lần thử lại khi thất bại
    int restartIntervalMinutes;// Khoảng thời gian thử lại (phút)

    // Privileges
    int runLevel;              // 0=LUA (thường), 1=HighestAvailable, 2=RequireAdministrator
    BOOL hidden;               // Ẩn task
    BOOL multipleInstances;    // Cho phép nhiều instance: 0=IgnoreNew, 1=Parallel, 2=Queue, 3=StopExisting

} TaskConfig;

// ==================== TIỆN ÍCH ====================

void PrintError(const WCHAR* msg, HRESULT hr) {
    WCHAR buf[512];
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buf, 512, NULL);
    wprintf(L"[LỖI] %s (0x%08X): %s\n", msg, hr, buf);
}

void PrintSuccess(const WCHAR* msg) {
    wprintf(L"[OK] %s\n", msg);
}

void PrintInfo(const WCHAR* msg) {
    wprintf(L"[INFO] %s\n", msg);
}

// Chuyển đổi TASK_STATE sang chuỗi
const WCHAR* TaskStateToString(TASK_STATE state) {
    switch (state) {
    case TASK_STATE_UNKNOWN:  return L"Không xác định";
    case TASK_STATE_DISABLED: return L"Đã tắt";
    case TASK_STATE_QUEUED:   return L"Đang chờ";
    case TASK_STATE_READY:    return L"Sẵn sàng";
    case TASK_STATE_RUNNING:  return L"Đang chạy";
    default: return L"Không biết";
    }
}

// ==================== LỚP QUẢN LÝ TASK SCHEDULER ====================

class CTaskScheduler {
private:
    ITaskService* m_pService;
    ITaskFolder* m_pRootFolder;
    BOOL          m_bInitialized;

public:
    CTaskScheduler() : m_pService(NULL), m_pRootFolder(NULL), m_bInitialized(FALSE) {}

    ~CTaskScheduler() {
        Cleanup();
    }

    // Khởi tạo kết nối đến Task Scheduler
    HRESULT Initialize() {
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
            PrintError(L"Không thể khởi tạo COM", hr);
            return hr;
        }

        hr = CoInitializeSecurity(
            NULL,
            -1,
            NULL,
            NULL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            0,
            NULL);
        // Bỏ qua lỗi nếu security đã được set

        hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
            IID_ITaskService, (void**)&m_pService);
        if (FAILED(hr)) {
            PrintError(L"Không thể tạo ITaskService", hr);
            return hr;
        }

        hr = m_pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        if (FAILED(hr)) {
            PrintError(L"Không thể kết nối Task Scheduler", hr);
            return hr;
        }

        hr = m_pService->GetFolder(_bstr_t(L"\\"), &m_pRootFolder);
        if (FAILED(hr)) {
            PrintError(L"Không thể lấy thư mục gốc", hr);
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

    // Lấy hoặc tạo thư mục trong Task Scheduler
    HRESULT GetOrCreateFolder(const WCHAR* folderPath, ITaskFolder** ppFolder) {
        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), ppFolder);
        if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
            hr = m_pRootFolder->CreateFolder(_bstr_t(folderPath), _variant_t(L""), ppFolder);
        }
        return hr;
    }

    // ==================== TẠO TASK ====================
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

        // Tạo định nghĩa task mới
        hr = m_pService->NewTask(0, &pTask);
        if (FAILED(hr)) { PrintError(L"Không thể tạo task definition", hr); goto cleanup; }

        // ---- Thông tin đăng ký ----
        hr = pTask->get_RegistrationInfo(&pRegInfo);
        if (SUCCEEDED(hr)) {
            if (wcslen(cfg->description) > 0)
                pRegInfo->put_Description(_bstr_t(cfg->description));
            if (wcslen(cfg->author) > 0)
                pRegInfo->put_Author(_bstr_t(cfg->author));
            pRegInfo->Release(); pRegInfo = NULL;
        }

        // ---- Principal (quyền chạy) ----
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

            // Giới hạn thời gian thực thi
            if (cfg->execTimeLimit > 0) {
                WCHAR timeLimitBuf[64];
                swprintf_s(timeLimitBuf, L"PT%dH", cfg->execTimeLimit);
                pSettings->put_ExecutionTimeLimit(_bstr_t(timeLimitBuf));
            }
            else {
                pSettings->put_ExecutionTimeLimit(_bstr_t(L"PT0S")); // Không giới hạn
            }

            // Số lần thử lại
            if (cfg->restartCount > 0) {
                pSettings->put_RestartCount(cfg->restartCount);
                WCHAR restartBuf[64];
                swprintf_s(restartBuf, L"PT%dM", cfg->restartIntervalMinutes);
                pSettings->put_RestartInterval(_bstr_t(restartBuf));
            }

            // Xóa task sau khi hết lịch
            if (cfg->deleteAfterDays > 0) {
                WCHAR deleteBuf[64];
                swprintf_s(deleteBuf, L"P%dD", cfg->deleteAfterDays);
                pSettings->put_DeleteExpiredTaskAfter(_bstr_t(deleteBuf));
            }

            // Multiple instances
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
        if (FAILED(hr)) { PrintError(L"Không thể lấy trigger collection", hr); goto cleanup; }

        {
            TASK_TRIGGER_TYPE2 trigType;
            switch (cfg->triggerType) {
            case 1: trigType = TASK_TRIGGER_DAILY; break;
            case 2: trigType = TASK_TRIGGER_WEEKLY; break;
            case 3: trigType = TASK_TRIGGER_MONTHLY; break;
            case 4: trigType = TASK_TRIGGER_LOGON; break;
            case 5: trigType = TASK_TRIGGER_BOOT; break;
            case 6: trigType = TASK_TRIGGER_IDLE; break;
            default: trigType = TASK_TRIGGER_TIME; break;
            }

            hr = pTriggerColl->Create(trigType, &pTrigger);
            if (FAILED(hr)) { PrintError(L"Không thể tạo trigger", hr); goto cleanup; }

            // Thời gian bắt đầu
            if (wcslen(cfg->startTime) > 0)
                pTrigger->put_StartBoundary(_bstr_t(cfg->startTime));
            if (wcslen(cfg->endTime) > 0)
                pTrigger->put_EndBoundary(_bstr_t(cfg->endTime));

            pTrigger->put_Enabled(VARIANT_TRUE);

            if (wcslen(cfg->randomDelay) > 0)
                pTrigger->put_ExecutionTimeLimit(_bstr_t(cfg->randomDelay));

            // Cài đặt trigger cụ thể
            switch (cfg->triggerType) {
            case 1: { // DAILY
                IDailyTrigger* pDaily = NULL;
                hr = pTrigger->QueryInterface(IID_IDailyTrigger, (void**)&pDaily);
                if (SUCCEEDED(hr)) {
                    pDaily->put_DaysInterval((short)(cfg->intervalDays > 0 ? cfg->intervalDays : 1));
                    pDaily->Release();
                }
                break;
            }
            case 2: { // WEEKLY
                IWeeklyTrigger* pWeekly = NULL;
                hr = pTrigger->QueryInterface(IID_IWeeklyTrigger, (void**)&pWeekly);
                if (SUCCEEDED(hr)) {
                    pWeekly->put_DaysOfWeek((short)(cfg->daysOfWeek > 0 ? cfg->daysOfWeek : 0x02)); // Mon default
                    pWeekly->put_WeeksInterval((short)(cfg->weeksInterval > 0 ? cfg->weeksInterval : 1));
                    pWeekly->Release();
                }
                break;
            }
            case 3: { // MONTHLY
                IMonthlyTrigger* pMonthly = NULL;
                hr = pTrigger->QueryInterface(IID_IMonthlyTrigger, (void**)&pMonthly);
                if (SUCCEEDED(hr)) {
                    pMonthly->put_DaysOfMonth(cfg->daysOfMonth > 0 ? cfg->daysOfMonth : 1);
                    pMonthly->put_MonthsOfYear(0xFFF); // Tất cả các tháng
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
        if (FAILED(hr)) { PrintError(L"Không thể lấy action collection", hr); goto cleanup; }

        hr = pActionColl->Create(TASK_ACTION_EXEC, &pAction);
        if (FAILED(hr)) { PrintError(L"Không thể tạo action", hr); goto cleanup; }

        hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
        if (FAILED(hr)) { PrintError(L"Không thể lấy IExecAction", hr); goto cleanup; }

        pExecAction->put_Path(_bstr_t(cfg->programPath));
        if (wcslen(cfg->arguments) > 0)
            pExecAction->put_Arguments(_bstr_t(cfg->arguments));
        if (wcslen(cfg->workingDir) > 0)
            pExecAction->put_WorkingDirectory(_bstr_t(cfg->workingDir));

        pExecAction->Release(); pExecAction = NULL;
        pAction->Release(); pAction = NULL;
        pActionColl->Release(); pActionColl = NULL;

        // ---- Đăng ký Task ----
        {
            // Xác định thư mục
            WCHAR folderPath[512] = L"\\";
            WCHAR taskNameOnly[256];
            wcscpy_s(taskNameOnly, cfg->taskName);

            if (wcslen(cfg->taskPath) > 0) {
                // Tách thư mục và tên từ taskPath
                const WCHAR* lastBackslash = wcsrchr(cfg->taskPath, L'\\');
                if (lastBackslash && lastBackslash != cfg->taskPath) {
                    size_t folderLen = lastBackslash - cfg->taskPath;
                    wcsncpy_s(folderPath, cfg->taskPath, folderLen);
                    wcscpy_s(taskNameOnly, lastBackslash + 1);
                }
                else if (lastBackslash) {
                    wcscpy_s(taskNameOnly, lastBackslash + 1);
                }
            }

            ITaskFolder* pFolder = NULL;
            hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
            if (FAILED(hr)) {
                hr = m_pRootFolder->CreateFolder(_bstr_t(folderPath), _variant_t(L""), &pFolder);
                if (FAILED(hr)) {
                    PrintError(L"Không thể tạo thư mục task", hr);
                    goto cleanup;
                }
            }

            _variant_t password_v;
            if (wcslen(cfg->password) > 0)
                password_v = cfg->password;

            hr = pFolder->RegisterTaskDefinition(
                _bstr_t(taskNameOnly),
                pTask,
                TASK_CREATE_OR_UPDATE,
                _variant_t(cfg->runAsUser),
                password_v,
                (wcslen(cfg->password) > 0) ? TASK_LOGON_PASSWORD : TASK_LOGON_INTERACTIVE_TOKEN,
                _variant_t(L""),
                &pRegisteredTask);

            pFolder->Release();

            if (FAILED(hr)) {
                PrintError(L"Không thể đăng ký task", hr);
                goto cleanup;
            }

            wprintf(L"[OK] Task '%s' đã được tạo thành công!\n", cfg->taskName);
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

    // ==================== XÓA TASK ====================
    HRESULT DeleteTask(const WCHAR* taskName, const WCHAR* folderPath = L"\\") {
        ITaskFolder* pFolder = NULL;
        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) {
            PrintError(L"Không tìm thấy thư mục", hr);
            return hr;
        }

        hr = pFolder->DeleteTask(_bstr_t(taskName), 0);
        pFolder->Release();

        if (FAILED(hr))
            PrintError(L"Không thể xóa task", hr);
        else
            wprintf(L"[OK] Task '%s' đã được xóa!\n", taskName);

        return hr;
    }

    // ==================== CHẠY TASK ====================
    HRESULT RunTask(const WCHAR* taskName, const WCHAR* folderPath = L"\\") {
        ITaskFolder* pFolder = NULL;
        IRegisteredTask* pTask = NULL;
        IRunningTask* pRunningTask = NULL;

        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) { PrintError(L"Không tìm thấy thư mục", hr); return hr; }

        hr = pFolder->GetTask(_bstr_t(taskName), &pTask);
        pFolder->Release();
        if (FAILED(hr)) { PrintError(L"Không tìm thấy task", hr); return hr; }

        hr = pTask->Run(_variant_t(L""), &pRunningTask);
        pTask->Release();

        if (FAILED(hr))
            PrintError(L"Không thể chạy task", hr);
        else {
            wprintf(L"[OK] Task '%s' đã được khởi động!\n", taskName);
            if (pRunningTask) pRunningTask->Release();
        }

        return hr;
    }

    // ==================== DỪNG TASK ====================
    HRESULT StopTask(const WCHAR* taskName, const WCHAR* folderPath = L"\\") {
        ITaskFolder* pFolder = NULL;
        IRegisteredTask* pTask = NULL;

        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) { PrintError(L"Không tìm thấy thư mục", hr); return hr; }

        hr = pFolder->GetTask(_bstr_t(taskName), &pTask);
        pFolder->Release();
        if (FAILED(hr)) { PrintError(L"Không tìm thấy task", hr); return hr; }

        hr = pTask->Stop(0);
        pTask->Release();

        if (FAILED(hr))
            PrintError(L"Không thể dừng task", hr);
        else
            wprintf(L"[OK] Task '%s' đã bị dừng!\n", taskName);

        return hr;
    }

    // ==================== BẬT/TẮT TASK ====================
    HRESULT EnableTask(const WCHAR* taskName, BOOL enable, const WCHAR* folderPath = L"\\") {
        ITaskFolder* pFolder = NULL;
        IRegisteredTask* pTask = NULL;
        ITaskDefinition* pDef = NULL;
        ITaskSettings* pSettings = NULL;
        IRegisteredTask* pUpdatedTask = NULL;

        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) { PrintError(L"Không tìm thấy thư mục", hr); return hr; }

        hr = pFolder->GetTask(_bstr_t(taskName), &pTask);
        if (FAILED(hr)) { pFolder->Release(); PrintError(L"Không tìm thấy task", hr); return hr; }

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
                    &pUpdatedTask);
                if (pUpdatedTask) { pUpdatedTask->Release(); }
            }
            pDef->Release();
        }

        pTask->Release();
        pFolder->Release();

        wprintf(L"[OK] Task '%s' đã được %s!\n", taskName, enable ? L"bật" : L"tắt");
        return hr;
    }

    // ==================== LIỆT KÊ TASKS ====================
    HRESULT ListTasks(const WCHAR* folderPath = L"\\", BOOL recursive = TRUE) {
        ITaskFolder* pFolder = NULL;

        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) {
            PrintError(L"Không tìm thấy thư mục", hr);
            return hr;
        }

        hr = ListTasksInFolder(pFolder, folderPath, recursive);
        pFolder->Release();
        return hr;
    }

    HRESULT ListTasksInFolder(ITaskFolder* pFolder, const WCHAR* folderPath, BOOL recursive) {
        IRegisteredTaskCollection* pTaskColl = NULL;
        LONG count = 0;

        HRESULT hr = pFolder->GetTasks(TASK_ENUM_HIDDEN, &pTaskColl);
        if (FAILED(hr)) return hr;

        hr = pTaskColl->get_Count(&count);
        if (FAILED(hr)) { pTaskColl->Release(); return hr; }

        if (count > 0) {
            wprintf(L"\n[Thư mục: %s] (%ld task(s))\n", folderPath, count);
            wprintf(L"%-40s %-15s %-25s %-20s\n", L"Tên Task", L"Trạng thái", L"Lần chạy tiếp theo", L"Lần chạy cuối");
            wprintf(L"%-40s %-15s %-25s %-20s\n", L"----------------------------------------",
                L"---------------", L"-------------------------", L"--------------------");
        }

        for (LONG i = 1; i <= count; i++) {
            IRegisteredTask* pTask = NULL;
            hr = pTaskColl->get_Item(_variant_t(i), &pTask);
            if (FAILED(hr)) continue;

            BSTR taskName = NULL;
            TASK_STATE state;
            DATE nextRun, lastRun;
            HRESULT lastResult;

            pTask->get_Name(&taskName);
            pTask->get_State(&state);
            pTask->get_NextRunTime(&nextRun);
            pTask->get_LastRunTime(&lastRun);
            pTask->get_LastTaskResult(&lastResult);

            WCHAR nextRunStr[64] = L"N/A";
            WCHAR lastRunStr[64] = L"N/A";

            if (nextRun != 0) {
                SYSTEMTIME st;
                VariantTimeToSystemTime(nextRun, &st);
                swprintf_s(nextRunStr, L"%04d-%02d-%02d %02d:%02d",
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
            }
            if (lastRun != 0) {
                SYSTEMTIME st;
                VariantTimeToSystemTime(lastRun, &st);
                swprintf_s(lastRunStr, L"%04d-%02d-%02d %02d:%02d",
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
            }

            wprintf(L"%-40s %-15s %-25s %-20s\n",
                taskName ? taskName : L"(null)",
                TaskStateToString(state),
                nextRunStr,
                lastRunStr);

            if (taskName) SysFreeString(taskName);
            pTask->Release();
        }
        pTaskColl->Release();

        // Đệ quy vào các thư mục con
        if (recursive) {
            ITaskFolderCollection* pSubFolders = NULL;
            hr = pFolder->GetFolders(0, &pSubFolders);
            if (SUCCEEDED(hr)) {
                LONG folderCount = 0;
                pSubFolders->get_Count(&folderCount);
                for (LONG i = 1; i <= folderCount; i++) {
                    ITaskFolder* pSubFolder = NULL;
                    hr = pSubFolders->get_Item(_variant_t(i), &pSubFolder);
                    if (SUCCEEDED(hr)) {
                        BSTR subPath = NULL;
                        pSubFolder->get_Path(&subPath);
                        if (subPath) {
                            ListTasksInFolder(pSubFolder, subPath, recursive);
                            SysFreeString(subPath);
                        }
                        pSubFolder->Release();
                    }
                }
                pSubFolders->Release();
            }
        }

        return S_OK;
    }

    // ==================== XEM CHI TIẾT TASK ====================
    HRESULT QueryTask(const WCHAR* taskName, const WCHAR* folderPath = L"\\") {
        ITaskFolder* pFolder = NULL;
        IRegisteredTask* pTask = NULL;
        ITaskDefinition* pDef = NULL;

        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) { PrintError(L"Không tìm thấy thư mục", hr); return hr; }

        hr = pFolder->GetTask(_bstr_t(taskName), &pTask);
        pFolder->Release();
        if (FAILED(hr)) { PrintError(L"Không tìm thấy task", hr); return hr; }

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

        wprintf(L"\n========== CHI TIẾT TASK ==========\n");
        wprintf(L"Tên:               %s\n", name);
        wprintf(L"Đường dẫn:         %s\n", path);
        wprintf(L"Trạng thái:        %s\n", TaskStateToString(state));
        wprintf(L"Kết quả lần cuối:  0x%08X\n", lastResult);

        if (nextRun != 0) {
            SYSTEMTIME st;
            VariantTimeToSystemTime(nextRun, &st);
            wprintf(L"Lần chạy tiếp:     %04d-%02d-%02d %02d:%02d:%02d\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        }
        if (lastRun != 0) {
            SYSTEMTIME st;
            VariantTimeToSystemTime(lastRun, &st);
            wprintf(L"Lần chạy cuối:     %04d-%02d-%02d %02d:%02d:%02d\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        }

        // Xem định nghĩa
        hr = pTask->get_Definition(&pDef);
        if (SUCCEEDED(hr)) {
            IRegistrationInfo* pReg = NULL;
            pDef->get_RegistrationInfo(&pReg);
            if (pReg) {
                BSTR desc = NULL, author = NULL;
                pReg->get_Description(&desc);
                pReg->get_Author(&author);
                if (desc) { wprintf(L"Mô tả:             %s\n", desc); SysFreeString(desc); }
                if (author) { wprintf(L"Tác giả:           %s\n", author); SysFreeString(author); }
                pReg->Release();
            }

            IPrincipal* pPrincipal = NULL;
            pDef->get_Principal(&pPrincipal);
            if (pPrincipal) {
                BSTR userId = NULL;
                pPrincipal->get_UserId(&userId);
                if (userId) { wprintf(L"Chạy với:          %s\n", userId); SysFreeString(userId); }
                pPrincipal->Release();
            }

            IActionCollection* pActions = NULL;
            pDef->get_Actions(&pActions);
            if (pActions) {
                LONG actCount = 0;
                pActions->get_Count(&actCount);
                wprintf(L"\n--- Actions (%ld) ---\n", actCount);
                for (LONG i = 1; i <= actCount; i++) {
                    IAction* pAct = NULL;
                    pActions->get_Item(_variant_t(i), &pAct);
                    if (pAct) {
                        TASK_ACTION_TYPE actType;
                        pAct->get_Type(&actType);
                        if (actType == TASK_ACTION_EXEC) {
                            IExecAction* pExec = NULL;
                            pAct->QueryInterface(IID_IExecAction, (void**)&pExec);
                            if (pExec) {
                                BSTR prog = NULL, args = NULL, wdir = NULL;
                                pExec->get_Path(&prog);
                                pExec->get_Arguments(&args);
                                pExec->get_WorkingDirectory(&wdir);
                                wprintf(L"  Chương trình:    %s\n", prog ? prog : L"");
                                if (args && wcslen(args) > 0) wprintf(L"  Tham số:         %s\n", args);
                                if (wdir && wcslen(wdir) > 0) wprintf(L"  Thư mục:         %s\n", wdir);
                                if (prog) SysFreeString(prog);
                                if (args) SysFreeString(args);
                                if (wdir) SysFreeString(wdir);
                                pExec->Release();
                            }
                        }
                        pAct->Release();
                    }
                }
                pActions->Release();
            }

            ITriggerCollection* pTriggers = NULL;
            pDef->get_Triggers(&pTriggers);
            if (pTriggers) {
                LONG trgCount = 0;
                pTriggers->get_Count(&trgCount);
                wprintf(L"\n--- Triggers (%ld) ---\n", trgCount);
                for (LONG i = 1; i <= trgCount; i++) {
                    ITrigger* pTrg = NULL;
                    pTriggers->get_Item(_variant_t(i), &pTrg);
                    if (pTrg) {
                        TASK_TRIGGER_TYPE2 trgType;
                        BSTR startBound = NULL;
                        pTrg->get_Type(&trgType);
                        pTrg->get_StartBoundary(&startBound);

                        const WCHAR* typeName = L"Không xác định";
                        switch (trgType) {
                        case TASK_TRIGGER_TIME: typeName = L"Một lần"; break;
                        case TASK_TRIGGER_DAILY: typeName = L"Hàng ngày"; break;
                        case TASK_TRIGGER_WEEKLY: typeName = L"Hàng tuần"; break;
                        case TASK_TRIGGER_MONTHLY: typeName = L"Hàng tháng"; break;
                        case TASK_TRIGGER_LOGON: typeName = L"Khi đăng nhập"; break;
                        case TASK_TRIGGER_BOOT: typeName = L"Khi khởi động"; break;
                        case TASK_TRIGGER_IDLE: typeName = L"Khi rảnh"; break;
                        case TASK_TRIGGER_EVENT: typeName = L"Sự kiện"; break;
                        }
                        wprintf(L"  Loại trigger:    %s\n", typeName);
                        if (startBound && wcslen(startBound) > 0)
                            wprintf(L"  Bắt đầu:         %s\n", startBound);
                        if (startBound) SysFreeString(startBound);
                        pTrg->Release();
                    }
                }
                pTriggers->Release();
            }

            pDef->Release();
        }

        wprintf(L"====================================\n");

        if (name) SysFreeString(name);
        if (path) SysFreeString(path);
        pTask->Release();
        return S_OK;
    }

    // ==================== XUẤT TASK XML ====================
    HRESULT ExportTaskXML(const WCHAR* taskName, const WCHAR* outputFile, const WCHAR* folderPath = L"\\") {
        ITaskFolder* pFolder = NULL;
        IRegisteredTask* pTask = NULL;

        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) { PrintError(L"Không tìm thấy thư mục", hr); return hr; }

        hr = pFolder->GetTask(_bstr_t(taskName), &pTask);
        pFolder->Release();
        if (FAILED(hr)) { PrintError(L"Không tìm thấy task", hr); return hr; }

        ITaskDefinition* pDef = NULL;
        hr = pTask->get_Definition(&pDef);
        pTask->Release();
        if (FAILED(hr)) { PrintError(L"Không lấy được definition", hr); return hr; }

        BSTR xmlText = NULL;
        hr = pDef->get_XmlText(&xmlText);
        pDef->Release();
        if (FAILED(hr)) { PrintError(L"Không lấy được XML", hr); return hr; }

        // Ghi ra file
        HANDLE hFile = CreateFileW(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            PrintError(L"Không thể tạo file output", HRESULT_FROM_WIN32(GetLastError()));
            SysFreeString(xmlText);
            return E_FAIL;
        }

        // Ghi BOM UTF-16LE
        WORD bom = 0xFEFF;
        DWORD written;
        WriteFile(hFile, &bom, 2, &written, NULL);
        WriteFile(hFile, xmlText, SysStringLen(xmlText) * sizeof(WCHAR), &written, NULL);
        CloseHandle(hFile);

        wprintf(L"[OK] Đã xuất XML task '%s' ra '%s'\n", taskName, outputFile);
        SysFreeString(xmlText);
        return S_OK;
    }

    // ==================== NHẬP TASK TỪ XML ====================
    HRESULT ImportTaskXML(const WCHAR* taskName, const WCHAR* xmlFile, const WCHAR* folderPath = L"\\") {
        // Đọc file XML
        HANDLE hFile = CreateFileW(xmlFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            PrintError(L"Không thể mở file XML", HRESULT_FROM_WIN32(GetLastError()));
            return E_FAIL;
        }

        DWORD fileSize = GetFileSize(hFile, NULL);
        BYTE* buffer = (BYTE*)malloc(fileSize + 2);
        if (!buffer) { CloseHandle(hFile); return E_OUTOFMEMORY; }

        DWORD bytesRead;
        ReadFile(hFile, buffer, fileSize, &bytesRead, NULL);
        CloseHandle(hFile);
        buffer[fileSize] = 0;
        buffer[fileSize + 1] = 0;

        // Bỏ qua BOM nếu có
        WCHAR* xmlText = (WCHAR*)buffer;
        if (buffer[0] == 0xFF && buffer[1] == 0xFE) xmlText++;

        ITaskFolder* pFolder = NULL;
        IRegisteredTask* pRegisteredTask = NULL;

        HRESULT hr = m_pRootFolder->GetFolder(_bstr_t(folderPath), &pFolder);
        if (FAILED(hr)) {
            hr = m_pRootFolder->CreateFolder(_bstr_t(folderPath), _variant_t(L""), &pFolder);
            if (FAILED(hr)) { free(buffer); return hr; }
        }

        hr = pFolder->RegisterTask(
            _bstr_t(taskName),
            _bstr_t(xmlText),
            TASK_CREATE_OR_UPDATE,
            _variant_t(), _variant_t(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            _variant_t(L""),
            &pRegisteredTask);

        pFolder->Release();
        free(buffer);

        if (FAILED(hr))
            PrintError(L"Không thể nhập task từ XML", hr);
        else {
            if (pRegisteredTask) pRegisteredTask->Release();
            wprintf(L"[OK] Đã nhập task '%s' từ '%s'\n", taskName, xmlFile);
        }

        return hr;
    }
};

// ==================== XỬ LÝ DÒNG LỆNH ====================

void PrintHelp() {
    wprintf(L"\n");
    wprintf(L"TaskScheduler.exe - Quản lý Windows Task Scheduler (WinAPI)\n");
    wprintf(L"==============================================================\n\n");
    wprintf(L"Cú pháp:\n");
    wprintf(L"  TaskScheduler.exe /CREATE [tùy chọn]     - Tạo task mới\n");
    wprintf(L"  TaskScheduler.exe /DELETE /TN tên        - Xóa task\n");
    wprintf(L"  TaskScheduler.exe /RUN /TN tên           - Chạy task ngay\n");
    wprintf(L"  TaskScheduler.exe /END /TN tên           - Dừng task đang chạy\n");
    wprintf(L"  TaskScheduler.exe /ENABLE /TN tên        - Bật task\n");
    wprintf(L"  TaskScheduler.exe /DISABLE /TN tên       - Tắt task\n");
    wprintf(L"  TaskScheduler.exe /QUERY [/TN tên]       - Xem thông tin task\n");
    wprintf(L"  TaskScheduler.exe /EXPORT /TN tên /XML f - Xuất task ra XML\n");
    wprintf(L"  TaskScheduler.exe /IMPORT /TN tên /XML f - Nhập task từ XML\n");
    wprintf(L"\n");
    wprintf(L"Tùy chọn cho /CREATE:\n");
    wprintf(L"  /TN tên           Tên task (bắt buộc)\n");
    wprintf(L"  /TR chương_trình  Chương trình cần chạy (bắt buộc)\n");
    wprintf(L"  /SC loại          Lịch: ONCE|DAILY|WEEKLY|MONTHLY|ONLOGON|ONSTART|ONIDLE\n");
    wprintf(L"  /ST HH:MM         Thời gian bắt đầu (VD: 08:00)\n");
    wprintf(L"  /SD YYYY-MM-DD    Ngày bắt đầu\n");
    wprintf(L"  /ED YYYY-MM-DD    Ngày kết thúc\n");
    wprintf(L"  /MO số            Khoảng cách (ngày/tuần/tháng)\n");
    wprintf(L"  /D ngày           Ngày trong tuần: MON,TUE,WED,THU,FRI,SAT,SUN\n");
    wprintf(L"  /RU tài_khoản     Tài khoản chạy (mặc định: SYSTEM)\n");
    wprintf(L"  /RP mật_khẩu      Mật khẩu\n");
    wprintf(L"  /RL mức           Quyền: HIGHEST|LIMITED\n");
    wprintf(L"  /A tham_số        Tham số chương trình\n");
    wprintf(L"  /FOLDER thư_mục   Thư mục trong Task Scheduler\n");
    wprintf(L"  /DESC mô_tả       Mô tả task\n");
    wprintf(L"  /AUTHOR tác_giả   Tác giả\n");
    wprintf(L"  /ET giờ           Giới hạn thời gian chạy (giờ)\n");
    wprintf(L"  /DELAY phút       Độ trễ ngẫu nhiên (phút)\n");
    wprintf(L"  /RC số            Số lần thử lại khi thất bại\n");
    wprintf(L"  /RI phút          Khoảng thời gian thử lại (phút)\n");
    wprintf(L"  /F                Buộc ghi đè nếu đã tồn tại\n");
    wprintf(L"  /NP               Không yêu cầu mật khẩu\n");
    wprintf(L"  /HIDELEVEL        Ẩn task\n");
    wprintf(L"\n");
    wprintf(L"Ví dụ:\n");
    wprintf(L"  TaskScheduler.exe /CREATE /TN \"MyBackup\" /TR \"C:\\backup.bat\" /SC DAILY /ST 02:00\n");
    wprintf(L"  TaskScheduler.exe /CREATE /TN \"WeeklyClean\" /TR \"cleantemp.bat\" /SC WEEKLY /D MON /ST 03:00\n");
    wprintf(L"  TaskScheduler.exe /CREATE /TN \"OnBoot\" /TR \"C:\\startup.exe\" /SC ONSTART\n");
    wprintf(L"  TaskScheduler.exe /QUERY\n");
    wprintf(L"  TaskScheduler.exe /QUERY /TN \"MyBackup\"\n");
    wprintf(L"  TaskScheduler.exe /DELETE /TN \"MyBackup\"\n");
    wprintf(L"  TaskScheduler.exe /RUN /TN \"MyBackup\"\n");
    wprintf(L"  TaskScheduler.exe /EXPORT /TN \"MyBackup\" /XML C:\\backup_task.xml\n");
    wprintf(L"\n");
}

// Tìm tham số tiếp theo trong argv
const WCHAR* GetParam(int argc, WCHAR** argv, int index) {
    if (index < argc && argv[index][0] != L'/') return argv[index];
    return NULL;
}

bool HasFlag(int argc, WCHAR** argv, const WCHAR* flag) {
    for (int i = 1; i < argc; i++)
        if (_wcsicmp(argv[i], flag) == 0) return true;
    return false;
}

const WCHAR* GetArg(int argc, WCHAR** argv, const WCHAR* flag) {
    for (int i = 1; i < argc - 1; i++)
        if (_wcsicmp(argv[i], flag) == 0) return argv[i + 1];
    return NULL;
}

// Chuyển đổi ngày/giờ sang ISO 8601
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
        wprintf(L"Không thể khởi tạo Task Scheduler. Hãy chạy với quyền Administrator.\n");
        return 1;
    }

    // ==================== /QUERY ====================
    if (HasFlag(argc, argv, L"/QUERY") || HasFlag(argc, argv, L"/query")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER");
        if (!folder) folder = L"\\";

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
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER");
        if (!folder) folder = L"\\";

        if (!tn) { wprintf(L"Thiếu /TN\n"); return 1; }
        scheduler.DeleteTask(tn, folder);
        return 0;
    }

    // ==================== /RUN ====================
    if (HasFlag(argc, argv, L"/RUN") || HasFlag(argc, argv, L"/run")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER");
        if (!folder) folder = L"\\";

        if (!tn) { wprintf(L"Thiếu /TN\n"); return 1; }
        scheduler.RunTask(tn, folder);
        return 0;
    }

    // ==================== /END ====================
    if (HasFlag(argc, argv, L"/END") || HasFlag(argc, argv, L"/end")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER");
        if (!folder) folder = L"\\";

        if (!tn) { wprintf(L"Thiếu /TN\n"); return 1; }
        scheduler.StopTask(tn, folder);
        return 0;
    }

    // ==================== /ENABLE ====================
    if (HasFlag(argc, argv, L"/ENABLE") || HasFlag(argc, argv, L"/enable")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER");
        if (!folder) folder = L"\\";
        if (!tn) { wprintf(L"Thiếu /TN\n"); return 1; }
        scheduler.EnableTask(tn, TRUE, folder);
        return 0;
    }

    // ==================== /DISABLE ====================
    if (HasFlag(argc, argv, L"/DISABLE") || HasFlag(argc, argv, L"/disable")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER");
        if (!folder) folder = L"\\";
        if (!tn) { wprintf(L"Thiếu /TN\n"); return 1; }
        scheduler.EnableTask(tn, FALSE, folder);
        return 0;
    }

    // ==================== /EXPORT ====================
    if (HasFlag(argc, argv, L"/EXPORT") || HasFlag(argc, argv, L"/export")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* xml = GetArg(argc, argv, L"/XML");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER");
        if (!folder) folder = L"\\";
        if (!tn || !xml) { wprintf(L"Thiếu /TN hoặc /XML\n"); return 1; }
        scheduler.ExportTaskXML(tn, xml, folder);
        return 0;
    }

    // ==================== /IMPORT ====================
    if (HasFlag(argc, argv, L"/IMPORT") || HasFlag(argc, argv, L"/import")) {
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        const WCHAR* xml = GetArg(argc, argv, L"/XML");
        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER");
        if (!folder) folder = L"\\";
        if (!tn || !xml) { wprintf(L"Thiếu /TN hoặc /XML\n"); return 1; }
        scheduler.ImportTaskXML(tn, xml, folder);
        return 0;
    }

    // ==================== /CREATE ====================
    if (HasFlag(argc, argv, L"/CREATE") || HasFlag(argc, argv, L"/create")) {
        TaskConfig cfg = {};

        // Giá trị mặc định
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

        // Đọc tham số
        const WCHAR* tn = GetArg(argc, argv, L"/TN");
        if (!tn) { wprintf(L"Lỗi: Thiếu /TN (tên task)\n"); return 1; }
        wcscpy_s(cfg.taskName, tn);
        wcscpy_s(cfg.taskPath, tn);

        const WCHAR* tr = GetArg(argc, argv, L"/TR");
        if (!tr) { wprintf(L"Lỗi: Thiếu /TR (chương trình cần chạy)\n"); return 1; }
        wcscpy_s(cfg.programPath, tr);

        const WCHAR* sc = GetArg(argc, argv, L"/SC");
        if (sc) {
            if (_wcsicmp(sc, L"ONCE") == 0)    cfg.triggerType = 0;
            else if (_wcsicmp(sc, L"DAILY") == 0)  cfg.triggerType = 1;
            else if (_wcsicmp(sc, L"WEEKLY") == 0) cfg.triggerType = 2;
            else if (_wcsicmp(sc, L"MONTHLY") == 0) cfg.triggerType = 3;
            else if (_wcsicmp(sc, L"ONLOGON") == 0) cfg.triggerType = 4;
            else if (_wcsicmp(sc, L"ONSTART") == 0 || _wcsicmp(sc, L"ONSTARTUP") == 0) cfg.triggerType = 5;
            else if (_wcsicmp(sc, L"ONIDLE") == 0) cfg.triggerType = 6;
        }

        const WCHAR* st_time = GetArg(argc, argv, L"/ST");
        const WCHAR* sd = GetArg(argc, argv, L"/SD");
        const WCHAR* ed = GetArg(argc, argv, L"/ED");

        BuildStartTime(sd, st_time, cfg.startTime, 32);
        if (ed) {
            BuildStartTime(ed, L"23:59", cfg.endTime, 32);
        }

        const WCHAR* mo = GetArg(argc, argv, L"/MO");
        if (mo) {
            cfg.intervalDays = _wtoi(mo);
            cfg.weeksInterval = _wtoi(mo);
        }

        // Ngày trong tuần
        const WCHAR* d_arg = GetArg(argc, argv, L"/D");
        if (d_arg) {
            cfg.daysOfWeek = 0;
            if (wcsstr(d_arg, L"SUN")) cfg.daysOfWeek |= 0x01;
            if (wcsstr(d_arg, L"MON")) cfg.daysOfWeek |= 0x02;
            if (wcsstr(d_arg, L"TUE")) cfg.daysOfWeek |= 0x04;
            if (wcsstr(d_arg, L"WED")) cfg.daysOfWeek |= 0x08;
            if (wcsstr(d_arg, L"THU")) cfg.daysOfWeek |= 0x10;
            if (wcsstr(d_arg, L"FRI")) cfg.daysOfWeek |= 0x20;
            if (wcsstr(d_arg, L"SAT")) cfg.daysOfWeek |= 0x40;
        }
        if (cfg.daysOfWeek == 0 && cfg.triggerType == 2)
            cfg.daysOfWeek = 0x02; // Mặc định: Thứ Hai

        const WCHAR* ru = GetArg(argc, argv, L"/RU");
        if (ru) wcscpy_s(cfg.runAsUser, ru);

        const WCHAR* rp = GetArg(argc, argv, L"/RP");
        if (rp) wcscpy_s(cfg.password, rp);

        const WCHAR* rl = GetArg(argc, argv, L"/RL");
        if (rl) {
            if (_wcsicmp(rl, L"HIGHEST") == 0) cfg.runLevel = 1;
            else cfg.runLevel = 0;
        }

        const WCHAR* args = GetArg(argc, argv, L"/A");
        if (args) wcscpy_s(cfg.arguments, args);

        const WCHAR* wdir = GetArg(argc, argv, L"/WD");
        if (wdir) wcscpy_s(cfg.workingDir, wdir);

        const WCHAR* folder = GetArg(argc, argv, L"/FOLDER");
        if (folder) {
            WCHAR fullPath[600];
            swprintf_s(fullPath, L"%s\\%s", folder, tn);
            wcscpy_s(cfg.taskPath, fullPath);
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

        if (HasFlag(argc, argv, L"/HIDELEVEL")) cfg.hidden = TRUE;

        // Tạo task
        hr = scheduler.CreateTask(&cfg);
        return SUCCEEDED(hr) ? 0 : 1;
    }

    // Không nhận dạng được lệnh
    PrintHelp();
    return 0;
}