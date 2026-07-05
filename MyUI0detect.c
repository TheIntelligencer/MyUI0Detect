#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <windows.h>
#include <wtsapi32.h>
#include <commdlg.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "comdlg32.lib")

#define SERVICE_NAME        "UI0Detect"
#define SERVICE_DISPLAY     "Interactive Services Detection"
#define LOG_FILE_NAME       "ui0test.log"

#define UI0_BG_CLASS        "$$$UI0Background"
#define UI0_BG_TITLE        "Shell0 Window"

#define IDC_RETURN_BUTTON   1001
#define IDC_RUN_BUTTON      1002
#define IDC_MAIN_ACTION     2001
#define IDC_MAIN_HELP       2002
#define IDC_MAIN_STATUS     2003
#define IDC_SWITCH_LAYOUT   1003
#define IDC_MINIMIZED_BASE   40000
#define IDC_MINIMIZED_MAX    40127
#define MAX_MINIMIZED_ITEMS  128
#define MAX_RUN_PROCESSES    64
#define WM_UI0_EXIT_HELPER   (WM_APP + 100)
#define S0UI_LAUNCH_COOKIE    "UI0DETECT_SERVICE_LAUNCHED_S0UI"

#define HELPER_BG_CLASS     "UI0HelperDesktopBackground"
#define S0_DIALOG_CLASS     "UI0ReturnDialog"
#define MAIN_WINDOW_CLASS   "UI0ControlMainWindow"

#define TIMER_CURSOR_PRIME  3001
#define TIMER_LAYOUT_REFRESH 3002
#define CURSOR_PRIME_LIMIT  12

#ifndef SE_TCB_NAME
#define SE_TCB_NAME TEXT("SeTcbPrivilege")
#endif

#ifndef SE_ASSIGNPRIMARYTOKEN_NAME
#define SE_ASSIGNPRIMARYTOKEN_NAME TEXT("SeAssignPrimaryTokenPrivilege")
#endif

#ifndef SE_INCREASE_QUOTA_NAME
#define SE_INCREASE_QUOTA_NAME TEXT("SeIncreaseQuotaPrivilege")
#endif

typedef BOOLEAN (WINAPI *PFN_WinStationSwitchToServicesSession)(VOID);
typedef BOOLEAN (WINAPI *PFN_WinStationRevertFromServicesSession)(VOID);
typedef BOOL    (WINAPI *PFN_SetShellWindow)(HWND);
typedef BOOL    (WINAPI *PFN_SetTaskmanWindow)(HWND);

static SERVICE_STATUS_HANDLE g_ServiceStatusHandle = NULL;
static SERVICE_STATUS g_ServiceStatus;
static DWORD g_MainThreadId = 0;

static HWINSTA g_OldWindowStation = NULL;
static HWINSTA g_ServiceWindowStation = NULL;
static HDESK g_ServiceDesktop = NULL;

static HWND g_ServiceBackgroundWindow = NULL;
static HWND g_HelperBackgroundWindow = NULL;
static HWND g_S0DialogWindow = NULL;
static HWND g_MainWindow = NULL;
static HWND g_MainStatusLabel = NULL;
static HWND g_MainActionButton = NULL;
static HWND g_ReturnButton = NULL;
static HWND g_RunButton = NULL;
static HMENU g_MainMenu = NULL;
static HMENU g_MinimizedMenu = NULL;
static HWND g_MinimizedWindows[MAX_MINIMIZED_ITEMS];
static HANDLE g_RunProcesses[MAX_RUN_PROCESSES];
static DWORD g_RunProcessIds[MAX_RUN_PROCESSES];
static DWORD g_CursorPrimeCount = 0;
static BOOL g_CursorSysCursorsResetDone = FALSE;

static HANDLE g_S0UiProcess = NULL;
static DWORD g_S0UiPid = 0;
static HBRUSH g_HelperBackgroundBrush = NULL;
static UINT g_ShellHookMessage = 0;
static DWORD g_BackgroundRefreshCount = 0;
static char g_CurrentKeyboardLayoutText[128] = "";
static HKL g_CurrentKeyboardLayout = NULL;
static HHOOK g_KeyboardHook = NULL;
static BOOL g_AltShiftConsumed = FALSE;

static void LogMessage(const char *Format, ...)
{
    char buffer[2048];
    char path[MAX_PATH];
    char winDir[MAX_PATH];
    DWORD written;
    HANDLE hFile;
    va_list ap;

    va_start(ap, Format);
    wvsprintfA(buffer, Format, ap);
    va_end(ap);

    lstrcatA(buffer, "\r\n");
    printf("%s", buffer);
    OutputDebugStringA(buffer);

    winDir[0] = 0;
    GetWindowsDirectoryA(winDir, MAX_PATH);
    wsprintfA(path, "%s\\Temp\\%s", winDir, LOG_FILE_NAME);

    hFile = CreateFileA(path,
                        FILE_APPEND_DATA,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        WriteFile(hFile, buffer, lstrlenA(buffer), &written, NULL);
        CloseHandle(hFile);
    }
}

static BOOL EnablePrivilegeA2(const char *PrivilegeName)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    DWORD gle;

    hToken = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        LogMessage("OpenProcessToken failed: GLE=%lu", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValueA(NULL, PrivilegeName, &luid))
    {
        LogMessage("LookupPrivilegeValueA(%s) failed: GLE=%lu", PrivilegeName, GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(0);
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
    {
        LogMessage("AdjustTokenPrivileges(%s) failed: GLE=%lu", PrivilegeName, GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    gle = GetLastError();
    if (gle == ERROR_NOT_ALL_ASSIGNED)
    {
        LogMessage("Privilege %s is not present in this token", PrivilegeName);
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

static void EnableServicePrivileges(void)
{
    EnablePrivilegeA2(SE_TCB_NAME);
    EnablePrivilegeA2(SE_ASSIGNPRIMARYTOKEN_NAME);
    EnablePrivilegeA2(SE_INCREASE_QUOTA_NAME);
}

static FARPROC LoadWinstaProc(const char *ProcName)
{
    HMODULE hMod;
    FARPROC proc;

    hMod = LoadLibraryA("winsta.dll");
    if (!hMod)
    {
        LogMessage("LoadLibraryA(winsta.dll) failed: GLE=%lu", GetLastError());
        return NULL;
    }

    proc = GetProcAddress(hMod, ProcName);
    if (!proc)
    {
        LogMessage("GetProcAddress(%s) failed: GLE=%lu", ProcName, GetLastError());
        return NULL;
    }

    return proc;
}

static BOOL DoSwitchToServicesSessionWithError(DWORD *LastErrorOut)
{
    PFN_WinStationSwitchToServicesSession pfn;
    BOOLEAN result;
    DWORD gle;

    EnablePrivilegeA2(SE_TCB_NAME);

    pfn = (PFN_WinStationSwitchToServicesSession)
        LoadWinstaProc("WinStationSwitchToServicesSession");

    if (!pfn)
    {
        gle = GetLastError();
        if (LastErrorOut) *LastErrorOut = gle;
        return FALSE;
    }

    SetLastError(0);
    result = pfn();
    gle = GetLastError();

    LogMessage("WinStationSwitchToServicesSession returned %u, GLE=%lu", (UINT)result, gle);

    if (!result)
    {
        if (LastErrorOut) *LastErrorOut = gle;
        return FALSE;
    }

    if (LastErrorOut) *LastErrorOut = 0;
    return TRUE;
}

static BOOL DoRevertFromServicesSessionWithError(DWORD *LastErrorOut)
{
    PFN_WinStationRevertFromServicesSession pfn;
    BOOLEAN result;
    DWORD gle;

    EnablePrivilegeA2(SE_TCB_NAME);

    pfn = (PFN_WinStationRevertFromServicesSession)
        LoadWinstaProc("WinStationRevertFromServicesSession");

    if (!pfn)
    {
        gle = GetLastError();
        if (LastErrorOut) *LastErrorOut = gle;
        return FALSE;
    }

    SetLastError(0);
    result = pfn();
    gle = GetLastError();

    LogMessage("WinStationRevertFromServicesSession returned %u, GLE=%lu", (UINT)result, gle);

    if (!result)
    {
        if (LastErrorOut) *LastErrorOut = gle;
        return FALSE;
    }

    if (LastErrorOut) *LastErrorOut = 0;
    return TRUE;
}

static void ShowApiFailureMessage(HWND Owner, const char *Operation, DWORD ErrorCode)
{
    char msg[512];

    wsprintfA(msg, "%s failed.\r\n\r\nWin32 error code: %lu", Operation, ErrorCode);
    MessageBoxA(Owner, msg, "UI0Detect test", MB_ICONEXCLAMATION | MB_OK);
}

static BOOL AttachToSession0InteractiveDesktop(void)
{
    HWINSTA hwinsta;
    HDESK hdesk;

    g_OldWindowStation = GetProcessWindowStation();

    hwinsta = OpenWindowStationA("WinSta0",
                                 FALSE,
                                 WINSTA_ENUMDESKTOPS |
                                 WINSTA_READATTRIBUTES |
                                 WINSTA_ACCESSCLIPBOARD |
                                 WINSTA_CREATEDESKTOP |
                                 WINSTA_WRITEATTRIBUTES |
                                 WINSTA_ACCESSGLOBALATOMS |
                                 WINSTA_EXITWINDOWS |
                                 READ_CONTROL);

    if (!hwinsta)
    {
        LogMessage("OpenWindowStationA(WinSta0) failed: GLE=%lu", GetLastError());
        return FALSE;
    }

    if (!SetProcessWindowStation(hwinsta))
    {
        LogMessage("SetProcessWindowStation(WinSta0) failed: GLE=%lu", GetLastError());
        CloseWindowStation(hwinsta);
        return FALSE;
    }

    hdesk = OpenDesktopA("Default",
                         0,
                         FALSE,
                         DESKTOP_READOBJECTS |
                         DESKTOP_CREATEWINDOW |
                         DESKTOP_CREATEMENU |
                         DESKTOP_HOOKCONTROL |
                         DESKTOP_ENUMERATE |
                         DESKTOP_WRITEOBJECTS |
                         DESKTOP_SWITCHDESKTOP |
                         READ_CONTROL);

    if (!hdesk)
    {
        LogMessage("OpenDesktopA(Default) failed: GLE=%lu", GetLastError());
        SetProcessWindowStation(g_OldWindowStation);
        CloseWindowStation(hwinsta);
        return FALSE;
    }

    if (!SetThreadDesktop(hdesk))
    {
        LogMessage("SetThreadDesktop(Default) failed: GLE=%lu", GetLastError());
        CloseDesktop(hdesk);
        SetProcessWindowStation(g_OldWindowStation);
        CloseWindowStation(hwinsta);
        return FALSE;
    }

    g_ServiceWindowStation = hwinsta;
    g_ServiceDesktop = hdesk;
    return TRUE;
}

static void GetVirtualScreen(int *X, int *Y, int *CX, int *CY)
{
    int x;
    int y;
    int cx;
    int cy;

    x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    cx = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    cy = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    if (cx <= 0) cx = GetSystemMetrics(SM_CXSCREEN);
    if (cy <= 0) cy = GetSystemMetrics(SM_CYSCREEN);

    *X = x;
    *Y = y;
    *CX = cx;
    *CY = cy;
}


static void NormalizeShowCursorCounter(void)
{
    int count;
    int i;

    count = 0;

    for (i = 0; i < 32; i++)
    {
        count = ShowCursor(TRUE);
        if (count >= 0)
            break;
    }

    for (i = 0; i < 32 && count > 0; i++)
        count = ShowCursor(FALSE);
}

static void PrimeSession0Cursor(const char *Tag, BOOL NudgePosition)
{
    CURSORINFO ci;
    POINT pt;
    int x;
    int y;
    int cx;
    int cy;
    int nx;
    HCURSOR hcur;
    BOOL isTimer;

    isTimer = (lstrcmpA(Tag, "HelperBackground cursor timer") == 0);

    hcur = LoadCursor(NULL, IDC_ARROW);
    if (hcur)
        SetCursor(hcur);

    NormalizeShowCursorCounter();

    ZeroMemory(&ci, sizeof(ci));
    ci.cbSize = sizeof(ci);

    if (GetCursorInfo(&ci))
    {
        if (!isTimer)
            LogMessage("%s: cursor flags=0x%lx hCursor=0x%p", Tag, ci.flags, ci.hCursor);
    }
    else
    {
        if (!isTimer)
            LogMessage("%s: GetCursorInfo failed, GLE=%lu", Tag, GetLastError());
    }

    if (!isTimer)
    {
        ClipCursor(NULL);
        ReleaseCapture();
        if (!g_CursorSysCursorsResetDone)
        {
            SystemParametersInfoA(SPI_SETCURSORS, 0, NULL, 0);
            g_CursorSysCursorsResetDone = TRUE;
        }
    }

    if (!isTimer && NudgePosition && GetCursorPos(&pt))
    {
        GetVirtualScreen(&x, &y, &cx, &cy);

        nx = pt.x;
        if (pt.x + 1 < x + cx)
            nx = pt.x + 1;
        else if (pt.x - 1 >= x)
            nx = pt.x - 1;

        if (nx != pt.x)
        {
            SetCursorPos(nx, pt.y);
            SetCursorPos(pt.x, pt.y);
        }
    }

    if (hcur)
        SetCursor(hcur);
}

static HWND FindServiceBackgroundWindow(void)
{
    HWND hwnd;

    if (g_ServiceBackgroundWindow && IsWindow(g_ServiceBackgroundWindow))
        return g_ServiceBackgroundWindow;

    hwnd = FindWindowA(UI0_BG_CLASS, UI0_BG_TITLE);
    return hwnd;
}

static void SendServiceBackgroundToBottom(void)
{
    HWND hwnd;

    hwnd = FindServiceBackgroundWindow();
    if (!hwnd || !IsWindow(hwnd))
        return;

    SetWindowPos(hwnd,
                 HWND_BOTTOM,
                 0,
                 0,
                 0,
                 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
}

static void KeepServiceBackgroundAsBottomShell(void)
{
    int x;
    int y;
    int cx;
    int cy;

    if (!g_ServiceBackgroundWindow || !IsWindow(g_ServiceBackgroundWindow))
        return;

    GetVirtualScreen(&x, &y, &cx, &cy);

    SetWindowPos(g_ServiceBackgroundWindow,
                 HWND_BOTTOM,
                 x,
                 y,
                 cx,
                 cy,
                 SWP_SHOWWINDOW | SWP_NOACTIVATE);

    InvalidateRect(g_ServiceBackgroundWindow, NULL, TRUE);
    UpdateWindow(g_ServiceBackgroundWindow);
}

static BOOL RegisterShellLikeWindow(HWND hwnd)
{
    HMODULE hUser32;
    PFN_SetTaskmanWindow pSetTaskmanWindow;
    PFN_SetShellWindow pSetShellWindow;
    BOOL ok;

    hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32)
        hUser32 = LoadLibraryA("user32.dll");

    if (!hUser32)
    {
        LogMessage("LoadLibrary(user32.dll) failed: GLE=%lu", GetLastError());
        return FALSE;
    }

    pSetTaskmanWindow = (PFN_SetTaskmanWindow)GetProcAddress(hUser32, "SetTaskmanWindow");
    pSetShellWindow = (PFN_SetShellWindow)GetProcAddress(hUser32, "SetShellWindow");

    if (pSetTaskmanWindow)
    {
        SetLastError(0);
        ok = pSetTaskmanWindow(hwnd);
        LogMessage("SetTaskmanWindow returned %u, GLE=%lu", ok, GetLastError());
    }

    if (pSetShellWindow)
    {
        SetLastError(0);
        ok = pSetShellWindow(hwnd);
        LogMessage("SetShellWindow returned %u, GLE=%lu", ok, GetLastError());
        if (!ok)
            return FALSE;
    }
    else
    {
        LogMessage("SetShellWindow is not exported");
        return FALSE;
    }

    return TRUE;
}

static BOOL SpawnSession0UiHelper(void);

static LRESULT CALLBACK ServiceBackgroundWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_CREATE:
            g_ShellHookMessage = RegisterWindowMessageA("SHELLHOOK");
            if (g_ShellHookMessage)
            {
                SetWindowLongPtr(hwnd, 0, (LONG_PTR)g_ShellHookMessage);
                RegisterShellHookWindow(hwnd);
            }

            WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
            return 0;

        case WM_MOUSEACTIVATE:
            return MA_NOACTIVATE;

        case WM_SETCURSOR:
            SetCursor(LoadCursor(NULL, IDC_ARROW));
            return TRUE;

        case WM_WINDOWPOSCHANGING:
            {
                WINDOWPOS *wp;
                wp = (WINDOWPOS *)lParam;
                if (wp && !(wp->flags & SWP_NOZORDER))
                    wp->hwndInsertAfter = HWND_BOTTOM;
            }
            return 0;

        case WM_SETFOCUS:
            KeepServiceBackgroundAsBottomShell();
            return 0;

        case WM_WTSSESSION_CHANGE:
            if (wParam == WTS_CONSOLE_CONNECT ||
                wParam == WTS_SESSION_LOGON ||
                wParam == WTS_SESSION_UNLOCK)
            {
                SpawnSession0UiHelper();
                KeepServiceBackgroundAsBottomShell();
            }
            return 0;

        case WM_CLOSE:
            return 0;

        case WM_DESTROY:
            if (hwnd == g_ServiceBackgroundWindow)
                g_ServiceBackgroundWindow = NULL;
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static BOOL CreateServiceBackgroundWindow(void)
{
    WNDCLASSA wc;
    HWND hwnd;
    int x;
    int y;
    int cx;
    int cy;

    if (g_ServiceBackgroundWindow && IsWindow(g_ServiceBackgroundWindow))
        return TRUE;

    ZeroMemory(&wc, sizeof(wc));
    wc.style = CS_NOCLOSE;
    wc.lpfnWndProc = ServiceBackgroundWndProc;
    wc.cbWndExtra = sizeof(LONG_PTR);
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_DESKTOP + 1);
    wc.lpszClassName = UI0_BG_CLASS;

    if (!RegisterClassA(&wc))
    {
        DWORD gle;
        gle = GetLastError();
        if (gle != ERROR_CLASS_ALREADY_EXISTS)
        {
            LogMessage("RegisterClassA(%s) failed: GLE=%lu", UI0_BG_CLASS, gle);
            return FALSE;
        }
    }

    GetVirtualScreen(&x, &y, &cx, &cy);

    hwnd = CreateWindowExA(WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
                           UI0_BG_CLASS,
                           UI0_BG_TITLE,
                           WS_POPUP | WS_CLIPCHILDREN,
                           x,
                           y,
                           cx,
                           cy,
                           NULL,
                           NULL,
                           GetModuleHandleA(NULL),
                           NULL);

    if (!hwnd)
    {
        LogMessage("CreateWindowExA($$$UI0Background) failed: GLE=%lu", GetLastError());
        return FALSE;
    }

    g_ServiceBackgroundWindow = hwnd;
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    RegisterShellLikeWindow(hwnd);
    KeepServiceBackgroundAsBottomShell();
    return TRUE;
}


static void UpdateKeyboardLayoutText(void)
{
    HWND fg;
    DWORD tid;
    HKL hkl;
    LANGID langid;
    char langName[128];
    char klid[KL_NAMELENGTH];

    fg = GetForegroundWindow();
    tid = 0;

    if (fg)
        tid = GetWindowThreadProcessId(fg, NULL);

    hkl = GetKeyboardLayout(tid);
    if (!hkl)
        hkl = GetKeyboardLayout(0);

    klid[0] = 0;
    GetKeyboardLayoutNameA(klid);

    langName[0] = 0;
    langid = LOWORD((DWORD_PTR)hkl);

#if defined(LOCALE_SENGLANGUAGE)
    GetLocaleInfoA(MAKELCID(langid, SORT_DEFAULT), LOCALE_SENGLANGUAGE, langName, sizeof(langName));
#endif

    if (langName[0])
        wsprintfA(g_CurrentKeyboardLayoutText, "Keyboard layout: %s  HKL=0x%p", langName, hkl);
    else
        wsprintfA(g_CurrentKeyboardLayoutText, "Keyboard layout: HKL=0x%p KLID=%s", hkl, klid[0] ? klid : "unknown");

    g_CurrentKeyboardLayout = hkl;
}

static void InvalidateHelperLayoutText(void)
{
    if (g_HelperBackgroundWindow && IsWindow(g_HelperBackgroundWindow))
        InvalidateRect(g_HelperBackgroundWindow, NULL, TRUE);
}

static BOOL SwitchToNextKeyboardLayout(void)
{
    HKL layouts[64];
    int count;
    int i;
    int index;
    HKL current;
    HKL next;
    HWND fg;
    DWORD tid;

    count = GetKeyboardLayoutList(64, layouts);
    if (count <= 0)
        return FALSE;

    fg = GetForegroundWindow();
    tid = 0;
    if (fg)
        tid = GetWindowThreadProcessId(fg, NULL);

    current = GetKeyboardLayout(tid);
    if (!current)
        current = GetKeyboardLayout(0);

    index = 0;
    for (i = 0; i < count; i++)
    {
        if (layouts[i] == current)
        {
            index = i;
            break;
        }
    }

    next = layouts[(index + 1) % count];

    if (fg && IsWindow(fg))
        PostMessageA(fg, WM_INPUTLANGCHANGEREQUEST, 0, (LPARAM)next);

    ActivateKeyboardLayout(next, KLF_SETFORPROCESS | KLF_REORDER);
    UpdateKeyboardLayoutText();
    InvalidateHelperLayoutText();
    LogMessage("Keyboard layout switch requested: current=0x%p next=0x%p", current, next);
    return TRUE;
}

static LRESULT CALLBACK LowLevelKeyboardProc(int code, WPARAM wParam, LPARAM lParam)
{
    KBDLLHOOKSTRUCT *kbd;
    BOOL altDown;
    BOOL shiftDown;

    if (code == HC_ACTION)
    {
        kbd = (KBDLLHOOKSTRUCT *)lParam;

        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)
        {
            altDown = ((GetAsyncKeyState(VK_MENU) & 0x8000) != 0);
            shiftDown = ((GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0);

            if ((kbd->vkCode == VK_MENU || kbd->vkCode == VK_LMENU || kbd->vkCode == VK_RMENU ||
                 kbd->vkCode == VK_SHIFT || kbd->vkCode == VK_LSHIFT || kbd->vkCode == VK_RSHIFT) &&
                altDown && shiftDown && !g_AltShiftConsumed)
            {
                g_AltShiftConsumed = TRUE;
                SwitchToNextKeyboardLayout();
                return 1;
            }
        }
        else if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP)
        {
            if (kbd->vkCode == VK_MENU || kbd->vkCode == VK_LMENU || kbd->vkCode == VK_RMENU ||
                kbd->vkCode == VK_SHIFT || kbd->vkCode == VK_LSHIFT || kbd->vkCode == VK_RSHIFT)
                g_AltShiftConsumed = FALSE;
        }
    }

    return CallNextHookEx(g_KeyboardHook, code, wParam, lParam);
}

static void InstallKeyboardLayoutHook(void)
{
    if (!g_KeyboardHook)
    {
        g_KeyboardHook = SetWindowsHookExA(WH_KEYBOARD_LL,
                                           LowLevelKeyboardProc,
                                           GetModuleHandleA(NULL),
                                           0);
        if (!g_KeyboardHook)
            LogMessage("SetWindowsHookEx(WH_KEYBOARD_LL) failed: GLE=%lu", GetLastError());
    }
}

static void UninstallKeyboardLayoutHook(void)
{
    if (g_KeyboardHook)
    {
        UnhookWindowsHookEx(g_KeyboardHook);
        g_KeyboardHook = NULL;
    }
}

static LRESULT CALLBACK HelperBackgroundWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    WINDOWPOS *wp;
    RECT rc;
    HDC hdc;
    PAINTSTRUCT ps;

    switch (msg)
    {
        case WM_CREATE:
            g_BackgroundRefreshCount = 0;
            g_CursorPrimeCount = 0;
            UpdateKeyboardLayoutText();
            PrimeSession0Cursor("HelperBackground WM_CREATE", TRUE);
            SetTimer(hwnd, TIMER_CURSOR_PRIME, 500, NULL);
            SetTimer(hwnd, TIMER_LAYOUT_REFRESH, 500, NULL);
            return 0;

        case WM_MOUSEACTIVATE:
            return MA_NOACTIVATE;

        case WM_NCHITTEST:
            return HTCLIENT;

        case WM_SETCURSOR:
            SetCursor(LoadCursor(NULL, IDC_ARROW));
            return TRUE;

        case WM_WINDOWPOSCHANGING:
            wp = (WINDOWPOS *)lParam;
            if (wp && !(wp->flags & SWP_NOZORDER))
                wp->hwndInsertAfter = HWND_BOTTOM;
            return 0;

        case WM_SETFOCUS:
            SetWindowPos(hwnd, HWND_BOTTOM, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            return 0;

        case WM_TIMER:
            if (wParam == TIMER_CURSOR_PRIME)
            {
                g_CursorPrimeCount++;
                PrimeSession0Cursor("HelperBackground cursor timer", FALSE);

                if (g_CursorPrimeCount >= CURSOR_PRIME_LIMIT)
                    KillTimer(hwnd, TIMER_CURSOR_PRIME);

                return 0;
            }

            if (wParam == TIMER_LAYOUT_REFRESH)
            {
                HKL oldLayout;
                oldLayout = g_CurrentKeyboardLayout;
                UpdateKeyboardLayoutText();
                if (oldLayout != g_CurrentKeyboardLayout)
                    InvalidateRect(hwnd, NULL, TRUE);
                return 0;
            }
            break;

        case WM_INPUTLANGCHANGE:
            UpdateKeyboardLayoutText();
            InvalidateRect(hwnd, NULL, TRUE);
            return 0;

        case WM_DISPLAYCHANGE:
        case WM_SETTINGCHANGE:
            if (hwnd == g_HelperBackgroundWindow)
            {
                int x;
                int y;
                int cx;
                int cy;
                GetVirtualScreen(&x, &y, &cx, &cy);
                SetWindowPos(hwnd, HWND_BOTTOM, x, y, cx, cy, SWP_SHOWWINDOW | SWP_NOACTIVATE);
                SendServiceBackgroundToBottom();
                /* Do not run the heavy cursor reset path from WM_SETTINGCHANGE/WM_DISPLAYCHANGE;
                   it can break mouse capture and drag operations in Session 0. */
                InvalidateRect(hwnd, NULL, TRUE);
                UpdateWindow(hwnd);
            }
            return 0;

        case WM_ERASEBKGND:
            GetClientRect(hwnd, &rc);
            FillRect((HDC)wParam, &rc, g_HelperBackgroundBrush);
            return 1;

        case WM_PAINT:
            hdc = BeginPaint(hwnd, &ps);
            FillRect(hdc, &ps.rcPaint, g_HelperBackgroundBrush);
            SetTextColor(hdc, RGB(255, 0, 0));
            SetBkMode(hdc, TRANSPARENT);
            TextOutA(hdc, 8, 8, g_CurrentKeyboardLayoutText, lstrlenA(g_CurrentKeyboardLayoutText));
            EndPaint(hwnd, &ps);
            return 0;

        case WM_CLOSE:
            return 0;

        case WM_DESTROY:
            KillTimer(hwnd, TIMER_CURSOR_PRIME);
            KillTimer(hwnd, TIMER_LAYOUT_REFRESH);
            if (hwnd == g_HelperBackgroundWindow)
                g_HelperBackgroundWindow = NULL;
            return 0;
    }

    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static void ResizeHelperBackground(void)
{
    int x;
    int y;
    int cx;
    int cy;

    if (!g_HelperBackgroundWindow || !IsWindow(g_HelperBackgroundWindow))
        return;

    GetVirtualScreen(&x, &y, &cx, &cy);
    SetWindowPos(g_HelperBackgroundWindow,
                 HWND_BOTTOM,
                 x,
                 y,
                 cx,
                 cy,
                 SWP_SHOWWINDOW | SWP_NOACTIVATE);
    SendServiceBackgroundToBottom();
    InvalidateRect(g_HelperBackgroundWindow, NULL, TRUE);
    UpdateWindow(g_HelperBackgroundWindow);
}

static BOOL CreateHelperBackgroundWindow(void)
{
    WNDCLASSA wc;
    HWND hwnd;
    int x;
    int y;
    int cx;
    int cy;

    if (g_HelperBackgroundWindow && IsWindow(g_HelperBackgroundWindow))
        return TRUE;

    if (!g_HelperBackgroundBrush)
        g_HelperBackgroundBrush = CreateSolidBrush(RGB(192, 192, 192));

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = HelperBackgroundWndProc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = g_HelperBackgroundBrush;
    wc.lpszClassName = HELPER_BG_CLASS;

    if (!RegisterClassA(&wc))
    {
        DWORD gle;
        gle = GetLastError();
        if (gle != ERROR_CLASS_ALREADY_EXISTS)
        {
            LogMessage("RegisterClassA(%s) failed: GLE=%lu", HELPER_BG_CLASS, gle);
            return FALSE;
        }
    }

    GetVirtualScreen(&x, &y, &cx, &cy);

    hwnd = CreateWindowExA(WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
                           HELPER_BG_CLASS,
                           "Session 0 Background",
                           WS_POPUP | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
                           x,
                           y,
                           cx,
                           cy,
                           NULL,
                           NULL,
                           GetModuleHandleA(NULL),
                           NULL);

    if (!hwnd)
    {
        LogMessage("CreateWindowExA(helper background) failed: GLE=%lu", GetLastError());
        return FALSE;
    }

    g_HelperBackgroundWindow = hwnd;
    ResizeHelperBackground();
    return TRUE;
}


static void PruneRunProcesses(void)
{
    DWORD exitCode;
    int i;

    for (i = 0; i < MAX_RUN_PROCESSES; i++)
    {
        if (!g_RunProcesses[i])
            continue;

        exitCode = 0;
        if (!GetExitCodeProcess(g_RunProcesses[i], &exitCode) || exitCode != STILL_ACTIVE)
        {
            CloseHandle(g_RunProcesses[i]);
            g_RunProcesses[i] = NULL;
            g_RunProcessIds[i] = 0;
        }
    }
}

static void AddRunProcess(HANDLE hProcess, DWORD ProcessId)
{
    int i;

    PruneRunProcesses();

    for (i = 0; i < MAX_RUN_PROCESSES; i++)
    {
        if (!g_RunProcesses[i])
        {
            g_RunProcesses[i] = hProcess;
            g_RunProcessIds[i] = ProcessId;
            LogMessage("Tracking Run process PID=%lu", ProcessId);
            return;
        }
    }

    LogMessage("Run process table is full; PID=%lu will not be tracked", ProcessId);
    CloseHandle(hProcess);
}

static void TerminateRunProcesses(void)
{
    DWORD exitCode;
    int i;

    for (i = 0; i < MAX_RUN_PROCESSES; i++)
    {
        if (!g_RunProcesses[i])
            continue;

        exitCode = 0;
        if (GetExitCodeProcess(g_RunProcesses[i], &exitCode) && exitCode == STILL_ACTIVE)
        {
            LogMessage("Terminating Run process PID=%lu", g_RunProcessIds[i]);
            TerminateProcess(g_RunProcesses[i], 0);
            WaitForSingleObject(g_RunProcesses[i], 2000);
        }

        CloseHandle(g_RunProcesses[i]);
        g_RunProcesses[i] = NULL;
        g_RunProcessIds[i] = 0;
    }
}

static BOOL IsOwnSession0UiWindow(HWND hwnd)
{
    char cls[128];

    cls[0] = 0;
    GetClassNameA(hwnd, cls, sizeof(cls));

    if (lstrcmpiA(cls, UI0_BG_CLASS) == 0)
        return TRUE;

    if (lstrcmpiA(cls, HELPER_BG_CLASS) == 0)
        return TRUE;

    if (lstrcmpiA(cls, S0_DIALOG_CLASS) == 0)
        return TRUE;

    return FALSE;
}

typedef struct _MINIMIZED_ENUM_CONTEXT
{
    int Count;
} MINIMIZED_ENUM_CONTEXT;

static BOOL CALLBACK BuildMinimizedMenuEnumProc(HWND hwnd, LPARAM lParam)
{
    MINIMIZED_ENUM_CONTEXT *ctx;
    char title[256];
    char cls[128];
    char itemText[320];
    UINT id;

    ctx = (MINIMIZED_ENUM_CONTEXT *)lParam;

    if (!IsWindowVisible(hwnd))
        return TRUE;

    if (!IsIconic(hwnd))
        return TRUE;

    if (IsOwnSession0UiWindow(hwnd))
        return TRUE;

    if (ctx->Count >= MAX_MINIMIZED_ITEMS)
        return FALSE;

    title[0] = 0;
    cls[0] = 0;
    GetWindowTextA(hwnd, title, sizeof(title));
    GetClassNameA(hwnd, cls, sizeof(cls));

    if (title[0] == 0)
        wsprintfA(itemText, "[%s]", cls[0] ? cls : "window");
    else
        wsprintfA(itemText, "%s", title);

    id = (UINT)(IDC_MINIMIZED_BASE + ctx->Count);
    g_MinimizedWindows[ctx->Count] = hwnd;
    AppendMenuA(g_MinimizedMenu, MF_STRING, id, itemText);
    ctx->Count++;

    return TRUE;
}

static void RebuildMinimizedWindowsMenu(void)
{
    MINIMIZED_ENUM_CONTEXT ctx;
    int i;
    int count;

    if (!g_MinimizedMenu)
        return;

    count = GetMenuItemCount(g_MinimizedMenu);
    while (count > 0)
    {
        DeleteMenu(g_MinimizedMenu, 0, MF_BYPOSITION);
        count--;
    }

    for (i = 0; i < MAX_MINIMIZED_ITEMS; i++)
        g_MinimizedWindows[i] = NULL;

    ctx.Count = 0;
    EnumWindows(BuildMinimizedMenuEnumProc, (LPARAM)&ctx);

    if (ctx.Count == 0)
        AppendMenuA(g_MinimizedMenu, MF_STRING | MF_GRAYED, IDC_MINIMIZED_BASE, "No minimized windows available");

    if (g_S0DialogWindow && IsWindow(g_S0DialogWindow))
        DrawMenuBar(g_S0DialogWindow);
}

static BOOL RestoreMinimizedWindowFromMenu(UINT MenuId)
{
    UINT index;
    HWND hwnd;

    if (MenuId < IDC_MINIMIZED_BASE || MenuId > IDC_MINIMIZED_MAX)
        return FALSE;

    index = MenuId - IDC_MINIMIZED_BASE;
    if (index >= MAX_MINIMIZED_ITEMS)
        return FALSE;

    hwnd = g_MinimizedWindows[index];
    if (!hwnd || !IsWindow(hwnd))
        return TRUE;

    DeleteMenu(g_MinimizedMenu, MenuId, MF_BYCOMMAND);

    ShowWindowAsync(hwnd, SW_RESTORE);
    BringWindowToTop(hwnd);
    SetForegroundWindow(hwnd);

    if (GetMenuItemCount(g_MinimizedMenu) == 0)
        AppendMenuA(g_MinimizedMenu, MF_STRING | MF_GRAYED, IDC_MINIMIZED_BASE, "No minimized windows available");

    if (g_S0DialogWindow && IsWindow(g_S0DialogWindow))
        DrawMenuBar(g_S0DialogWindow);
    return TRUE;
}

static void CreateS0DialogMenu(HWND hwnd)
{
    g_MainMenu = CreateMenu();
    g_MinimizedMenu = CreatePopupMenu();

    if (!g_MainMenu || !g_MinimizedMenu)
    {
        LogMessage("Create menu failed: GLE=%lu", GetLastError());
        return;
    }

    AppendMenuA(g_MainMenu, MF_POPUP, (UINT_PTR)g_MinimizedMenu, "Minimized windows");
    AppendMenuA(g_MainMenu, MF_STRING, IDC_SWITCH_LAYOUT, "Switch keyboard layout");
    SetMenu(hwnd, g_MainMenu);
    RebuildMinimizedWindowsMenu();
}

static BOOL RunSelectedExecutableFromSession0(HWND Owner)
{
    OPENFILENAMEA ofn;
    char fileName[MAX_PATH];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char dir[MAX_PATH];
    char *lastSlash;
    BOOL ok;

    ZeroMemory(fileName, sizeof(fileName));
    ZeroMemory(&ofn, sizeof(ofn));

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = Owner;
    ofn.lpstrFilter = "Executable files (*.exe)\0*.exe\0All files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    ofn.lpstrTitle = "Select executable to run in Session 0";

    if (!GetOpenFileNameA(&ofn))
    {
        DWORD gle;
        char msg[256];

        gle = CommDlgExtendedError();
        if (gle != 0)
        {
            wsprintfA(msg, "GetOpenFileName failed. CommDlgExtendedError=%lu", gle);
            MessageBoxA(Owner, msg, "UI0Detect test", MB_ICONEXCLAMATION | MB_OK);
            return FALSE;
        }
        return FALSE;
    }

    lstrcpynA(dir, fileName, MAX_PATH);
    lastSlash = strrchr(dir, '\\');
    if (lastSlash)
        *lastSlash = 0;
    else
        dir[0] = 0;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.lpDesktop = "WinSta0\\Default";

    SetLastError(0);
    ok = CreateProcessA(fileName,
                        NULL,
                        NULL,
                        NULL,
                        FALSE,
                        0,
                        NULL,
                        dir[0] ? dir : NULL,
                        &si,
                        &pi);

    if (!ok)
    {
        DWORD gle;
        char msg[512];

        gle = GetLastError();
        wsprintfA(msg, "CreateProcess failed.\r\n\r\nFile: %s\r\nWin32 error code: %lu", fileName, gle);
        MessageBoxA(Owner, msg, "UI0Detect test", MB_ICONEXCLAMATION | MB_OK);
        return FALSE;
    }

    CloseHandle(pi.hThread);
    AddRunProcess(pi.hProcess, pi.dwProcessId);
    return TRUE;
}

static void PositionS0Dialog(void)
{
    int x;
    int y;
    int cx;
    int cy;
    int w;
    int h;

    if (!g_S0DialogWindow || !IsWindow(g_S0DialogWindow))
        return;

    GetVirtualScreen(&x, &y, &cx, &cy);
    w = 320;
    h = 118;

    SetWindowPos(g_S0DialogWindow,
                 HWND_TOPMOST,
                 x + (cx - w) / 2,
                 y + 20,
                 w,
                 h,
                 SWP_SHOWWINDOW);

    BringWindowToTop(g_S0DialogWindow);
    SetForegroundWindow(g_S0DialogWindow);
    SetActiveWindow(g_S0DialogWindow);

    if (g_ReturnButton && IsWindow(g_ReturnButton))
        SetFocus(g_ReturnButton);

    PrimeSession0Cursor("PositionS0Dialog", FALSE);
}

static void DisableS0DialogCloseCommand(HWND hwnd)
{
    HMENU hSysMenu;

    hSysMenu = GetSystemMenu(hwnd, FALSE);
    if (hSysMenu)
    {
        EnableMenuItem(hSysMenu, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
        DeleteMenu(hSysMenu, SC_CLOSE, MF_BYCOMMAND);
    }

    DrawMenuBar(hwnd);
}

static LRESULT CALLBACK S0DialogWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    DWORD gle;

    if (msg == WM_UI0_EXIT_HELPER)
    {
        DestroyWindow(hwnd);
        return 0;
    }

    switch (msg)
    {
        case WM_CREATE:
            g_ReturnButton = CreateWindowA("BUTTON",
                                          "Return",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_GROUP | BS_DEFPUSHBUTTON,
                                          16,
                                          18,
                                          130,
                                          28,
                                          hwnd,
                                          (HMENU)IDC_RETURN_BUTTON,
                                          GetModuleHandleA(NULL),
                                          NULL);

            g_RunButton = CreateWindowA("BUTTON",
                                       "Run...",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                       160,
                                       18,
                                       130,
                                       28,
                                       hwnd,
                                       (HMENU)IDC_RUN_BUTTON,
                                       GetModuleHandleA(NULL),
                                       NULL);

            CreateS0DialogMenu(hwnd);
            DisableS0DialogCloseCommand(hwnd);

            PrimeSession0Cursor("S0Dialog WM_CREATE", TRUE);
            if (g_ReturnButton)
                SetFocus(g_ReturnButton);
            return 0;

        case WM_SETCURSOR:
            SetCursor(LoadCursor(NULL, IDC_ARROW));
            return TRUE;

        case WM_MOUSEACTIVATE:
            return MA_ACTIVATE;

        case WM_ACTIVATE:
            if (LOWORD(wParam) != WA_INACTIVE)
                PrimeSession0Cursor("S0Dialog WM_ACTIVATE", FALSE);
            return 0;

        case WM_INITMENUPOPUP:
            if ((HMENU)wParam == g_MinimizedMenu)
                RebuildMinimizedWindowsMenu();
            return 0;

        case WM_SYSCOMMAND:
            if ((wParam & 0xFFF0) == SC_CLOSE)
            {
                MessageBeep(MB_ICONEXCLAMATION);
                return 0;
            }
            break;

        case WM_COMMAND:
            if (LOWORD(wParam) == IDC_SWITCH_LAYOUT)
            {
                SwitchToNextKeyboardLayout();
                return 0;
            }

            if (LOWORD(wParam) >= IDC_MINIMIZED_BASE && LOWORD(wParam) <= IDC_MINIMIZED_MAX)
            {
                if (RestoreMinimizedWindowFromMenu((UINT)LOWORD(wParam)))
                    return 0;
            }

            if (LOWORD(wParam) == IDC_RETURN_BUTTON)
            {
                if (!DoRevertFromServicesSessionWithError(&gle))
                    ShowApiFailureMessage(hwnd, "WinStationRevertFromServicesSession", gle);
                return 0;
            }

            if (LOWORD(wParam) == IDC_RUN_BUTTON)
            {
                RunSelectedExecutableFromSession0(hwnd);
                return 0;
            }
            break;

        case WM_INPUTLANGCHANGE:
            UpdateKeyboardLayoutText();
            InvalidateHelperLayoutText();
            return 0;

        case WM_DISPLAYCHANGE:
            ResizeHelperBackground();
            PositionS0Dialog();
            return 0;

        case WM_SETTINGCHANGE:
            /* Do not recenter the dialog here. SPI_SETCURSORS and other
               cursor/system setting refreshes can broadcast WM_SETTINGCHANGE;
               recentering on that message makes user-dragged windows jump back. */
            ResizeHelperBackground();
            return 0;

        case WM_CLOSE:
            MessageBeep(MB_ICONEXCLAMATION);
            return 0;

        case WM_DESTROY:
            if (hwnd == g_S0DialogWindow)
            {
                TerminateRunProcesses();

                if (g_MainMenu)
                {
                    DestroyMenu(g_MainMenu);
                    g_MainMenu = NULL;
                    g_MinimizedMenu = NULL;
                }

                g_S0DialogWindow = NULL;
                g_ReturnButton = NULL;
                g_RunButton = NULL;
            }
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static BOOL CreateS0DialogWindow(void)
{
    WNDCLASSA wc;
    HWND hwnd;

    if (g_S0DialogWindow && IsWindow(g_S0DialogWindow))
        return TRUE;

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = S0DialogWndProc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = S0_DIALOG_CLASS;

    if (!RegisterClassA(&wc))
    {
        DWORD gle;
        gle = GetLastError();
        if (gle != ERROR_CLASS_ALREADY_EXISTS)
        {
            LogMessage("RegisterClassA(%s) failed: GLE=%lu", S0_DIALOG_CLASS, gle);
            return FALSE;
        }
    }

    hwnd = CreateWindowExA(WS_EX_TOPMOST | WS_EX_CONTROLPARENT,
                           S0_DIALOG_CLASS,
                           "Interactive Services Detection",
                           WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                           CW_USEDEFAULT,
                           CW_USEDEFAULT,
                           320,
                           118,
                           NULL,
                           NULL,
                           GetModuleHandleA(NULL),
                           NULL);

    if (!hwnd)
    {
        LogMessage("CreateWindowExA(S0 dialog) failed: GLE=%lu", GetLastError());
        return FALSE;
    }

    g_S0DialogWindow = hwnd;
    DisableS0DialogCloseCommand(hwnd);
    PositionS0Dialog();
    return TRUE;
}

static BOOL SpawnSession0UiHelper(void)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char exe[MAX_PATH];
    char cmd[MAX_PATH + 64];
    DWORD exitCode;

    if (g_S0UiProcess)
    {
        if (GetExitCodeProcess(g_S0UiProcess, &exitCode) && exitCode == STILL_ACTIVE)
            return TRUE;

        CloseHandle(g_S0UiProcess);
        g_S0UiProcess = NULL;
        g_S0UiPid = 0;
    }

    if (!GetModuleFileNameA(NULL, exe, MAX_PATH))
    {
        LogMessage("GetModuleFileNameA failed: GLE=%lu", GetLastError());
        return FALSE;
    }

    wsprintfA(cmd, "\"%s\" /s0ui %lu %s", exe, GetCurrentProcessId(), S0UI_LAUNCH_COOKIE);

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.lpDesktop = "WinSta0\\Default";
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;

    SetLastError(0);
    if (!CreateProcessA(NULL,
                        cmd,
                        NULL,
                        NULL,
                        FALSE,
                        0,
                        NULL,
                        NULL,
                        &si,
                        &pi))
    {
        LogMessage("CreateProcess(/s0ui) failed: GLE=%lu", GetLastError());
        return FALSE;
    }

    g_S0UiProcess = pi.hProcess;
    g_S0UiPid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    LogMessage("Spawned /s0ui PID=%lu", g_S0UiPid);
    return TRUE;
}



static void TerminateDirectChildProcesses(DWORD ParentPid)
{
    HANDLE snap;
    PROCESSENTRY32 pe;
    HANDLE process;

    if (ParentPid == 0)
        return;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        LogMessage("CreateToolhelp32Snapshot failed: GLE=%lu", GetLastError());
        return;
    }

    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (!Process32First(snap, &pe))
    {
        CloseHandle(snap);
        return;
    }

    do
    {
        if (pe.th32ParentProcessID == ParentPid)
        {
            process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);
            if (process)
            {
                LogMessage("Terminating child process PID=%lu of /s0ui PID=%lu", pe.th32ProcessID, ParentPid);
                TerminateProcess(process, 0);
                WaitForSingleObject(process, 2000);
                CloseHandle(process);
            }
            else
            {
                LogMessage("OpenProcess(child PID=%lu) failed: GLE=%lu", pe.th32ProcessID, GetLastError());
            }
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
}

static void ShutdownSession0UiHelper(void)
{
    HWND hwnd;
    DWORD waitResult;

    hwnd = FindWindowA(S0_DIALOG_CLASS, NULL);
    if (hwnd)
        PostMessageA(hwnd, WM_UI0_EXIT_HELPER, 0, 0);

    if (g_S0UiProcess)
    {
        waitResult = WaitForSingleObject(g_S0UiProcess, 5000);
        if (waitResult == WAIT_TIMEOUT)
        {
            LogMessage("/s0ui did not exit gracefully; terminating PID=%lu", g_S0UiPid);
            TerminateDirectChildProcesses(g_S0UiPid);
            TerminateProcess(g_S0UiProcess, 0);
            WaitForSingleObject(g_S0UiProcess, 2000);
        }

        CloseHandle(g_S0UiProcess);
        g_S0UiProcess = NULL;
        g_S0UiPid = 0;
    }
}


static DWORD GetCurrentParentProcessId(void)
{
    HANDLE snap;
    PROCESSENTRY32 pe;
    DWORD pid;
    DWORD parentPid;

    pid = GetCurrentProcessId();
    parentPid = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (Process32First(snap, &pe))
    {
        do
        {
            if (pe.th32ProcessID == pid)
            {
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return parentPid;
}


static BOOL IsParentExecutableSameAsSelf(DWORD ParentPid)
{
    HANDLE process;
    char selfPath[MAX_PATH];
    char parentPath[MAX_PATH];
    DWORD size;
    BOOL ok;

    if (!GetModuleFileNameA(NULL, selfPath, MAX_PATH))
        return FALSE;

    process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ParentPid);
    if (!process)
    {
        LogMessage("OpenProcess(parent PID=%lu) failed: GLE=%lu", ParentPid, GetLastError());
        return FALSE;
    }

    parentPath[0] = 0;
    size = MAX_PATH;
    ok = QueryFullProcessImageNameA(process, 0, parentPath, &size);
    CloseHandle(process);

    if (!ok)
    {
        LogMessage("QueryFullProcessImageName(parent PID=%lu) failed: GLE=%lu", ParentPid, GetLastError());
        return FALSE;
    }

    if (lstrcmpiA(selfPath, parentPath) != 0)
    {
        LogMessage("Invalid /s0ui launch: parent image differs. self=%s parent=%s", selfPath, parentPath);
        return FALSE;
    }

    return TRUE;
}

static BOOL ValidateS0UiLaunch(int argc, char **argv)
{
    DWORD expectedParentPid;
    DWORD actualParentPid;

    if (argc < 4)
    {
        LogMessage("Invalid /s0ui launch: missing service PID/cookie");
        return FALSE;
    }

    if (lstrcmpA(argv[3], S0UI_LAUNCH_COOKIE) != 0)
    {
        LogMessage("Invalid /s0ui launch: bad launch cookie");
        return FALSE;
    }

    expectedParentPid = strtoul(argv[2], NULL, 10);
    actualParentPid = GetCurrentParentProcessId();

    if (expectedParentPid == 0 || actualParentPid != expectedParentPid)
    {
        LogMessage("Invalid /s0ui launch: expected parent PID=%lu actual parent PID=%lu",
                   expectedParentPid,
                   actualParentPid);
        return FALSE;
    }

    if (!IsParentExecutableSameAsSelf(actualParentPid))
        return FALSE;

    return TRUE;
}

static int RunS0UiMode(int argc, char **argv)
{
    MSG msg;
    HANDLE hMutex;

    if (!ValidateS0UiLaunch(argc, argv))
        return 1;

    InstallKeyboardLayoutHook();

    hMutex = CreateMutexA(NULL, FALSE, "Local\\UI0Detect_S0UI_Instance");
    if (hMutex && GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(hMutex);
        return 2;
    }

    CreateHelperBackgroundWindow();
    CreateS0DialogWindow();
    PrimeSession0Cursor("RunS0UiMode startup", TRUE);

    while (GetMessageA(&msg, NULL, 0, 0) > 0)
    {
        if (g_S0DialogWindow && IsWindow(g_S0DialogWindow) && IsDialogMessageA(g_S0DialogWindow, &msg))
            continue;

        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    TerminateRunProcesses();
    UninstallKeyboardLayoutHook();

    if (hMutex)
        CloseHandle(hMutex);

    return 0;
}

static int RunServiceWindowLoop(void)
{
    MSG msg;
    HANDLE hMutex;

    hMutex = CreateMutexA(NULL, FALSE, "Local\\UI0Detect_Service_Instance");
    if (hMutex && GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(hMutex);
        return 2;
    }

    if (!AttachToSession0InteractiveDesktop())
    {
        if (hMutex) CloseHandle(hMutex);
        return 3;
    }

    if (!CreateServiceBackgroundWindow())
    {
        if (hMutex) CloseHandle(hMutex);
        return 4;
    }

    SpawnSession0UiHelper();

    while (GetMessageA(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    ShutdownSession0UiHelper();

    if (g_ServiceDesktop)
    {
        CloseDesktop(g_ServiceDesktop);
        g_ServiceDesktop = NULL;
    }

    if (g_ServiceWindowStation)
    {
        CloseWindowStation(g_ServiceWindowStation);
        g_ServiceWindowStation = NULL;
    }

    if (hMutex)
        CloseHandle(hMutex);

    return 0;
}

static void ReportServiceStatusSimple(DWORD CurrentState, DWORD Win32ExitCode, DWORD WaitHint)
{
    static DWORD checkpoint = 1;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
    g_ServiceStatus.dwCurrentState = CurrentState;
    g_ServiceStatus.dwWin32ExitCode = Win32ExitCode;
    g_ServiceStatus.dwWaitHint = WaitHint;

    if (CurrentState == SERVICE_START_PENDING)
        g_ServiceStatus.dwControlsAccepted = 0;
    else
        g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

    if (CurrentState == SERVICE_RUNNING || CurrentState == SERVICE_STOPPED)
        g_ServiceStatus.dwCheckPoint = 0;
    else
        g_ServiceStatus.dwCheckPoint = checkpoint++;

    SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
}

static DWORD WINAPI StopThreadProc(LPVOID Param)
{
    UNREFERENCED_PARAMETER(Param);

    if (g_ServiceBackgroundWindow && IsWindow(g_ServiceBackgroundWindow))
        DestroyWindow(g_ServiceBackgroundWindow);

    if (g_MainThreadId)
        PostThreadMessageA(g_MainThreadId, WM_QUIT, 0, 0);

    return 0;
}

static VOID WINAPI ServiceControlHandler(DWORD Control)
{
    HANDLE hThread;

    switch (Control)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ReportServiceStatusSimple(SERVICE_STOP_PENDING, NO_ERROR, 3000);
            hThread = CreateThread(NULL, 0, StopThreadProc, NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);
            return;
    }

    ReportServiceStatusSimple(g_ServiceStatus.dwCurrentState, NO_ERROR, 0);
}

static VOID WINAPI ServiceMain(DWORD argc, LPSTR *argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    g_MainThreadId = GetCurrentThreadId();

    g_ServiceStatusHandle = RegisterServiceCtrlHandlerA(SERVICE_NAME, ServiceControlHandler);
    if (!g_ServiceStatusHandle)
        return;

    ReportServiceStatusSimple(SERVICE_START_PENDING, NO_ERROR, 3000);
    EnableServicePrivileges();
    ReportServiceStatusSimple(SERVICE_RUNNING, NO_ERROR, 0);
    RunServiceWindowLoop();
    ReportServiceStatusSimple(SERVICE_STOPPED, NO_ERROR, 0);
}

static int RunAsServiceDispatcher(void)
{
    SERVICE_TABLE_ENTRYA table[2];

    table[0].lpServiceName = SERVICE_NAME;
    table[0].lpServiceProc = ServiceMain;
    table[1].lpServiceName = NULL;
    table[1].lpServiceProc = NULL;

    if (!StartServiceCtrlDispatcherA(table))
    {
        LogMessage("StartServiceCtrlDispatcherA failed: GLE=%lu", GetLastError());
        return 1;
    }

    return 0;
}

static int InstallService(void)
{
    SC_HANDLE scm;
    SC_HANDLE svc;
    char exe[MAX_PATH];
    char binPath[MAX_PATH + 64];

    if (!GetModuleFileNameA(NULL, exe, MAX_PATH))
        return 1;

    wsprintfA(binPath, "\"%s\" /service", exe);

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm)
    {
        LogMessage("OpenSCManagerA failed: GLE=%lu", GetLastError());
        return 1;
    }

    svc = CreateServiceA(scm,
                         SERVICE_NAME,
                         SERVICE_DISPLAY,
                         SERVICE_ALL_ACCESS,
                         SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
                         SERVICE_DEMAND_START,
                         SERVICE_ERROR_NORMAL,
                         binPath,
                         NULL,
                         NULL,
                         NULL,
                         "LocalSystem",
                         NULL);

    if (!svc)
    {
        LogMessage("CreateServiceA(%s) failed: GLE=%lu", SERVICE_NAME, GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    LogMessage("Service installed: %s", SERVICE_NAME);
    return 0;
}

static int UninstallService(void)
{
    SC_HANDLE scm;
    SC_HANDLE svc;
    SERVICE_STATUS status;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
        return 1;

    svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!svc)
    {
        LogMessage("OpenServiceA(%s) failed: GLE=%lu", SERVICE_NAME, GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }

    ControlService(svc, SERVICE_CONTROL_STOP, &status);

    if (!DeleteService(svc))
    {
        LogMessage("DeleteService failed: GLE=%lu", GetLastError());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return 1;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    LogMessage("Service deleted: %s", SERVICE_NAME);
    return 0;
}

static int StartTestService(void)
{
    SC_HANDLE scm;
    SC_HANDLE svc;
    BOOL ok;
    DWORD gle;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
        return 1;

    svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc)
    {
        LogMessage("OpenServiceA(%s) failed: GLE=%lu", SERVICE_NAME, GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }

    SetLastError(0);
    ok = StartServiceA(svc, 0, NULL);
    gle = GetLastError();

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (!ok && gle != ERROR_SERVICE_ALREADY_RUNNING)
    {
        LogMessage("StartServiceA failed: GLE=%lu", gle);
        return 1;
    }

    return 0;
}

static int StopTestService(void)
{
    SC_HANDLE scm;
    SC_HANDLE svc;
    SERVICE_STATUS status;
    BOOL ok;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
        return 1;

    svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc)
    {
        LogMessage("OpenServiceA(%s) failed: GLE=%lu", SERVICE_NAME, GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }

    ok = ControlService(svc, SERVICE_CONTROL_STOP, &status);
    if (!ok)
        LogMessage("ControlService(STOP) failed: GLE=%lu", GetLastError());

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok ? 0 : 1;
}

static BOOL QueryUI0DetectServiceStatus(char *StatusText, DWORD StatusTextCch, BOOL *CanSwitch)
{
    SC_HANDLE scm;
    SC_HANDLE svc;
    SERVICE_STATUS_PROCESS ssp;
    DWORD needed;
    BOOL installed;

    installed = FALSE;
    *CanSwitch = FALSE;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
    {
        lstrcpynA(StatusText, "SCM is not accessible; switch readiness is unknown.", StatusTextCch);
        return FALSE;
    }

    svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!svc)
    {
        lstrcpynA(StatusText, "Switch is not ready: service UI0Detect is not installed.", StatusTextCch);
        CloseServiceHandle(scm);
        return FALSE;
    }

    installed = TRUE;
    ZeroMemory(&ssp, sizeof(ssp));

    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
    {
        if (ssp.dwCurrentState == SERVICE_RUNNING)
        {
            lstrcpynA(StatusText, "Switch is ready: service UI0Detect is installed and running.", StatusTextCch);
            *CanSwitch = TRUE;
        }
        else
            wsprintfA(StatusText, "Switch is not ready: service UI0Detect is installed but not running (state=%lu).", ssp.dwCurrentState);
    }
    else
        lstrcpynA(StatusText, "Service UI0Detect is installed, but status query failed.", StatusTextCch);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return installed;
}


static void ShowCommandStatusMessage(const char *CommandName, int Result)
{
    char msg[512];

    if (Result == 0)
        wsprintfA(msg, "%s succeeded.", CommandName);
    else
        wsprintfA(msg, "%s failed. Return code: %d. See %%SystemRoot%%\\Temp\\%s for details.",
                  CommandName,
                  Result,
                  LOG_FILE_NAME);

    LogMessage("%s", msg);
    printf("%s\n", msg);
    MessageBoxA(NULL, msg, "UI0Detect test", (Result == 0) ? (MB_OK | MB_ICONINFORMATION) : (MB_OK | MB_ICONEXCLAMATION));
}

static int RunServiceStatusQueryCommand(void)
{
    char status[512];
    BOOL canSwitch;
    BOOL installed;

    canSwitch = FALSE;
    status[0] = 0;
    installed = QueryUI0DetectServiceStatus(status, sizeof(status), &canSwitch);

    LogMessage("/queryservice: installed=%u canSwitch=%u status=%s",
               installed,
               canSwitch,
               status);
    printf("%s\n", status);
    MessageBoxA(NULL, status, "UI0Detect service status", MB_OK | (canSwitch ? MB_ICONINFORMATION : MB_ICONWARNING));
    return canSwitch ? 0 : 1;
}

static const char *GetHelpText(void)
{
    return
        "UI0Detect Session 0 test utility\r\n"
        "\r\n"
        "Main commands:\r\n"
        "  /install     Install the LocalSystem interactive service named UI0Detect.\r\n"
        "  /uninstall   Stop and delete the UI0Detect service.\r\n"
        "  /start       Start the UI0Detect service.\r\n"
        "  /stop        Stop the UI0Detect service.\r\n"
        "  /switch      Switch the physical console to Session 0.\r\n"
        "  /revert      Return from Session 0 to the previous user session.\r\n"
        "  /queryservice Query the UI0Detect service status.\r\n"
        "  /help, /?    Open this help window.\r\n"
        "\r\n"
        "Internal commands:\r\n"
        "  /service     Service entry point used by SCM.\r\n"
        "  /s0ui        Session 0 UI helper launched by the service; not for manual use.\r\n"
        "\r\n"
        "Notes:\r\n"
        "  The service name must be exactly UI0Detect.\r\n"
        "  /switch is expected to work only after the UI0Detect service is running\r\n"
        "  and has initialized its Session 0 viewer state.\r\n";
}

static void UpdateMainStatus(void)
{
    DWORD sid;
    char text[512];
    BOOL canSwitch;

    if (!g_MainStatusLabel)
        return;

    sid = 0xFFFFFFFF;
    ProcessIdToSessionId(GetCurrentProcessId(), &sid);

    if (sid == 0)
    {
        lstrcpynA(text, "Current session: 0. The button will call revert.", sizeof(text));
        if (g_MainActionButton)
            SetWindowTextA(g_MainActionButton, "Revert");
    }
    else
    {
        QueryUI0DetectServiceStatus(text, sizeof(text), &canSwitch);
        if (g_MainActionButton)
            SetWindowTextA(g_MainActionButton, "Switch to Session 0");
    }

    SetWindowTextA(g_MainStatusLabel, text);
}

static LRESULT CALLBACK MainWindowWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    HWND edit;
    HWND label;
    HWND button;
    RECT rc;
    DWORD sid;
    DWORD gle;
    HFONT font;

    switch (msg)
    {
        case WM_CREATE:
            font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

            edit = CreateWindowExA(WS_EX_CLIENTEDGE,
                                   "EDIT",
                                   GetHelpText(),
                                   WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
                                   ES_AUTOVSCROLL | WS_VSCROLL,
                                   12,
                                   12,
                                   560,
                                   260,
                                   hwnd,
                                   (HMENU)IDC_MAIN_HELP,
                                   GetModuleHandleA(NULL),
                                   NULL);

            label = CreateWindowA("STATIC",
                                  "",
                                  WS_CHILD | WS_VISIBLE | SS_CENTER,
                                  12,
                                  282,
                                  560,
                                  34,
                                  hwnd,
                                  (HMENU)IDC_MAIN_STATUS,
                                  GetModuleHandleA(NULL),
                                  NULL);

            button = CreateWindowA("BUTTON",
                                   "Switch",
                                   WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                   202,
                                   322,
                                   180,
                                   30,
                                   hwnd,
                                   (HMENU)IDC_MAIN_ACTION,
                                   GetModuleHandleA(NULL),
                                   NULL);

            if (font)
            {
                SendMessageA(edit, WM_SETFONT, (WPARAM)font, TRUE);
                SendMessageA(label, WM_SETFONT, (WPARAM)font, TRUE);
                SendMessageA(button, WM_SETFONT, (WPARAM)font, TRUE);
            }

            g_MainStatusLabel = label;
            g_MainActionButton = button;
            UpdateMainStatus();
            return 0;

        case WM_SIZE:
            GetClientRect(hwnd, &rc);
            MoveWindow(GetDlgItem(hwnd, IDC_MAIN_HELP), 12, 12, rc.right - 24, rc.bottom - 112, TRUE);
            MoveWindow(GetDlgItem(hwnd, IDC_MAIN_STATUS), 12, rc.bottom - 92, rc.right - 24, 34, TRUE);
            MoveWindow(GetDlgItem(hwnd, IDC_MAIN_ACTION), (rc.right - 180) / 2, rc.bottom - 48, 180, 30, TRUE);
            return 0;

        case WM_COMMAND:
            if (LOWORD(wParam) == IDC_MAIN_ACTION)
            {
                sid = 0xFFFFFFFF;
                ProcessIdToSessionId(GetCurrentProcessId(), &sid);

                if (sid == 0)
                {
                    if (!DoRevertFromServicesSessionWithError(&gle))
                        ShowApiFailureMessage(hwnd, "WinStationRevertFromServicesSession", gle);
                }
                else
                {
                    if (!DoSwitchToServicesSessionWithError(&gle))
                        ShowApiFailureMessage(hwnd, "WinStationSwitchToServicesSession", gle);
                }

                UpdateMainStatus();
                return 0;
            }
            break;

        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            g_MainWindow = NULL;
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static int RunMainWindow(void)
{
    WNDCLASSA wc;
    HWND hwnd;
    MSG msg;

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = MainWindowWndProc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = MAIN_WINDOW_CLASS;

    RegisterClassA(&wc);

    hwnd = CreateWindowExA(0,
                           MAIN_WINDOW_CLASS,
                           "UI0Detect Session 0 Test",
                           WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           CW_USEDEFAULT,
                           CW_USEDEFAULT,
                           600,
                           410,
                           NULL,
                           NULL,
                           GetModuleHandleA(NULL),
                           NULL);

    if (!hwnd)
        return 1;

    g_MainWindow = hwnd;

    while (GetMessageA(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return 0;
}

static void PrintConsoleUsage(void)
{
    printf("%s\n", GetHelpText());
}


static BOOL CommandArgEquals(const char *Arg, const char *Name)
{
    if (!Arg || !Name)
        return FALSE;

    if (Arg[0] == '/' || Arg[0] == '-')
        Arg++;

    return lstrcmpiA(Arg, Name) == 0;
}

int main(int argc, char **argv)
{
    DWORD gle;
    int result;
    char msg[512];

    if (argc < 2)
        return RunMainWindow();

    if (CommandArgEquals(argv[1], "help") || lstrcmpA(argv[1], "?") == 0 || lstrcmpA(argv[1], "/?") == 0)
        return RunMainWindow();

    if (CommandArgEquals(argv[1], "install"))
    {
        result = InstallService();
        ShowCommandStatusMessage("Install", result);
        return result;
    }

    if (CommandArgEquals(argv[1], "uninstall"))
    {
        result = UninstallService();
        ShowCommandStatusMessage("Uninstall", result);
        return result;
    }

    if (CommandArgEquals(argv[1], "start"))
    {
        result = StartTestService();
        ShowCommandStatusMessage("Start", result);
        return result;
    }

    if (CommandArgEquals(argv[1], "stop"))
    {
        result = StopTestService();
        ShowCommandStatusMessage("Stop", result);
        return result;
    }

    if (CommandArgEquals(argv[1], "queryservice"))
        return RunServiceStatusQueryCommand();

    if (CommandArgEquals(argv[1], "service"))
        return RunAsServiceDispatcher();

    if (CommandArgEquals(argv[1], "s0ui"))
        return RunS0UiMode(argc, argv);

    if (CommandArgEquals(argv[1], "switch"))
    {
        if (!DoSwitchToServicesSessionWithError(&gle))
        {
            ShowApiFailureMessage(NULL, "WinStationSwitchToServicesSession", gle);
            return 2;
        }
        return 0;
    }

    if (CommandArgEquals(argv[1], "revert"))
    {
        if (!DoRevertFromServicesSessionWithError(&gle))
        {
            ShowApiFailureMessage(NULL, "WinStationRevertFromServicesSession", gle);
            return 2;
        }
        return 0;
    }

    wsprintfA(msg, "Unknown command-line argument: %s", argv[1]);
    LogMessage("%s", msg);
    printf("%s\n", msg);
    MessageBoxA(NULL, msg, "UI0Detect test", MB_OK | MB_ICONEXCLAMATION);
    return 1;
}

#ifdef _MSC_VER
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    extern int __argc;
    extern char **__argv;

    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    return main(__argc, __argv);
}
#endif
