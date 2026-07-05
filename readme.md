# UI0Detect switch-to-session 0 test utility/service

## 1. Summary

This program is an experimental Windows Session 0 switching utility inspired by the legacy Interactive Services Detection (`UI0Detect`) mechanism available on Windows Vista - 10 (before build 1803).

`WARNING! Since Windows 10 keyboard/mouse input is not available in session 0 you need to use bypass ways in order to provide this feature (you can FireDeamon FDUI0Input driver for example).`

`WARNING! This program WON'T work correctly since Windows 10/11 build 22H2 so be carefully!`

`WARNING! This implementation is not perfect, so you can meet some lags/bugs sometime. You can feel free fixing and modifying this program in way you want!`

It installs and runs a LocalSystem interactive service named exactly `UI0Detect`, prepares a Session 0 viewer environment on `WinSta0\Default`, and allows the physical console to be switched between the active user session and Session 0 by calling the undocumented WinStation exports:

- `winsta.dll!WinStationSwitchToServicesSession`
- `winsta.dll!WinStationRevertFromServicesSession`

The service creates the minimum Session 0 state required for switching:

- a service-owned `$$$UI0Background` / `Shell0 Window` shell-state window;
- `SetTaskmanWindow` / `SetShellWindow` registration;
- a separate Session 0 UI helper process that owns the visible grey background and the return/run dialog.

The visible Session 0 UI intentionally lives in a separate helper process, because service-owned visible windows were observed to repaint incorrectly after switching, while helper-owned windows render normally.

The service name is significant. For the switching path to work reliably, the SCM service name must be exactly:

```cmd
UI0Detect
```

The executable file itself may have any name.

## 2. Command-line arguments

### `/install`

Installs the program as a LocalSystem interactive service named `UI0Detect`.

The installed service command line is the current executable path with the internal `/service` argument.

Example:

```cmd
MyUI0detect.exe /install
```

### `/uninstall`

Stops the `UI0Detect` service if possible and deletes it from the Service Control Manager database.

Example:

```cmd
MyUI0detect.exe /uninstall
```

### `/queryservice`

Shows current status of UI0detect service

Example:

```cmd
MyUI0detect.exe /queryservice
```

### `/start`

Starts the installed `UI0Detect` service.

When started, the service prepares the Session 0 viewer state and launches the Session 0 UI helper.

Example:

```cmd
MyUI0detect.exe /start
```

### `/stop`

Stops the installed `UI0Detect` service.

Example:

```cmd
MyUI0detect.exe /stop
```

### `/switch`

Attempts to switch the physical console from the current user session to Session 0.

This is expected to work only when the `UI0Detect` service is installed, running, and has initialized its Session 0 viewer state.

Example:

```cmd
MyUI0detect.exe /switch
```

### `/revert`

Attempts to return from Session 0 to the previous user session.

This is intended to be called from Session 0, either from the Session 0 return dialog or manually from a process running in Session 0.

Example:

```cmd
MyUI0detect.exe /revert
```

### `/help` or `/?`

Prints command-line help text.

Example:

```cmd
MyUI0detect.exe /help
```

### `/service` internal

Internal service entry point used by the Service Control Manager.

Do not run this manually under normal use. It is used by the installed `UI0Detect` service.

### `/s0ui` internal

Internal Session 0 UI helper mode launched by the service.

The helper creates the visible grey Session 0 background and the small Session 0 dialog containing:

- `Return` — calls `WinStationRevertFromServicesSession`;
- `Run...` — opens a file picker and starts the selected executable on `WinSta0\Default`.

Do not run this manually under normal use unless you are specifically debugging the helper UI.

### No arguments

Running the executable with no arguments opens a GUI help window. The window contains:

- a read-only help text box;
- a status label indicating whether switching appears available;
- an action button.

The action button calls:

- `WinStationSwitchToServicesSession` outside Session 0;
- `WinStationRevertFromServicesSession` inside Session 0.

If the WinStation call fails, the program shows a message box containing the Win32 error code.

## 3. Basic usage

Open an elevated command prompt.

Install the service:

```cmd
MyUI0detect.exe /install
```

Start the service:

```cmd
MyUI0detect.exe /start
```

Switch to Session 0 from the active user session:

```cmd
MyUI0detect.exe /switch
```

In Session 0, use the `Return` button to go back to the previous user session. The `Run...` button can be used to start an executable directly on the Session 0 interactive desktop.

Alternatively, from a process already running in Session 0, return manually:

```cmd
MyUI0detect.exe /revert
```

Stop and remove the service when finished:

```cmd
MyUI0detect.exe /stop
MyUI0detect.exe /uninstall
```

Notes:

- The service must be named exactly `UI0Detect`.
- The service must run as LocalSystem.
- `/switch` should be issued only after the service is running and has prepared the Session 0 viewer state.
- Session 0 interactive UI is a legacy compatibility mechanism. Use it only for controlled testing and research.

## 4. How to build?

Console-subsystem build:

```cmd
cl /W3 /D_WIN32_WINNT=0x0600 MyUI0detect.c user32.lib gdi32.lib advapi32.lib wtsapi32.lib comdlg32.lib
```

GUI-subsystem build without a console window:

```cmd
cl /W3 /D_WIN32_WINNT=0x0600 MyUI0detect.c user32.lib gdi32.lib advapi32.lib wtsapi32.lib comdlg32.lib /link /SUBSYSTEM:WINDOWS
```
