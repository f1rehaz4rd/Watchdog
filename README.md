# Watchdog

## About
This is a Windows Service that injects a DLL into a process of choice. After the thread for the DLL is created it is then watched to ensure that it is always still running. If Watchdog detects that the thread is killed it attempts to create it again. If the DLL is missing from the computer it redownloads it from some remote host and then again attempts to inject the DLL again.

## How to use
* Compile the code to be x64 after replacing all the filler information.
* Compile a x64 DLL to be used for injection.
* Create the service:
```
sc.exe create "Watchdog" binPath= "C:\PATH\TO\EXECUTABLE" start=auto
```
