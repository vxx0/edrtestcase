
#include <stdint.h>
#include <string>
#include <vector>
#include <windows.h>
//#include <winternl.h>

typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;

} STRING, *PSTRING;
typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG  TimeStamp;
	STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;
typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;

} CURDIR, *PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;                                                    //0x0
	ULONG Length;                                                           //0x4
	ULONG Flags;                                                            //0x8
	ULONG DebugFlags;                                                       //0xc
	VOID* ConsoleHandle;                                                    //0x10
	ULONG ConsoleFlags;                                                     //0x14
	VOID* StandardInput;                                                    //0x18
	VOID* StandardOutput;                                                   //0x1c
	VOID* StandardError;                                                    //0x20
	struct _CURDIR CurrentDirectory;                                        //0x24
	struct _UNICODE_STRING DllPath;                                         //0x30
	struct _UNICODE_STRING ImagePathName;                                   //0x38
	struct _UNICODE_STRING CommandLine;                                     //0x40
	VOID* Environment;                                                      //0x48
	ULONG StartingX;                                                        //0x4c
	ULONG StartingY;                                                        //0x50
	ULONG CountX;                                                           //0x54
	ULONG CountY;                                                           //0x58
	ULONG CountCharsX;                                                      //0x5c
	ULONG CountCharsY;                                                      //0x60
	ULONG FillAttribute;                                                    //0x64
	ULONG WindowFlags;                                                      //0x68
	ULONG ShowWindowFlags;                                                  //0x6c
	struct _UNICODE_STRING WindowTitle;                                     //0x70
	struct _UNICODE_STRING DesktopInfo;                                     //0x78
	struct _UNICODE_STRING ShellInfo;                                       //0x80
	struct _UNICODE_STRING RuntimeData;                                     //0x88
	struct _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0x90
	volatile ULONG EnvironmentSize;                                         //0x290
	volatile ULONG EnvironmentVersion;                                      //0x294
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;


typedef
VOID
(NTAPI *PPS_POST_PROCESS_INIT_ROUTINE) (
	VOID
	);

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;

#ifndef Add2Ptr
#define Add2Ptr(_P_, _X_) (void*)((uintptr_t)(_P_) + _X_)
#endif//Add2Ptr

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif//NT_SUCCESS

HRESULT GetFileSize(
	handle_t FileHandle,
	uint64_t& FileSize)
{
	LARGE_INTEGER fileSize;
	FileSize = 0;
	if (!GetFileSizeEx(FileHandle, &fileSize)) {
		return E_FAIL;
	}
	if (fileSize.QuadPart < 0) {
		return E_FAIL;
	}
	FileSize = fileSize.QuadPart;
	return S_OK;
}

HRESULT SetFilePointer(
	handle_t FileHandle,
	int64_t DistanceToMove,
	uint32_t MoveMethod
)
{
	LARGE_INTEGER distance;
	distance.QuadPart = DistanceToMove;
	if (!SetFilePointerEx(FileHandle, distance, nullptr, MoveMethod)) {
		return E_FAIL;
	}
	return S_OK;
}


HRESULT CopyFileByHandle(
	_In_ HANDLE SourceHandle,
	_In_ HANDLE TargetHandle,
	_In_ BOOL FlushFile
)
{
	uint64_t sourceSize;
	uint64_t targetSize;
	if (GetFileSize(SourceHandle, sourceSize) != S_OK) {
		return E_FAIL;
	}
	if (GetFileSize(TargetHandle, targetSize) != S_OK) {
		return E_FAIL;
	}
	if (SetFilePointer(SourceHandle, 0, FILE_BEGIN) != S_OK) {
		return E_FAIL;
	}
	if (SetFilePointer(TargetHandle, 0, FILE_BEGIN) != S_OK) {
		return E_FAIL;
	}
	uint64_t bytesRemaining = sourceSize;
	std::vector<uint8_t> buffer;
	constexpr static uint32_t MaxFileBuffer{ 0x8000 };

	if (bytesRemaining > MaxFileBuffer) {
		buffer.assign(MaxFileBuffer, 0);
	}
	else {
		buffer.assign((size_t)(bytesRemaining), 0);
	}
	while (bytesRemaining > 0) {
		if (bytesRemaining < buffer.size()) {
			buffer.assign((size_t)(bytesRemaining), 0);
		}
		DWORD bytesRead = 0;
		if (!ReadFile(SourceHandle, buffer.data(), (DWORD)(buffer.size()), &bytesRead, nullptr)) {
			return E_FAIL;
		}
		bytesRemaining -= bytesRead;
		DWORD bytesWitten = 0;
		if (!WriteFile(TargetHandle, buffer.data(), (DWORD)(buffer.size()), &bytesWitten, nullptr)) {
			return E_FAIL;
		}
	}
	if (FlushFile) {
		if (!FlushFileBuffers(TargetHandle)) {
			return E_FAIL;
		}
	}
	if (!SetEndOfFile(TargetHandle)) {
		return E_FAIL;
	}
	return S_OK;
}

HRESULT GetImageEntryPointRva(
	handle_t FileHandle,
	uint32_t& EntryPointRva
)
{
	EntryPointRva = 0;

	uint64_t fileSize;
	if (GetFileSize(FileHandle, fileSize) != S_OK) {
		return E_FAIL;
	}

	ULARGE_INTEGER mappingSize = { 0 };

	HANDLE mapping = CreateFileMappingW(FileHandle,
		nullptr,
		PAGE_READONLY,
		mappingSize.HighPart,
		mappingSize.LowPart,
		nullptr);

	mappingSize.QuadPart = fileSize;

	PUCHAR view = (PUCHAR)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, mappingSize.LowPart);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(view);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return E_FAIL;
	}

	PIMAGE_NT_HEADERS32 ntHeader = (PIMAGE_NT_HEADERS32)(Add2Ptr(view, dosHeader->e_lfanew));
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		return E_FAIL;
	}
	if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		EntryPointRva = ntHeader->OptionalHeader.AddressOfEntryPoint;
	}
	else if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		PIMAGE_NT_HEADERS64 ntHeader64 = (PIMAGE_NT_HEADERS64)(ntHeader);
		EntryPointRva = ntHeader64->OptionalHeader.AddressOfEntryPoint;
	}
	else {
		return E_FAIL;
	}
	return S_OK;
}

typedef
NTSTATUS
(NTAPI* pfn_RtlCreateProcessParametersEx)(
	PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	PUNICODE_STRING  ImagePathName,
	PUNICODE_STRING  DllPath,
	PUNICODE_STRING  CurrentDirectory,
	PUNICODE_STRING  CommandLine,
	PWSTR            Environment,
	PUNICODE_STRING  WindowTitle,
	PUNICODE_STRING  DesktopInfo,
	PUNICODE_STRING  ShellInfo,
	PUNICODE_STRING  RuntimeData,
	DWORD           UNKONW
	);

typedef
NTSYSAPI
VOID
(NTAPI* pfn_RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);


PPEB NtCurrentPeb()
{
#ifdef _AMD64_
	return (PPEB)__readgsqword(0x60);
#else
	return (PPEB)__readfsdword(0x30);
#endif
}

HRESULT WriteRemoteProcessParameters(
	handle_t ProcessHandle,
	const std::wstring ImageFileName,
	const std::wstring& CommandLine,
	void* EnvironmentBlock,
	const std::wstring& WindowTitle,
	const std::wstring& DesktopInfo
)
{
	//
	// Get the basic info for the remote PEB address.
	//
	PROCESS_BASIC_INFORMATION pbi{};
	NTSTATUS status = NtQueryInformationProcess(
		ProcessHandle,
		ProcessBasicInformation,
		&pbi,
		sizeof(pbi),
		nullptr);
	if (!NT_SUCCESS(status)) {
		return E_FAIL;
	}

	UNICODE_STRING imageName;
	UNICODE_STRING dllPath;
	UNICODE_STRING commandLine;
	UNICODE_STRING currentDirectory;
	UNICODE_STRING windowTitle;
	UNICODE_STRING desktopInfo;
	UNICODE_STRING shellInfo;
	UNICODE_STRING runtimeData;
	PRTL_USER_PROCESS_PARAMETERS params = NULL;

	pfn_RtlInitUnicodeString RtlInitUnicodeString = (pfn_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString");

	RtlInitUnicodeString(&imageName, ImageFileName.c_str());
	RtlInitUnicodeString(&dllPath, L"");
	RtlInitUnicodeString(&commandLine, CommandLine.c_str());
	RtlInitUnicodeString(&currentDirectory, L"");
	RtlInitUnicodeString(&windowTitle, WindowTitle.c_str());
	RtlInitUnicodeString(&desktopInfo, DesktopInfo.c_str());
	RtlInitUnicodeString(&shellInfo, L"");
	RtlInitUnicodeString(&runtimeData, L"");

	pfn_RtlCreateProcessParametersEx RtlCreateProcessParametersEx = (pfn_RtlCreateProcessParametersEx)
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");

	RtlCreateProcessParametersEx(&params,
		&imageName,
		NULL,
		NULL,
		&commandLine,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		1);

	size_t len = params->MaximumLength + params->EnvironmentSize;

	//
	// Allocate memory in the remote process to hold the process parameters.
	//
	auto remoteMemory = VirtualAllocEx(ProcessHandle,
		params,
		len + 0x1000,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (params->Environment != nullptr)
	{
		//params->Environment = Add2Ptr(remoteMemory, params->Length);
	}

	//
	// Write the parameters into the remote process.
	//
	WriteProcessMemory(ProcessHandle,
		params,
		params,
		len,
		nullptr);

	//
	// Write the parameter pointer to the remote process PEB.
	//
	WriteProcessMemory(
		ProcessHandle,
		Add2Ptr(pbi.PebBaseAddress,
			FIELD_OFFSET(PEB, ProcessParameters)),
		&params,
		sizeof(params),
		nullptr);

	return S_OK;
}

typedef struct _FILE_DISPOSITION_INFORMATION {
	BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

int main()
{
	std::wstring SourceFileName = L"c:\\windows\\system32\\calc.exe";
	std::wstring targetFileName = L"c:\\test\\test.exe";

	HANDLE hFile = CreateFileW(SourceFileName.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ |
		FILE_SHARE_WRITE |
		FILE_SHARE_DELETE,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);

	DWORD shareMode = (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);

	HANDLE hTarget = CreateFileW(targetFileName.c_str(),
		GENERIC_ALL,
		shareMode,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);

	CopyFileByHandle(hFile, hTarget, TRUE);

	FILE_DISPOSITION_INFORMATION info = { 0 };
	IO_STATUS_BLOCK status_block = { 0 };
	info.DeleteFile = TRUE;
	NTSTATUS status;
	
	status = NtSetInformationFile(hTarget, &status_block, &info, sizeof(info), FileDispositionInformation);

	HANDLE sectionHandle = 0;
	 status = NtCreateSection(&sectionHandle,
		SECTION_ALL_ACCESS,
		nullptr,
		nullptr,
		PAGE_READONLY,
		SEC_IMAGE,
		hTarget);

	 //

	if (!NT_SUCCESS(status)) {
		return 0;
	}

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) -1)
#endif//NtCurrentProcess

#ifndef PROCESS_CREATE_FLAGS_INHERIT_HANDLES
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004
#endif//PROCESS_CREATE_FLAGS_INHERIT_HANDLES

	HANDLE processHandle = 0;
	status = NtCreateProcessEx(&processHandle,
		PROCESS_ALL_ACCESS,
		nullptr,
		NtCurrentProcess(),
		PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
		sectionHandle,
		nullptr,
		nullptr,
		0);
	if (!NT_SUCCESS(status)) {
		return 0;
	}

	

	uint32_t imageEntryPointRva;
	GetImageEntryPointRva(hTarget, imageEntryPointRva);


	PROCESS_BASIC_INFORMATION pbi{};
	status = NtQueryInformationProcess(processHandle,
		ProcessBasicInformation,
		&pbi,
		sizeof(pbi),
		nullptr);

	PEB peb{};
	if (!ReadProcessMemory(processHandle,
		pbi.PebBaseAddress,
		&peb,
		sizeof(peb),
		nullptr))
	{
		return 0;
	}

	WriteRemoteProcessParameters(
		processHandle,
		targetFileName,
		(L"\"" + targetFileName + L"\""),
		NtCurrentPeb()->ProcessParameters->Environment,
		targetFileName,
		L"WinSta0\\Default"
	);

	PVOID ImageBaseAddress = peb.Reserved3[1];
	void* remoteEntryPoint = (void*)Add2Ptr(ImageBaseAddress, imageEntryPointRva);

	char epbuf[0x100];
	ReadProcessMemory(processHandle, remoteEntryPoint, epbuf, 0x100, NULL);
	NtClose(hTarget);
	/**/
	HANDLE threadHandle = 0;
	status = NtCreateThreadEx(&threadHandle,
		THREAD_ALL_ACCESS,
		nullptr,
		processHandle,
		remoteEntryPoint,
		nullptr,
		0,
		0,
		0,
		0,
		nullptr);
	

	WaitForSingleObject(processHandle, INFINITE);

	DWORD targetExitCode = 0;
	GetExitCodeProcess(processHandle, &targetExitCode);

	return 0;
}
