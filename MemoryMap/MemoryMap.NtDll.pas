////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : MemoryMap
//  * Unit Name : MemoryMap.NtDll
//  * Purpose   : Декларации необходимых функций и типов из NTDLL.DLL
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2013.
//  * Version   : 1.0
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

// Размеры структур должны быть выравнены
{$A8}

unit MemoryMap.NtDll;

interface

uses
  Winapi.Windows;

const
  ntdll = 'ntdll.dll';

  STATUS_SUCCESS = 0;

type
  NTSTATUS = DWORD;

  UNICODE_STRING = record
    Length: WORD;
    MaximumLength: WORD;
    Buffer: PWideChar;
  end;
  PUNICODE_STRING = ^UNICODE_STRING;

  TUNICODE_STRING = packed record
    Length : WORD;
    MaximumLength : WORD;
    Buffer : array [0..MAX_PATH - 1] of WideChar;
  end;

  POBJECT_NAME_INFORMATION = ^TOBJECT_NAME_INFORMATION;
  TOBJECT_NAME_INFORMATION = packed record
    Name : TUNICODE_STRING;
  end;

  OBJECT_ATTRIBUTES = record
    Length: ULONG;
    RootDirectory: THandle;
    ObjectName: PUNICODE_STRING;
    Attributes: ULONG;
    SecurityDescriptor: Pointer;
    SecurityQualityOfService: Pointer;
  end;
  POBJECT_ATTRIBUTES = ^OBJECT_ATTRIBUTES;

  IO_STATUS_BLOCK = record
    case integer of
      0:
       (Status: DWORD);
      1:
       (Pointer: Pointer;
        Information: ULONG);
  end;
  PIO_STATUS_BLOCK = ^IO_STATUS_BLOCK;

  procedure RtlInitUnicodeString(
    DestinationString : PUNICODE_STRING;
    SourceString : LPCWSTR); stdcall; external ntdll;

  function ZwOpenFile(FileHandle: PHANDLE; DesiredAccess: ACCESS_MASK;
    ObjectAttributes: POBJECT_ATTRIBUTES; IoStatusBlock: PIO_STATUS_BLOCK;
    ShareAccess: ULONG; OpenOptions: ULONG): NTSTATUS; stdcall; external ntdll;

  function ZwClose(AHandle: THandle): NTSTATUS; stdcall; external ntdll;

  function NtQueryObject(ObjectHandle: THandle;
    ObjectInformationClass: DWORD; ObjectInformation: Pointer;
    ObjectInformationLength: ULONG;
    ReturnLength: PDWORD): NTSTATUS; stdcall; external ntdll;

type
  WOW64_POINTER = ULONG;

  UNICODE_STRING32 = record
    Length: USHORT;
    MaximumLength: USHORT;
    Buffer: ULONG;
  end;

  LIST_ENTRY_32 = record
    FLink, BLink: ULONG;
  end;

  PLIST_ENTRY = ^LIST_ENTRY;
  LIST_ENTRY = record
    FLink, BLink: PLIST_ENTRY;
  end;


const
  FLS_MAXIMUM_AVAILABLE = 128;

type
  PWOW64_PEB = ^TWOW64_PEB;
  TWOW64_PEB = record
    InheritedAddressSpace: BOOLEAN;
    ReadImageFileExecOptions: BOOLEAN;
    BeingDebugged: BOOLEAN;
    BitField: BOOLEAN;
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsLegacyProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN SpareBits : 1;
        }
    Mutant: WOW64_POINTER;
    ImageBaseAddress: WOW64_POINTER;
    LoaderData: WOW64_POINTER;
    ProcessParameters: WOW64_POINTER;
    SubSystemData: WOW64_POINTER;
    ProcessHeap: WOW64_POINTER;
    FastPebLock: WOW64_POINTER;
    AtlThunkSListPtr: WOW64_POINTER;
    IFEOKey: WOW64_POINTER;
    EnvironmentUpdateCount: ULONG;
    UserSharedInfoPtr: WOW64_POINTER;
    SystemReserved: ULONG;
    AtlThunkSListPtr32: ULONG;
    ApiSetMap: WOW64_POINTER;
    TlsExpansionCounter: ULONG;
    TlsBitmap: WOW64_POINTER;
    TlsBitmapBits: array[0..1] of ULONG;
    ReadOnlySharedMemoryBase: WOW64_POINTER;
    HotpatchInformation: WOW64_POINTER;
    ReadOnlyStaticServerData: WOW64_POINTER;
    AnsiCodePageData: WOW64_POINTER;
    OemCodePageData: WOW64_POINTER;
    UnicodeCaseTableData: WOW64_POINTER;

    KeNumberOfProcessors: ULONG;
    NtGlobalFlag: ULONG;

    CriticalSectionTimeout: LARGE_INTEGER;
    HeapSegmentReserve: WOW64_POINTER;
    HeapSegmentCommit: WOW64_POINTER;
    HeapDeCommitTotalFreeThreshold: WOW64_POINTER;
    HeapDeCommitFreeBlockThreshold: WOW64_POINTER;

    NumberOfHeaps: ULONG;
    MaximumNumberOfHeaps: ULONG;
    ProcessHeaps: WOW64_POINTER;

    GdiSharedHandleTable: WOW64_POINTER;
    ProcessStarterHelper: WOW64_POINTER;
    GdiDCAttributeList: ULONG;

    LoaderLock: WOW64_POINTER;

    NtMajorVersion: ULONG;
    NtMinorVersion: ULONG;
    NtBuildNumber: USHORT;
    NtCSDVersion: USHORT;
    PlatformId: ULONG;
    Subsystem: ULONG;
    MajorSubsystemVersion: ULONG;
    MinorSubsystemVersion: ULONG;
    AffinityMask: WOW64_POINTER;
    GdiHandleBuffer: array [0..33] of ULONG;
    PostProcessInitRoutine: WOW64_POINTER;

    TlsExpansionBitmap: WOW64_POINTER;
    TlsExpansionBitmapBits: array [0..31] of ULONG;

    SessionId: ULONG;

    AppCompatFlags: ULARGE_INTEGER;
    AppCompatFlagsUser: ULARGE_INTEGER;
    pShimData: WOW64_POINTER;
    AppCompatInfo: WOW64_POINTER;

    CSDVersion: UNICODE_STRING32;

    ActivationContextData: WOW64_POINTER;
    ProcessAssemblyStorageMap: WOW64_POINTER;
    SystemDefaultActivationContextData: WOW64_POINTER;
    SystemAssemblyStorageMap: WOW64_POINTER;

    MinimumStackCommit: WOW64_POINTER;

    FlsCallback: WOW64_POINTER;
    FlsListHead: LIST_ENTRY_32;
    FlsBitmap: WOW64_POINTER;
    FlsBitmapBits: array [1..FLS_MAXIMUM_AVAILABLE div SizeOf(ULONG) * 8] of ULONG;
    FlsHighIndex: ULONG;

    WerRegistrationData: WOW64_POINTER;
    WerShipAssertPtr: WOW64_POINTER;
    pContextData: WOW64_POINTER;
    pImageHeaderHash: WOW64_POINTER;

    TracingFlags: ULONG;
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        }
    CsrServerReadOnlySharedMemoryBase: ULONGLONG;
  end;

  RTL_DRIVE_LETTER_CURDIR = record
    Flags: Word;
    Length: Word;
    TimeStamp: ULONG;
    DosPath: UNICODE_STRING;
  end;

  PRTL_USER_PROCESS_PARAMETERS = ^RTL_USER_PROCESS_PARAMETERS;
  RTL_USER_PROCESS_PARAMETERS = record
    MaximumLength: ULONG;
    Length: ULONG;
    Flags: ULONG;
    DebugFlags: ULONG;
    ConsoleHandle: PVOID;
    ConsoleFlags: ULONG;
    StdInputHandle: PVOID;
    StdOutputHandle: PVOID;
    StdErrorHandle: PVOID;
    CurrentDirectoryPath: UNICODE_STRING;
    CurrentDirectoryHandle: PVOID;
    DllPath: UNICODE_STRING;
    ImagePathName: UNICODE_STRING;
    CommandLine: UNICODE_STRING;
    Environment: PVOID;
    StartingPositionLeft: ULONG;
    StartingPositionTop: ULONG;
    Width: ULONG;
    Height: ULONG;
    CharWidth: ULONG;
    CharHeight: ULONG;
    ConsoleTextAttributes: ULONG;
    WindowFlags: ULONG;
    ShowWindowFlags: ULONG;
    WindowTitle: UNICODE_STRING;
    DesktopName: UNICODE_STRING;
    ShellInfo: UNICODE_STRING;
    RuntimeData: UNICODE_STRING;
    DLCurrentDirectory: array [0..31] of RTL_DRIVE_LETTER_CURDIR;
    EnvironmentSize: ULONG;
  end;

  KSPIN_LOCK = ULONG_PTR;
  PPEBLOCKROUTINE = ULONG_PTR;

  HANDLE = THandle;

  PPEB = ^TPEB;
  TPEB = record
    InheritedAddressSpace: BOOLEAN;
    ReadImageFileExecOptions: BOOLEAN;
    BeingDebugged: BOOLEAN;
    BitField: BOOLEAN;
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsLegacyProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN SpareBits : 1;
        }
    Mutant: HANDLE;
    ImageBaseAddress: PVOID;
    LoaderData: PVOID;
    ProcessParameters: PRTL_USER_PROCESS_PARAMETERS;
    SubSystemData: PVOID;
    ProcessHeap: PVOID;
    FastPebLock: PRTLCriticalSection;
    AtlThunkSListPtr: PVOID;
    IFEOKey: PVOID;
    EnvironmentUpdateCount: ULONG;
    UserSharedInfoPtr: PVOID;
    SystemReserved: ULONG;
    AtlThunkSListPtr32: ULONG;
    ApiSetMap: PVOID;
    TlsExpansionCounter: ULONG;
    TlsBitmap: PVOID;
    TlsBitmapBits: array[0..1] of ULONG;
    ReadOnlySharedMemoryBase: PVOID;
    HotpatchInformation: PVOID;
    ReadOnlyStaticServerData: PPVOID;
    AnsiCodePageData: PVOID;
    OemCodePageData: PVOID;
    UnicodeCaseTableData: PVOID;

    KeNumberOfProcessors: ULONG;
    NtGlobalFlag: ULONG;

    CriticalSectionTimeout: LARGE_INTEGER;
    HeapSegmentReserve: SIZE_T;
    HeapSegmentCommit: SIZE_T;
    HeapDeCommitTotalFreeThreshold: SIZE_T;
    HeapDeCommitFreeBlockThreshold: SIZE_T;

    NumberOfHeaps: ULONG;
    MaximumNumberOfHeaps: ULONG;
    ProcessHeaps: PPVOID;

    GdiSharedHandleTable: PVOID;
    ProcessStarterHelper: PVOID;
    GdiDCAttributeList: ULONG;

    LoaderLock: PRTLCriticalSection;

    NtMajorVersion: ULONG;
    NtMinorVersion: ULONG;
    NtBuildNumber: USHORT;
    NtCSDVersion: USHORT;
    PlatformId: ULONG;
    Subsystem: ULONG;
    MajorSubsystemVersion: ULONG;
    MinorSubsystemVersion: ULONG;
    AffinityMask: ULONG_PTR;
    {$IFDEF WIN32}
    GdiHandleBuffer: array [0..33] of ULONG;
    {$ELSE}
    GdiHandleBuffer: array [0..59] of ULONG;
    {$ENDIF}
    PostProcessInitRoutine: PVOID;

    TlsExpansionBitmap: PVOID;
    TlsExpansionBitmapBits: array [0..31] of ULONG;

    SessionId: ULONG;

    AppCompatFlags: ULARGE_INTEGER;
    AppCompatFlagsUser: ULARGE_INTEGER;
    pShimData: PVOID;
    AppCompatInfo: PVOID;

    CSDVersion: UNICODE_STRING;

    ActivationContextData: PVOID;
    ProcessAssemblyStorageMap: PVOID;
    SystemDefaultActivationContextData: PVOID;
    SystemAssemblyStorageMap: PVOID;

    MinimumStackCommit: SIZE_T;

    FlsCallback: PPVOID;
    FlsListHead: LIST_ENTRY;
    FlsBitmap: PVOID;
    FlsBitmapBits: array [1..FLS_MAXIMUM_AVAILABLE div SizeOf(ULONG) * 8] of ULONG;
    FlsHighIndex: ULONG;

    WerRegistrationData: PVOID;
    WerShipAssertPtr: PVOID;
    pContextData: PVOID;
    pImageHeaderHash: PVOID;

    TracingFlags: ULONG;
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        }
    CsrServerReadOnlySharedMemoryBase: ULONGLONG;
  end;

  PPROCESS_BASIC_INFORAMTION = ^PROCESS_BASIC_INFORMATION;
  PROCESS_BASIC_INFORMATION = record
    ExitStatus: LONG;
    PebBaseAddress: PPEB;
    AffinityMask: ULONG_PTR;
    BasePriority: LONG;
    uUniqueProcessId: ULONG_PTR;
    uInheritedFromUniqueProcessId: ULONG_PTR;
  end;

  function NtQueryInformationProcess(ProcessHandle: Cardinal;
    ProcessInformationClass: Integer;
    ProcessInformation: Pointer;
    ProcessInformationLength: Cardinal;
    ReturnLength: PCardinal): NTSTATUS; stdcall; external ntdll;

const
  RTL_QUERY_PROCESS_HEAP_SUMMARY = $00000004;
  RTL_QUERY_PROCESS_HEAP_ENTRIES = $00000010;

type
  TSettableAndTag = record
    Settable: SIZE_T;
    Tag: ULONG;
  end;

  TCommittedSizeAndBlock = record
    CommittedSize: SIZE_T;
    FirstBlock: PVOID;
  end;

  THeapEntryUnion = record
  case Integer of
    0: (s1: TSettableAndTag);
    1: (s2: TCommittedSizeAndBlock);
  end;

  _RTL_HEAP_ENTRY = record
    Size: SIZE_T;
    Flags: USHORT;
    AllocatorBackTraceIndex: USHORT;
    u: THeapEntryUnion;
  end;
  RTL_HEAP_ENTRY = _RTL_HEAP_ENTRY;
  PRTL_HEAP_ENTRY = ^RTL_HEAP_ENTRY;
  TRtrHeapEntry = RTL_HEAP_ENTRY;
  PRtrHeapEntry = PRTL_HEAP_ENTRY;

  _RTL_HEAP_INFORMATION = record
    BaseAddress: PVOID;
    Flags: ULONG;
    EntryOverhead: USHORT;
    CreatorBackTraceIndex: USHORT;
    BytesAllocated: SIZE_T;
    BytesCommitted: SIZE_T;
    NumberOfTags: ULONG;
    NumberOfEntries: ULONG;
    NumberOfPseudoTags: ULONG;
    PseudoTagGranularity: ULONG;
    Reserved: array [0..4] of ULONG;
    Tags: PVOID;
    Entries: PRTL_HEAP_ENTRY;
  end;
  RTL_HEAP_INFORMATION = _RTL_HEAP_INFORMATION;
  PRTL_HEAP_INFORMATION = ^RTL_HEAP_INFORMATION;
  TRtlHeapInformation = RTL_HEAP_INFORMATION;
  PRtlHeapInformation = ^TRtlHeapInformation;

  _RTL_PROCESS_HEAPS = record
    NumberOfHeaps: ULONG;
    Heaps: array [0..0] of RTL_HEAP_INFORMATION;
  end;
  RTL_PROCESS_HEAPS = _RTL_PROCESS_HEAPS;
  PRTL_PROCESS_HEAPS = ^RTL_PROCESS_HEAPS;
  TRtlProcessHeaps = RTL_PROCESS_HEAPS;
  PRtlProcessHeaps = ^TRtlProcessHeaps;

  _RTL_DEBUG_INFORMATION = record
    SectionHandleClient: HANDLE;
    ViewBaseClient: PVOID;
    ViewBaseTarget: PVOID;
    ViewBaseDelta: ULONG_PTR;
    EventPairClient: HANDLE;
    EventPairTarget: PVOID;
    TargetProcessId: HANDLE;
    TargetThreadHandle: HANDLE;
    Flags: SIZE_T;
    OffsetFree: SIZE_T;
    CommitSize: SIZE_T;
    ViewSize: SIZE_T;
    {
    union
    {
        PRTL_PROCESS_MODULES Modules;
        PRTL_PROCESS_MODULE_INFORMATION_EX ModulesEx;
    }
    Modules: PVOID;
    BackTraces: PVOID; // PRTL_PROCESS_BACKTRACES
    Heaps: PRTL_PROCESS_HEAPS;
    Locks: PVOID; // PRTL_PROCESS_LOCKS
    SpecificHeap: HANDLE;
    TargetProcessHandle: HANDLE;
    VerifierOptions: PVOID; //RTL_PROCESS_VERIFIER_OPTIONS;
    ProcessHeap: HANDLE;
    CriticalSectionHandle: HANDLE;
    CriticalSectionOwnerThread: HANDLE;
    Reserved: array [0..3] of PVOID;
  end;
  RTL_DEBUG_INFORMATION = _RTL_DEBUG_INFORMATION;
  PRTL_DEBUG_INFORMATION = ^RTL_DEBUG_INFORMATION;
  TRtlDebugInformation = RTL_DEBUG_INFORMATION;
  PRtlDebugInformation = ^TRtlDebugInformation;

  function RtlCreateQueryDebugBuffer(
    Size: ULONG; EventPair: BOOLEAN): PRtlDebugInformation; stdcall;
    external ntdll;

  function RtlQueryProcessDebugInformation(
    ProcessId: ULONG; DebugInfoClassMask: ULONG;
    DebugBuffer: PRtlDebugInformation): NTSTATUS; stdcall; external ntdll;

  function RtlDestroyQueryDebugBuffer(
    DebugBuffer: PRtlDebugInformation): NTSTATUS; stdcall; external ntdll;

type
  _CLIENT_ID = record
    UniqueProcess: HANDLE;
    UniqueThread: HANDLE;
  end;
  CLIENT_ID = _CLIENT_ID;
  PCLIENT_ID = ^CLIENT_ID;
  TClientID = CLIENT_ID;
  PClientID = ^TClientID;

  PNT_TIB = ^_NT_TIB;
  _NT_TIB = record
    ExceptionList: Pointer; // ^_EXCEPTION_REGISTRATION_RECORD
    StackBase,
      StackLimit,
      SubSystemTib: Pointer;
    case Integer of
      0: (
        FiberData: Pointer
        );
      1: (
        Version: ULONG;
        ArbitraryUserPointer: Pointer;
        Self: PNT_TIB;
        )
  end;
  NT_TIB = _NT_TIB;
  PPNT_TIB = ^PNT_TIB;

  KPRIORITY = LONG;

  _THREAD_BASIC_INFORMATION = record // Information Class 0
    ExitStatus: NTSTATUS;
    TebBaseAddress: PNT_TIB;
    ClientId: CLIENT_ID;
    AffinityMask: KAFFINITY;
    Priority: KPRIORITY;
    BasePriority: KPRIORITY;
  end;
  THREAD_BASIC_INFORMATION = _THREAD_BASIC_INFORMATION;
  PTHREAD_BASIC_INFORMATION = ^THREAD_BASIC_INFORMATION;
  TThreadBasicInformation = THREAD_BASIC_INFORMATION;
  PThreadBasicInformation = ^TThreadBasicInformation;

  function OpenThread(dwDesiredAccess: DWORD; bInheritHandle: BOOL;
    dwThreadId: DWORD): THandle; stdcall; external kernel32;

  function NtQueryInformationThread(ThreadHandle: THandle;
    ThreadInformationClass: DWORD;
    ThreadInformation: Pointer; ThreadInformationLength: ULONG;
    ReturnLength: PULONG): NTSTATUS; stdcall; external ntdll;

implementation

end.
