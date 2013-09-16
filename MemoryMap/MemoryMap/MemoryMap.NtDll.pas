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

  PPEB = ^TPEB;
  TPEB = record
    InheritedAddressSpace: UCHAR;
    ReadImageFileExecOptions: UCHAR;
    BeingDebugged: UCHAR;
    Spare: Byte;
    Mutant: PVOID;
    ImageBaseAddress: PVOID;
    LoaderData: PVOID; //PPEB_LDR_DATA;
    ProcessParameters: PRTL_USER_PROCESS_PARAMETERS;
    SubSystemData: PVOID;
    ProcessHeap: PVOID;
    FastPebLock: KSPIN_LOCK;
    FastPebLockRoutine: PPEBLOCKROUTINE;
    FastPebUnlockRoutine: PPEBLOCKROUTINE;
    EnvironmentUpdateCount: ULONG;
    KernelCallbackTable: PPVOID;
    EventLogSection: PVOID;
    EventLog: PVOID;
    FreeList: PVOID; //PPEB_FREE_BLOCK;
    TlsExpansionCounter: ULONG;
    TlsBitmap: PVOID;
    TlsBitmapBits: array[0..1] of ULONG;
    ReadOnlySharedMemoryBase: PVOID;
    ReadOnlySharedMemoryHeap: PVOID;
    ReadOnlyStaticServerData: PVOID;
    InitAnsiCodePageData: PVOID;
    InitOemCodePageData: PVOID;
    InitUnicodeCaseTableData: PVOID;
    KeNumberOfProcessors: ULONG;
    NtGlobalFlag: ULONG;
    Spare2: array[0..3] of Byte;
    MmCriticalSectionTimeout: LARGE_INTEGER;
    MmHeapSegmentReserve: ULONG;
    MmHeapSegmentCommit: ULONG;
    MmHeapDeCommitTotalFreeThreshold: ULONG;
    MmHeapDeCommitFreeBlockThreshold: ULONG;
    NumberOfHeaps: ULONG;
    MaximumNumberOfHeaps: ULONG;
    ProcessHeapsListBuffer: PHANDLE;
    GdiSharedHandleTable: PVOID;
    ProcessStarterHelper: PVOID;
    GdiDCAttributeList: PVOID;
    LoaderLock: KSPIN_LOCK;
    NtMajorVersion: ULONG;
    NtMinorVersion: ULONG;
    NtBuildNumber: USHORT;
    NtCSDVersion: USHORT;
    PlatformId: ULONG;
    Subsystem: ULONG;
    MajorSubsystemVersion: ULONG;
    MinorSubsystemVersion: ULONG;
    AffinityMask: KAFFINITY;
    GdiHandleBuffer: array [0..33] of ULONG;
    PostProcessInitRoutine: ULONG;
    TlsExpansionBitmap: ULONG;
    TlsExpansionBitmapBits: array [0..127] of UCHAR;
    SessionId: ULONG;
    AppCompatFlags: ULARGE_INTEGER;
    CSDVersion: PWORD;
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
  HANDLE = THandle;

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
