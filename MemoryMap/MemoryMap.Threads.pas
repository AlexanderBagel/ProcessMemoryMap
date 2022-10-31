////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : MemoryMap
//  * Unit Name : MemoryMap.Threads.pas
//  * Purpose   : Класс собирает данные о потоках процесса.
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

unit MemoryMap.Threads;

interface

uses
  Winapi.Windows,
  Generics.Collections,
  Winapi.TlHelp32,
  Winapi.ImageHlp,
  MemoryMap.NtDll,
  MemoryMap.Utils;

type
  TThreadInfo = (tiNoData, tiExceptionList, tiStackBase,
    tiStackLimit, tiTEB, tiThreadProc, tiOleTlsData);

const
  ThreadInfoStr: array [TThreadInfo] of string = ('UnknownThreadData',
    'Thread Exception List', 'Thread Stack Base', 'Thread Stack Limit',
    'TEB', 'ThreadProc', 'OleTlsData');

type
  TThreadData = record
    Flag: TThreadInfo;
    ThreadID: Integer;
    Address: Pointer;
    Wow64: Boolean;
  end;

type
  PWow64Context = ^TWow64Context;
  TWow64Context = record
    ContextFlags: DWORD;
    Dr0: DWORD;
    Dr1: DWORD;
    Dr2: DWORD;
    Dr3: DWORD;
    Dr6: DWORD;
    Dr7: DWORD;
    FloatSave: TFloatingSaveArea;
    SegGs: DWORD;
    SegFs: DWORD;
    SegEs: DWORD;
    SegDs: DWORD;
    Edi: DWORD;
    Esi: DWORD;
    Ebx: DWORD;
    Edx: DWORD;
    Ecx: DWORD;
    Eax: DWORD;
    Ebp: DWORD;
    Eip: DWORD;
    SegCs: DWORD;
    EFlags: DWORD;
    Esp: DWORD;
    SegSs: DWORD;
    ExtendedRegisters: array[0..MAXIMUM_SUPPORTED_EXTENSION-1] of Byte;
  end;

  TWOW64_NT_TIB = record
    ExceptionList,
    StackBase,
    StackLimit,
    SubSystemTib,
    Version,
    ArbitraryUserPointer,
    Self: DWORD;
  end;

  LPADDRESS64 = ^ADDRESS64;
  {$EXTERNALSYM PADDRESS64}
  _tagADDRESS64 = record
    Offset: DWORD64;
    Segment: WORD;
    Mode: ADDRESS_MODE;
  end;
  {$EXTERNALSYM _tagADDRESS64}
  ADDRESS64 = _tagADDRESS64;
  {$EXTERNALSYM ADDRESS64}
  TAddress64 = ADDRESS64;
  PAddress64 = LPADDRESS64;

  PKDHELP64 = ^KDHELP64;
  {$EXTERNALSYM PKDHELP64}
  _KDHELP64 = record
    Thread: DWORD64;
    ThCallbackStack: DWORD;
    ThCallbackBStore: DWORD;
    NextCallback: DWORD;
    FramePointer: DWORD;
    KiCallUserMode: DWORD64;
    KeUserCallbackDispatcher: DWORD64;
    SystemRangeStart: DWORD64;
    KiUserExceptionDispatcher: DWORD64;
    StackBase: DWORD64;
    StackLimit: DWORD64;
    Reserved: array [0..4] of DWORD64;
  end;
  {$EXTERNALSYM _KDHELP64}
  KDHELP64 = _KDHELP64;
  {$EXTERNALSYM KDHELP64}
  TKdHelp64 = KDHELP64;

  LPSTACKFRAME64 = ^STACKFRAME64;
  {$EXTERNALSYM LPSTACKFRAME64}
  _tagSTACKFRAME64 = record
    AddrPC: ADDRESS64; // program counter
    AddrReturn: ADDRESS64; // return address
    AddrFrame: ADDRESS64; // frame pointer
    AddrStack: ADDRESS64; // stack pointer
    AddrBStore: ADDRESS64; // backing store pointer
    FuncTableEntry: PVOID; // pointer to pdata/fpo or NULL
    Params: array [0..3] of DWORD64; // possible arguments to the function
    Far: BOOL; // WOW far call
    Virtual: BOOL; // is this a virtual frame?
    Reserved: array [0..2] of DWORD64;
    KdHelp: KDHELP64;
  end;
  {$EXTERNALSYM _tagSTACKFRAME64}
  STACKFRAME64 = _tagSTACKFRAME64;
  {$EXTERNALSYM STACKFRAME64}
  TStackFrame64 = STACKFRAME64;
  PStackFrame64 = LPSTACKFRAME64;

  TThreadStackEntry = record
    ThreadID: Integer;
    Data: TStackFrame64;
    FuncName: ShortString;
    Wow64: Boolean;
    procedure SetFuncName(const Value: string);
  end;

  TSEHEntry = record
    ThreadID: Integer;
    Address: Pointer;
    Previous: Pointer;
    Handler: Pointer;
    HandlerName: ShortString;
    Wow64: Boolean;
    procedure SetHandlerName(const Value: string);
  end;

  TThreads = class
  private
    FThreadData: TList<TThreadData>;
    FThreadStackEntries: TList<TThreadStackEntry>;
    FSEH: TList<TSEHEntry>;
  protected
    procedure Add(hProcess: THandle;
      Flag: TThreadInfo; Address: Pointer; ID: Integer;
      Wow64: Boolean);
    function ConvertStackFrameToStackFrame64(Value: TStackFrame): TStackFrame64;
    procedure Update(PID: Cardinal; hProcess: THandle);
    procedure GetWow64ThreadCallStack32(hProcess, hThread: THandle; ID: Integer);
    procedure GetThreadCallStack(hProcess, hThread: THandle; ID: Integer);
    procedure GetThreadSEHFrames(hProcess: THandle; InitialAddr: Pointer;
      ID: Integer; Wow64: Boolean);
  public
    constructor Create; overload;
    constructor Create(PID: Cardinal; hProcess: THandle); overload;
    destructor Destroy; override;
    property SEHEntries: TList<TSEHEntry> read FSEH;
    property ThreadData: TList<TThreadData> read FThreadData;
    property ThreadStackEntries: TList<TThreadStackEntry> read FThreadStackEntries;
  end;

implementation

uses
  MemoryMap.Core;


{ TThreadStackEntry }

procedure TThreadStackEntry.SetFuncName(const Value: string);
begin
  FuncName := ShortString(Value);
end;

{ TThreadSehEntry }

procedure TSEHEntry.SetHandlerName(const Value: string);
begin
  HandlerName := ShortString(Value);
end;

{ TThreads }

procedure TThreads.Add(hProcess: THandle;
  Flag: TThreadInfo; Address: Pointer; ID: Integer; Wow64: Boolean);
var
  ThreadData: TThreadData;
begin
  if Address = nil then Exit;
  ThreadData.Flag := Flag;
  ThreadData.ThreadID := ID;
  ThreadData.Address := Address;
  ThreadData.Wow64 := Wow64;
  FThreadData.Add(ThreadData);
end;

function TThreads.ConvertStackFrameToStackFrame64(
  Value: TStackFrame): TStackFrame64;
begin
  Result.AddrPC.Offset := Value.AddrPC.Offset;
  Result.AddrPC.Segment := Value.AddrPC.Segment;
  Result.AddrPC.Mode := Value.AddrPC.Mode;
  Result.AddrReturn.Offset := Value.AddrReturn.Offset;
  Result.AddrReturn.Segment := Value.AddrReturn.Segment;
  Result.AddrReturn.Mode := Value.AddrPC.Mode;
  Result.AddrFrame.Offset := Value.AddrFrame.Offset;
  Result.AddrFrame.Segment := Value.AddrFrame.Segment;
  Result.AddrFrame.Mode := Value.AddrFrame.Mode;
  Result.AddrStack.Offset := Value.AddrStack.Offset;
  Result.AddrStack.Segment := Value.AddrStack.Segment;
  Result.AddrStack.Mode := Value.AddrStack.Mode;
  Result.AddrBStore.Offset := Value.AddrBStore.Offset;
  Result.AddrBStore.Segment := Value.AddrBStore.Segment;
  Result.AddrBStore.Mode := Value.AddrBStore.Mode;
  Result.FuncTableEntry := Value.FuncTableEntry;
  Result.Params[0] := Value.Params[0];
  Result.Params[1] := Value.Params[1];
  Result.Params[2] := Value.Params[2];
  Result.Params[3] := Value.Params[3];
  Result.Far := Value._Far;
  Result.Virtual := Value._Virtual;
  Result.KdHelp.Thread := Value.KdHelp.Thread;
  Result.KdHelp.ThCallbackStack := Value.KdHelp.ThCallbackStack;
  Result.KdHelp.ThCallbackBStore := Value.KdHelp.ThCallbackBStore;
  Result.KdHelp.NextCallback := Value.KdHelp.NextCallback;
  Result.KdHelp.FramePointer := Value.KdHelp.FramePointer;
  Result.KdHelp.KiCallUserMode := Value.KdHelp.KiCallUserMode;
  Result.KdHelp.KeUserCallbackDispatcher := Value.KdHelp.KeUserCallbackDispatcher;
  Result.KdHelp.SystemRangeStart := Value.KdHelp.SystemRangeStart;
  Result.KdHelp.KiUserExceptionDispatcher := Value.KdHelp.KiUserExceptionDispatcher;
  Result.KdHelp.StackBase := Value.KdHelp.StackBase;
  Result.KdHelp.StackLimit := Value.KdHelp.StackLimit;
end;

constructor TThreads.Create(PID: Cardinal; hProcess: THandle);
begin
  Create;
  Update(PID, hProcess);
end;

constructor TThreads.Create;
begin
  FSEH := TList<TSEHEntry>.Create;
  FThreadData := TList<TThreadData>.Create;
  FThreadStackEntries := TList<TThreadStackEntry>.Create;
end;

destructor TThreads.Destroy;
begin
  FSEH.Free;
  FThreadStackEntries.Free;
  FThreadData.Free;
  inherited;
end;

  function StackWalk64(MachineType: DWORD; hProcess: HANDLE; hThread: HANDLE;
    var StackFrame: STACKFRAME64; ContextRecord: PVOID;
    ReadMemoryRoutine: PVOID; FunctionTableAccessRoutine: PVOID;
    GetModuleBaseRoutine: PVOID; TranslateAddress: PVOID): BOOL; stdcall;
    external 'imagehlp.dll';

procedure TThreads.GetThreadCallStack(hProcess, hThread: THandle;
  ID: Integer);
var
  {$IFDEF WIN32}
  StackFrame: TStackFrame;
  {$ELSE}
  StackFrame: TStackFrame64;
  {$ENDIF}
  ThreadContext: PContext;
  MachineType: DWORD;
  ThreadShackEntry: TThreadStackEntry;
begin
  ZeroMemory(@ThreadShackEntry, SizeOf(TThreadStackEntry));

  // ThreadContext должен быть выравнен, поэтому используем VirtualAlloc
  // которая автоматически выделит память выровненую по началу страницы
  // в противном случае получим ERROR_NOACCESS (998)
  ThreadContext := VirtualAlloc(nil, SizeOf(TContext), MEM_COMMIT, PAGE_READWRITE);
  try
    ThreadContext^.ContextFlags := CONTEXT_FULL;
    if not GetThreadContext(hThread, ThreadContext^) then
      Exit;

    ZeroMemory(@StackFrame, SizeOf(TStackFrame));
    StackFrame.AddrPC.Mode := AddrModeFlat;
    StackFrame.AddrStack.Mode := AddrModeFlat;
    StackFrame.AddrFrame.Mode := AddrModeFlat;
    {$IFDEF WIN32}
    StackFrame.AddrPC.Offset := ThreadContext.Eip;
    StackFrame.AddrStack.Offset := ThreadContext.Esp;
    StackFrame.AddrFrame.Offset := ThreadContext.Ebp;
    MachineType := IMAGE_FILE_MACHINE_I386;
    {$ELSE}
    StackFrame.AddrPC.Offset := ThreadContext.Rip;
    StackFrame.AddrStack.Offset := ThreadContext.Rsp;
    StackFrame.AddrFrame.Offset := ThreadContext.Rbp;
    MachineType := IMAGE_FILE_MACHINE_AMD64;
    {$ENDIF}

    while True do
    begin

      {$IFDEF WIN32}
      if not StackWalk(MachineType, hProcess, hThread, @StackFrame,
        ThreadContext, nil, nil, nil, nil) then
        Break;
      {$ELSE}
      if not StackWalk64(MachineType, hProcess, hThread, StackFrame,
        ThreadContext, nil, nil, nil, nil) then
        Break;
      {$ENDIF}

      if StackFrame.AddrPC.Offset <= 0 then Break;

      ThreadShackEntry.ThreadID := ID;
      {$IFDEF WIN32}
      ThreadShackEntry.Data := ConvertStackFrameToStackFrame64(StackFrame);
      {$ELSE}
      ThreadShackEntry.Data := StackFrame;
      {$ENDIF}
      ThreadShackEntry.Wow64 := False;
      ThreadStackEntries.Add(ThreadShackEntry);
    end;

  finally
    VirtualFree(ThreadContext, SizeOf(TContext), MEM_FREE);
  end;
end;

procedure TThreads.GetWow64ThreadCallStack32(hProcess, hThread: THandle;
  ID: Integer);
const
  ThreadWow64Context = 29;
var
  StackFrame: TStackFrame64;
  ThreadContext: PWow64Context;
  ThreadShackEntry: TThreadStackEntry;
begin
  ZeroMemory(@ThreadShackEntry, SizeOf(TThreadStackEntry));

  // ThreadContext должен быть выравнен, поэтому используем VirtualAlloc
  // которая автоматически выделит память выровненую по началу страницы
  // в противном случае получим ERROR_NOACCESS (998)
  ThreadContext := VirtualAlloc(nil, SizeOf(TWow64Context), MEM_COMMIT, PAGE_READWRITE);
  try
    ThreadContext^.ContextFlags := CONTEXT_FULL;

    if NtQueryInformationThread(hThread, ThreadWow64Context, ThreadContext,
      SizeOf(TWow64Context), nil) <> STATUS_SUCCESS then Exit;

    ZeroMemory(@StackFrame, SizeOf(TStackFrame));
    StackFrame.AddrPC.Mode := AddrModeFlat;
    StackFrame.AddrStack.Mode := AddrModeFlat;
    StackFrame.AddrFrame.Mode := AddrModeFlat;
    StackFrame.AddrPC.Offset := ThreadContext.Eip;
    StackFrame.AddrStack.Offset := ThreadContext.Esp;
    StackFrame.AddrFrame.Offset := ThreadContext.Ebp;

    while StackWalk64(IMAGE_FILE_MACHINE_I386, hProcess, hThread, StackFrame,
      ThreadContext, nil, nil, nil, nil) do
    begin
      if StackFrame.AddrPC.Offset <= 0 then Break;
      ThreadShackEntry.ThreadID := ID;
      ThreadShackEntry.Data := StackFrame;
      ThreadShackEntry.Wow64 := True;
      ThreadStackEntries.Add(ThreadShackEntry);
    end;

  finally
    VirtualFree(ThreadContext, SizeOf(TContext), MEM_FREE);
  end;
end;

procedure TThreads.GetThreadSEHFrames(hProcess: THandle; InitialAddr: Pointer;
  ID: Integer; Wow64: Boolean);
type
  EXCEPTION_REGISTRATION = record
    prev, handler: Pointer;
  end;
  PWOW64_EXCEPTION_REGISTRATION = ^WOW64_EXCEPTION_REGISTRATION;
  WOW64_EXCEPTION_REGISTRATION = record
    prev, handler: DWORD;
  end;
var
  ER: EXCEPTION_REGISTRATION;
  lpNumberOfBytesRead: NativeUInt;
  SEHEntry: TSEHEntry;
begin
  while ReadProcessMemory(hProcess, InitialAddr, @ER,
    SizeOf(EXCEPTION_REGISTRATION), lpNumberOfBytesRead) do
  begin
    SEHEntry.ThreadID := ID;
    SEHEntry.Address := InitialAddr;
    if Wow64 then
    begin
      SEHEntry.Previous := Pointer(PWOW64_EXCEPTION_REGISTRATION(@ER)^.prev);
      SEHEntry.Handler := Pointer(PWOW64_EXCEPTION_REGISTRATION(@ER)^.handler);
    end
    else
    begin
      SEHEntry.Previous := ER.prev;
      SEHEntry.Handler := ER.handler;
    end;
    SEHEntry.Wow64 := Wow64;
    SEHEntries.Add(SEHEntry);
    InitialAddr := SEHEntry.Previous;
    if DWORD(InitialAddr) <= 0 then Break;
  end;
end;

procedure TThreads.Update(PID: Cardinal; hProcess: THandle);
const
  THREAD_GET_CONTEXT = 8;
  THREAD_SUSPEND_RESUME = 2;
  THREAD_QUERY_INFORMATION = $40;
  ThreadBasicInformation = 0;
  ThreadQuerySetWin32StartAddress = 9;
var
  hSnap, hThread: THandle;
  ThreadEntry: TThreadEntry32;
  TBI: TThreadBasicInformation;
  TIB: NT_TIB;
  lpNumberOfBytesRead: NativeUInt;
  ThreadStartAddress, pOleTlsData: Pointer;
  Wow64: Boolean;
  {$IFDEF WIN64}
  WOW64_NT_TIB: TWOW64_NT_TIB;
  {$ENDIF}
begin
  {$IFDEF WIN64}
  Wow64 := True;
  {$ELSE}
  Wow64 := False;
  {$ENDIF}

  // Делаем снимок нитей в системе
  hSnap := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, PID);
  if hSnap <> INVALID_HANDLE_VALUE then
  try
    ThreadEntry.dwSize := SizeOf(TThreadEntry32);
    if Thread32First(hSnap, ThreadEntry) then
    repeat
      if ThreadEntry.th32OwnerProcessID <> PID then Continue;

      // Открываем нить
      hThread := OpenThread(THREAD_GET_CONTEXT or
        THREAD_SUSPEND_RESUME or THREAD_QUERY_INFORMATION,
        False, ThreadEntry.th32ThreadID);
      if hThread <> 0 then
      try
        // Получаем адрес ThreadProc()
        if NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress,
          @ThreadStartAddress, SizeOf(ThreadStartAddress), nil) = STATUS_SUCCESS then
          Add(hProcess, tiThreadProc, ThreadStartAddress, ThreadEntry.th32ThreadID, False);
        // Получаем информацию по нити
        if NtQueryInformationThread(hThread, ThreadBasicInformation, @TBI,
          SizeOf(TThreadBasicInformation), nil) = STATUS_SUCCESS then
        begin
          // Читаем из удаленного адресного пространства
          // TIB (Thread Information Block) открытой нити
          if not ReadProcessMemory(hProcess,
            TBI.TebBaseAddress, @TIB, SizeOf(NT_TIB),
            lpNumberOfBytesRead) then Exit;

          // Добавляем в массив адрес стэка
          Add(hProcess, tiStackBase, TIB.StackBase, ThreadEntry.th32ThreadID, False);
          Add(hProcess, tiStackLimit, TIB.StackLimit, ThreadEntry.th32ThreadID, False);
          Add(hProcess, tiTEB, TIB.Self, ThreadEntry.th32ThreadID, False);

          // Адрес структуры OleTlsData хранящей информацию по OLE32 данным
          // находится по фиксированному оффсету $1758
          if ReadProcessMemory(hProcess,
            Pointer(PByte(TBI.TebBaseAddress) + $1758), @pOleTlsData, 8,
            lpNumberOfBytesRead) and Assigned(pOleTlsData) then
            Add(hProcess, tiOleTlsData, pOleTlsData, ThreadEntry.th32ThreadID, False);
        end;
        // Получаем стэк нити
        GetThreadCallStack(hProcess, hThread, ThreadEntry.th32ThreadID);

        {$IFDEF WIN64}
        // то-же самое только для Wow64 нити
        if not IsWow64(hProcess) then Exit;

        // в 64 битном TEB поле TIB.ExceptionList указывает на начало Wow64TEB
        if not ReadProcessMemory(hProcess,
          TIB.ExceptionList, @WOW64_NT_TIB, SizeOf(TWOW64_NT_TIB),
          lpNumberOfBytesRead) then Exit;

        TIB.ExceptionList := Pointer(WOW64_NT_TIB.ExceptionList);
        TIB.StackLimit := Pointer(WOW64_NT_TIB.StackLimit);
        TIB.StackBase := Pointer(WOW64_NT_TIB.StackBase);
        TIB.Self := Pointer(WOW64_NT_TIB.Self);

        // Добавляем в массив адрес стэка
        Add(hProcess, tiStackBase, TIB.StackBase, ThreadEntry.th32ThreadID, True);
        Add(hProcess, tiStackLimit, TIB.StackLimit, ThreadEntry.th32ThreadID, True);
        Add(hProcess, tiTEB, TIB.Self, ThreadEntry.th32ThreadID, True);

        // Адрес структуры OleTlsData хранящей информацию по OLE32 данным
        // находится по фиксированному оффсету $F80
        pOleTlsData := nil;
        if ReadProcessMemory(hProcess,
          Pointer(PByte(TIB.Self) + $F80), @pOleTlsData, 4,
          lpNumberOfBytesRead) and Assigned(pOleTlsData) then
          Add(hProcess, tiOleTlsData, pOleTlsData, ThreadEntry.th32ThreadID, True);

        // Получаем стэк нити
        GetWow64ThreadCallStack32(hProcess, hThread, ThreadEntry.th32ThreadID);
        {$ENDIF}

        // Получаем список SEH фреймов
        GetThreadSEHFrames(hProcess, TIB.ExceptionList,
          ThreadEntry.th32ThreadID, Wow64);
      finally
        CloseHandle(hThread);
      end;
    until not Thread32Next(hSnap, ThreadEntry);
  finally
     CloseHandle(hSnap);
  end;
end;

end.
