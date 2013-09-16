unit MemoryMap.Threads;

interface

uses
  Winapi.Windows,
  Generics.Collections,
  Winapi.TlHelp32,
  MemoryMap.NtDll;

type
  TThreadInfo = (tiNoData, tiExceptionList, tiStackBase,
    tiStackLimit, tiTEB, tiThreadProc);
  TThreadData = record
    Flag: TThreadInfo;
    ThreadID: Integer;
    Address: Pointer;
    Wow64: Boolean;
  end;

  TThreads = class
  private
    FThreadData: TList<TThreadData>;
  protected
    procedure Add(hProcess: THandle;
      Flag: TThreadInfo; Address: Pointer; ID: Integer);
    procedure Update(PID: Cardinal; hProcess: THandle);
  public
    constructor Create; overload;
    constructor Create(PID: Cardinal; hProcess: THandle); overload;
    destructor Destroy; override;
    property ThreadData: TList<TThreadData> read FThreadData;
  end;

implementation

uses
  MemoryMap.Core;

{ TThreads }

procedure TThreads.Add(hProcess: THandle;
  Flag: TThreadInfo; Address: Pointer; ID: Integer);
var
  ThreadData: TThreadData;
begin
  if Address = nil then Exit;
  ThreadData.Flag := Flag;
  ThreadData.ThreadID := ID;
  ThreadData.Address := Address;
  ThreadData.Wow64 := False;
  FThreadData.Add(ThreadData);
end;

constructor TThreads.Create(PID: Cardinal; hProcess: THandle);
begin
  Create;
  Update(PID, hProcess);
end;

constructor TThreads.Create;
begin
  FThreadData := TList<TThreadData>.Create;
end;

destructor TThreads.Destroy;
begin
  FThreadData.Free;
  inherited;
end;

procedure TThreads.Update(PID: Cardinal; hProcess: THandle);
const
  THREAD_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED or SYNCHRONIZE or $3FF;
  ThreadBasicInformation = 0;
  ThreadQuerySetWin32StartAddress = 9;
var
  hSnap, hThread: THandle;
  ThreadEntry: TThreadEntry32;
  TBI: TThreadBasicInformation;
  TIB: NT_TIB;
  lpNumberOfBytesRead: NativeUInt;
  ThreadStartAddress: Pointer;
begin

  // Делаем снимок нитей в системе
  hSnap := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, PID);
  if hSnap <> INVALID_HANDLE_VALUE then
  try
    ThreadEntry.dwSize := SizeOf(TThreadEntry32);
    if Thread32First(hSnap, ThreadEntry) then
    repeat
      if ThreadEntry.th32OwnerProcessID <> PID then Continue;

      // Открываем нить
      hThread := OpenThread(THREAD_ALL_ACCESS,
        False, ThreadEntry.th32ThreadID);
      if hThread <> 0 then
      try
        // Получаем адрес ThreadProc()
        if NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress,
          @ThreadStartAddress, SizeOf(ThreadStartAddress), nil) = STATUS_SUCCESS then
          Add(hProcess, tiThreadProc, ThreadStartAddress, ThreadEntry.th32ThreadID);
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
          Add(hProcess, tiExceptionList, TIB.ExceptionList, ThreadEntry.th32ThreadID);
          Add(hProcess, tiStackBase, TIB.StackBase, ThreadEntry.th32ThreadID);
          Add(hProcess, tiStackLimit, TIB.StackLimit, ThreadEntry.th32ThreadID);
          Add(hProcess, tiTEB, TIB.Self, ThreadEntry.th32ThreadID);
        end;
      finally
        CloseHandle(hThread);
      end;
    until not Thread32Next(hSnap, ThreadEntry);
  finally
     CloseHandle(hSnap);
  end;
end;

end.
