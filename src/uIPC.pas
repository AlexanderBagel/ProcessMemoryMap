////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uIPC.pas
//  * Purpose   : Модуль для обмена данными о кучах между процессами
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2013, 2022.
//  * Version   : 1.3.19
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uIPC;

interface

uses
  Windows,
  Messages,
  Classes,
  SysUtils,
  MemoryMap.Heaps;

const
  WM_GETMEMORYMAP = WM_USER + 123;

type
  PRemoteData = ^TRemoteData;
  TRemoteData = packed record
    Address, Size: DWORD;
  end;

  PIPCServerParams = ^TIPCServerParams;
  TIPCServerParams = packed record
    PID: DWORD;
    WndHandle: THandle;
  end;

  TIPCServer = class
  private
    FMMFHandle: THandle;
    FIPCServerParams: TIPCServerParams;
    FMMFName: string;
    FMemoryMapData: array of Byte;
    FRemoteData: TRemoteData;
  protected
    procedure InitFileMapping;
    procedure ReleaseFileMapping;
    procedure WndProc(var Message: TMessage);
  public
    constructor Create;
    destructor Destroy; override;
    property MMFName: string read FMMFName;
    property WndHandle: THandle read FIPCServerParams.WndHandle;
  end;

  function GetWin32MemoryMap(PID: DWORD; const MMFName: string): TMemoryStream;
  procedure LoadHeaps(Value: THeap; AStream: TStream);

implementation

procedure SaveHeaps(Value: THeap; AStream: TStream);
var
  HD: THeapData;
begin
  for HD in Value.Data do
  begin
    AStream.WriteBuffer(HD.ID, 4);
    AStream.WriteBuffer(HD.Entry.Address, 4);
    AStream.WriteBuffer(HD.Entry.Size, 4);
    AStream.WriteBuffer(HD.Entry.Flags, 4);
  end;
end;

procedure LoadHeaps(Value: THeap; AStream: TStream);
var
  HD: THeapData;
begin
  ZeroMemory(@HD, SizeOf(THeapData));
  while AStream.Position < AStream.Size do
  begin
    AStream.ReadBuffer(HD.ID, 4);
    AStream.ReadBuffer(HD.Entry.Address, 4);
    AStream.ReadBuffer(HD.Entry.Size, 4);
    AStream.ReadBuffer(HD.Entry.Flags, 4);
    HD.Wow64 := True;
    Value.Data.Add(HD);
  end;
end;

{ TIPCServer }

constructor TIPCServer.Create;
begin
  Randomize;
  // Директива SINGLE_INSTANCE не дает запускать 32 битному приложению 64 битный аналог
  // Сугубо для отладки
  FMMFName := 'Process_Memory_Map_MMF';
  {$IFNDEF SINGLE_INSTANCE}
  FMMFName := FMMFName + IntToHex(Random(MaxInt), 1);
  {$ENDIF}
  InitFileMapping;
end;

destructor TIPCServer.Destroy;
begin
  ReleaseFileMapping;
  inherited;
end;

procedure TIPCServer.InitFileMapping;
var
  MMFData: Pointer;
begin
  FIPCServerParams.PID := GetCurrentProcessId;
  FIPCServerParams.WndHandle := Classes.AllocateHWnd(WndProc);
  FMMFHandle := CreateFileMapping($FFFFFFFF, nil, PAGE_READWRITE,
    0, 4096, PChar(MMFName));
  if FMMFHandle <> 0 then
  begin
    MMFData := MapViewOfFile(FMMFHandle, FILE_MAP_WRITE, 0, 0, 0);
    if MMFData <> nil then
    begin
      PIPCServerParams(MMFData)^ := FIPCServerParams;
      UnmapViewOfFile(MMFData);
    end;
  end;
end;

procedure TIPCServer.ReleaseFileMapping;
begin
  Classes.DeallocateHWnd(FIPCServerParams.WndHandle);
  CloseHandle(FMMFHandle);
end;

procedure TIPCServer.WndProc(var Message: TMessage);
var
  Process: THandle;
  H: THeap;
  M: TMemoryStream;
begin
  if (Message.Msg = WM_GETMEMORYMAP) and
    (Message.WParam = 0) then
  begin
    Process := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
      False, Message.LParam);
    if Process = 0 then Exit;
    try
      M := TMemoryStream.Create;
      try
        H := THeap.Create(Message.LParam, Process);
        try
          SaveHeaps(H, M);
        finally
          H.Free;
        end;
        M.Position := 0;
        SetLength(FMemoryMapData, M.Size);
        M.ReadBuffer(FMemoryMapData[0], M.Size);
        FRemoteData.Address := DWORD(@FMemoryMapData[0]);
        FRemoteData.Size := M.Size;
        Message.Result := LRESULT(@FRemoteData);
        Exit;
      finally
        M.Free;
      end;
    finally
      CloseHandle(Process);
    end;
  end;
  inherited;
end;

function GetWin32MemoryMap(PID: DWORD; const MMFName: string): TMemoryStream;
var
  RemoteDataAddr: DWORD;
  RemoteData: TRemoteData;
  MemoryMapData: array of Byte;
  MMFHandle: THandle;
  Data: Pointer;
  IPCServerParams: TIPCServerParams;
  Process: THandle;
  lpNumberOfBytesRead: SIZE_T;
begin
  Result := TMemoryStream.Create;
  IPCServerParams.WndHandle := 0;
  MMFHandle := OpenFileMapping(FILE_MAP_READ, False, PChar(MMFName));
  if MMFHandle = 0 then Exit;
  try
    Data := MapViewOfFile(MMFHandle, FILE_MAP_READ, 0, 0, 0);
    if Data = nil then Exit;
    try
      IPCServerParams := PIPCServerParams(Data)^;
    except
      // Другое приложение файл создало, но еще ничего туда не записало..
      on EAccessViolation do ;
    end;
  finally
    CloseHandle(MMFHandle);
  end;
  if IPCServerParams.WndHandle = 0 then Exit;
  RemoteDataAddr := DWORD(SendMessage(IPCServerParams.WndHandle,
    WM_GETMEMORYMAP, 0, PID));
  Process := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
    False, IPCServerParams.PID);
  if Process = 0 then Exit;
  try
    if not ReadProcessMemory(Process, Pointer(RemoteDataAddr), @RemoteData,
      SizeOf(TRemoteData), lpNumberOfBytesRead) then Exit;
    SetLength(MemoryMapData, RemoteData.Size);
    if not ReadProcessMemory(Process, Pointer(RemoteData.Address),
      @MemoryMapData[0], RemoteData.Size, lpNumberOfBytesRead) then Exit;
    Result.WriteBuffer(MemoryMapData[0], RemoteData.Size);
    Result.Position := 0;
  finally
    CloseHandle(Process);
  end;
end;

end.
