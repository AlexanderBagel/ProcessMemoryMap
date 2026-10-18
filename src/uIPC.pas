////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : uIPC.pas
//  * Purpose   : Unit for exchanging data between 32-bit and 64-bit processes
//  * Author    : Alexander (Rouse_) Bagel
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.7.54
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : https://github.com/AlexanderBagel/ProcessMemoryMap/releases/latest
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//  *
//  * SPDX-License-Identifier: MPL-2.0
//  * This Source Code Form is subject to the terms of the Mozilla Public
//  * License, v. 2.0. If a copy of the MPL was not distributed with this
//  * file, You can obtain one at http://mozilla.org/MPL/2.0/.
//  *
//  ****************************************************************************
//  *
//  * Support the Project:
//  *
//  * If you found this project useful, you can support its development
//  * on the author's main-project page:
//  *
//  * https://boosty.to/processmemorymap
//  *
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
  WM_EXECUTEX86_GETWNDPROCLIST = WM_USER + 124;

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

  function GetWin32MemoryMap(PID: DWORD): TMemoryStream;
  function GetWin32WndProcList(PID: DWORD): Boolean;
  procedure LoadHeaps(Value: THeap; AStream: TStream);

implementation

uses
  uWindows;

const
  DefIPCServerName = 'Process_Memory_Map_MMF';

var
  IPCServerMMFName: string = '';

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
  FMMFName := DefIPCServerName;

  // The SINGLE_INSTANCE directive prevents the 32-bit application
  // from launching its 64-bit counterpart
  // For debugging purposes only

  // [ru] Директива SINGLE_INSTANCE не дает запускать 32 битному приложению
  // 64 битный аналог
  // Сугубо для отладки

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
    try
      PIPCServerParams(MMFData)^ := FIPCServerParams;
    finally
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
  if (Message.Msg = WM_EXECUTEX86_GETWNDPROCLIST) and
    (Message.WParam = 0) then
  begin
    Message.Result := ExecuteX86GetWndProcList(Message.LParam);
    Exit;
  end;
  inherited;
end;

function GetWin32MemoryMap(PID: DWORD): TMemoryStream;
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
  if IPCServerMMFName = '' then Exit;
  IPCServerParams.WndHandle := 0;
  MMFHandle := OpenFileMapping(FILE_MAP_READ, False, PChar(IPCServerMMFName));
  if MMFHandle = 0 then Exit;
  try
    Data := MapViewOfFile(MMFHandle, FILE_MAP_READ, 0, 0, 0);
    if Data = nil then Exit;
    try
      try
        IPCServerParams := PIPCServerParams(Data)^;
      except
         // Another application has created the file but hasn't written anything to it yet
        on EAccessViolation do ;
      end;
    finally
      UnmapViewOfFile(Data);
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
    if RemoteData.Size > 0 then
    begin
      SetLength(MemoryMapData, RemoteData.Size);
      if not ReadProcessMemory(Process, Pointer(RemoteData.Address),
        @MemoryMapData[0], RemoteData.Size, lpNumberOfBytesRead) then Exit;
      Result.WriteBuffer(MemoryMapData[0], RemoteData.Size);
    end;
    Result.Position := 0;
  finally
    CloseHandle(Process);
  end;
end;

function GetWin32WndProcList(PID: DWORD): Boolean;
var
  MMFHandle: THandle;
  Data: Pointer;
  IPCServerParams: TIPCServerParams;
begin
  Result := False;
  if IPCServerMMFName = '' then Exit;  
  IPCServerParams.WndHandle := 0;
  MMFHandle := OpenFileMapping(FILE_MAP_READ, False, PChar(IPCServerMMFName));
  if MMFHandle = 0 then Exit;
  try
    Data := MapViewOfFile(MMFHandle, FILE_MAP_READ, 0, 0, 0);
    if Data = nil then Exit;
    try
      try
        IPCServerParams := PIPCServerParams(Data)^;
      except
        // Another application has created the file but hasn't written anything to it yet
        on EAccessViolation do ;
      end;
    finally
      UnmapViewOfFile(Data);
    end;
  finally
    CloseHandle(MMFHandle);
  end;
  if IPCServerParams.WndHandle = 0 then Exit;
  Result := SendMessage(IPCServerParams.WndHandle,
    WM_EXECUTEX86_GETWNDPROCLIST, 0, PID) = NO_ERROR;
end;

initialization

  {$IFDEF WIN64}
    {$IFDEF SINGLE_INSTANCE}
    IPCServerMMFName := DefIPCServerName;
    {$ELSE}
    IPCServerMMFName := ParamStr(1);
    {$ENDIF}
  {$ENDIF}

end.
