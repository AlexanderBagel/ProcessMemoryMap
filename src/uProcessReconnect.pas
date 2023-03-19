////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uProcessReconnect.pas
//  * Purpose   : Модуль отвечающий за поиск нового PID процесса после его перезапуска
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2017, 2023.
//  * Version   : 1.4.28
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uProcessReconnect;

interface

uses
  Winapi.Windows,
  System.Classes,
  Winapi.TlHelp32;

type
  TProcessReconnect = class
  private
    FProcessData: TStringList;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Clear;
    function GetNewPID(OldPID: DWORD): DWORD;
    procedure SetKnownProcessList(Value: TStringList);
  end;

function ProcessReconnect: TProcessReconnect;

implementation

uses
  MemoryMap.Core,
  uUtils;

var
  _ProcessReconnect: TProcessReconnect;

function ProcessReconnect: TProcessReconnect;
begin
  if _ProcessReconnect = nil then
    _ProcessReconnect := TProcessReconnect.Create;
  Result := _ProcessReconnect;
end;

{ TProcessReconnect }

procedure TProcessReconnect.Clear;
begin
  FProcessData.Clear;
end;

constructor TProcessReconnect.Create;
begin
  FProcessData := TStringList.Create;
end;

destructor TProcessReconnect.Destroy;
begin
  FProcessData.Free;
  inherited;
end;

function TProcessReconnect.GetNewPID(OldPID: DWORD): DWORD;
var
  Index: Integer;
  ProcessName: string;
  hProcessSnap: THandle;
  ProcessEntry: TProcessEntry32;
  Process: THandle;
  MBI: TMemoryBasicInformation;
begin
  Result := 0;
  Process := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ or
    PROCESS_VM_OPERATION, False, OldPID);
  if Process <> 0 then
  try
    // дополнительная проверка, если кто-то держит хэндл на уже убитый процесс
    if VirtualQueryEx(Process, MemoryMapCore.PebBaseAddress, MBI, SizeOf(MBI)) <> 0 then
      Exit(OldPID);
  finally
    CloseHandle(Process);
  end;
  Index := FProcessData.IndexOfObject(Pointer(OldPID));
  if Index < 0 then Exit;
  ProcessName := FProcessData[Index];
  hProcessSnap := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hProcessSnap = INVALID_HANDLE_VALUE) then Exit;
  try
    FillChar(ProcessEntry, SizeOf(TProcessEntry32), #0);
    ProcessEntry.dwSize := SizeOf(TProcessEntry32);
    if not Process32First(hProcessSnap, ProcessEntry) then Exit;
    repeat
      if FProcessData.IndexOfObject(
        Pointer(ProcessEntry.th32ProcessID)) >= 0 then Continue;
      if GetProcessFullPath(ProcessEntry.th32ProcessID) = ProcessName then
      begin
        FProcessData.AddObject(ProcessName, Pointer(ProcessEntry.th32ProcessID));
        Result := ProcessEntry.th32ProcessID;
        Break;
      end;
    until not Process32Next(hProcessSnap, ProcessEntry);
  finally
    CloseHandle(hProcessSnap);
  end;
end;

procedure TProcessReconnect.SetKnownProcessList(Value: TStringList);
begin
  FProcessData.Assign(Value);
end;

initialization

finalization

  _ProcessReconnect.Free;

end.
