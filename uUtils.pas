////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uUtils.pas
//  * Purpose   : Модуль с различными вспомогательными функциями и процедурами
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

unit uUtils;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  Winapi.ShellAPI,
  Winapi.TlHelp32,
  Winapi.CommCtrl,
  System.Classes,
  MemoryMap.Core;

  function CheckIsAdmin: Boolean;
  function RestartAsAdmin: Boolean;
  function Run64App(const FilePath, Param: string): THandle;
  function SetDebugPriv: Boolean;
  function GetProcessIco(APid: Cardinal): HICON;
  procedure ConcatenateStrings(var A: string; const B: string);
  function SizeToStr(Value: NativeUInt): string;
  function SizeToStr2(Value: NativeUInt): string;
  function UInt64ToStr(Value: NativeUInt): string; overload;
  function UInt64ToStr(Value: Pointer): string; overload;
  procedure ShowErrorHint(AHandle: THandle);

type
  TReadCondition = (
    rcReadIfReadAccessPresent,
    rcReadIfReadWriteAccessPresent,
    rcReadAllwais);

  function ReadProcessData(Process: THandle; Address, OutBuffer: Pointer;
    var Size: NativeUInt; out RegionSize: NativeUInt;
    ReadCondition: TReadCondition): Boolean;

implementation

uses
  uSettings;

var
  hShell32: HMODULE = 0;
var
  _IsUserAnAdmin: function(): BOOL; stdcall = nil;

function CheckIsAdmin: Boolean;
begin
  if Assigned(_IsUserAnAdmin) then
    Result := _IsUserAnAdmin()
  else
  begin
    Result := True;
    if hShell32 = 0 then
      hShell32 := LoadLibrary(shell32);
    if hShell32 > HINSTANCE_ERROR then
    begin
      _IsUserAnAdmin := GetProcAddress(hShell32, 'IsUserAnAdmin');
      if Assigned(_IsUserAnAdmin) then
        Result := _IsUserAnAdmin();
    end;
  end;
end;

function RestartAsAdmin: Boolean;
var
  SEI: TShellExecuteInfo;
begin
  ZeroMemory(@SEI, SizeOf(TShellExecuteInfo));
  SEI.cbSize := SizeOf(TShellExecuteInfo);
  SEI.lpFile := PChar(ParamStr(0));
  SEI.lpDirectory := PChar(ExtractFilePath(ParamStr(0)));
  SEI.lpParameters := PChar(ParamStr(1));
  SEI.lpVerb := PChar('runas');
  SEI.fMask := SEE_MASK_DEFAULT;
  SEI.nShow := SW_SHOWNORMAL;
  Result := ShellExecuteEx(@SEI);
end;

function Run64App(const FilePath, Param: string): THandle;
var
  SEI: TShellExecuteInfo;
  R: TResourceStream;
begin
  if not FileExists(FilePath) then
  begin
    R := TResourceStream.Create(HInstance, 'PE64_IMAGE', RT_RCDATA);
    try
      R.SaveToFile(FilePath);
    finally
      R.Free;
    end;
  end;
  ZeroMemory(@SEI, SizeOf(TShellExecuteInfo));
  SEI.cbSize := SizeOf(TShellExecuteInfo);
  SEI.lpFile := PChar(FilePath);
  SEI.lpDirectory := PChar(ExtractFilePath(FilePath));
  SEI.lpParameters := PChar('"' + Param +'"');
  SEI.lpVerb := PChar('open');
  SEI.fMask := SEE_MASK_NOCLOSEPROCESS;
  SEI.nShow := SW_SHOWNORMAL;
  if ShellExecuteEx(@SEI) then
    Result := SEI.hProcess
  else
    Result := 0;
end;

function SetDebugPriv: Boolean;
var
  hToken: THandle;
  Tkp: TTokenPrivileges;
  ReturnLength: Cardinal;
begin
  Result := False;
  if OpenProcessToken(GetCurrentProcess,
    TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, hToken) then
  begin
    if LookupPrivilegeValue(nil,
      PChar('SeDebugPrivilege'), Tkp.Privileges[0].Luid) then
    begin
      Tkp.PrivilegeCount := 1;
      Tkp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
      Result := AdjustTokenPrivileges(hToken, False, Tkp, 0, nil, ReturnLength);
    end;
  end;
end;

function GetProcessFullPath(APid: Cardinal): string;
var
  hModuleSnap: THandle;
  ModuleEntry: TModuleEntry32;
begin
  Result := '';
  hModuleSnap := CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, APid);
  if (hModuleSnap = INVALID_HANDLE_VALUE) then Exit;
  try
    FillChar(ModuleEntry, SizeOf(TModuleEntry32), #0);
    ModuleEntry.dwSize := SizeOf(TModuleEntry32);
    if not Module32First(hModuleSnap, ModuleEntry) then Exit;
    Result := PChar(@ModuleEntry.szExePath[0]);
  finally
    CloseHandle(hModuleSnap);
  end;
end;

function GetProcessIco(APid: Cardinal): HICON;
var
  lpiIcon: Word;
begin
  lpiIcon := 0;
  Result := ExtractAssociatedIcon(HInstance,
    PChar(GetProcessFullPath(APid)), lpiIcon);
end;

procedure ConcatenateStrings(var A: string; const B: string);
begin
  if Trim(A) = '' then
    A := A + B
  else
    A := A + ', ' + B;
end;

function SizeToStr(Value: NativeUInt): string;
begin
  if Value = 0 then Exit('');
  if Value div 1024 = 0 then
    Result := IntToStr(Value)
  else
    Result := IntToStr(Value div 1024) + ' K';
end;

function SizeToStr2(Value: NativeUInt): string;
begin
  if Value div 1024 = 0 then
    Result := IntToStr(Value)
  else
    Result := IntToStr(Value div 1024) + ' K';
end;

function UInt64ToStr(Value: NativeUInt): string;
begin
  if MemoryMapCore.Process64 then
    Result := IntToHex(Value, 16)
  else
    Result := IntToHex(Value, 8);
end;

function UInt64ToStr(Value: Pointer): string;
begin
  Result := UInt64ToStr(NativeUInt(Value));
end;

procedure ShowErrorHint(AHandle: THandle);
var
  BaloonTip: TEditBalloonTip;
begin
  BaloonTip.cbStruct := SizeOf(TEditBalloonTip);
  BaloonTip.pszTitle := 'Unacceptable Character';
  BaloonTip.pszText := 'You can only type a number here.';
  BaloonTip.ttiIcon := TTI_ERROR;
  SendMessage(AHandle, EM_SHOWBALLOONTIP, 0, Integer(@BaloonTip));
end;

//
//  Функция читает данные с удаленного процесса
//  in     Process - хэндл процесса
//  in     Address - адрес с которого нужно читать
//  in     OutBuffer - буффер в который происходит чтение
//  in/out Size - размер OutBuffer (после вызова, размер зачитанных данных)
//  out    RegionSize - размер от Address до конца региона
//  in     ReadCondition - параметры чтения
//  ВАЖНО!!!
//  Если в настройках не включен флаг SuspendProcess, то ReadCondition
//  установленный в rcReadAllwais трактуется как rcReadIfReadAccessPresent
// =============================================================================
function ReadProcessData(Process: THandle; Address, OutBuffer: Pointer;
  var Size: NativeUInt; out RegionSize: NativeUInt;
  ReadCondition: TReadCondition): Boolean;
var
  MBI: TMemoryBasicInformation;

  function CanRead: Boolean;
  begin
    Result := MBI.State = MEM_COMMIT;
    if Result then
      Result := MBI.Protect and (
        PAGE_EXECUTE_READ or
        PAGE_EXECUTE_READWRITE or
        PAGE_READONLY or
        PAGE_READWRITE) <> 0;
    if Result then
      Result := (MBI.Protect and PAGE_GUARD) = 0;
  end;

  function CanWrite: Boolean;
  const
    PAGE_WRITECOMBINE = $400;
  begin
    Result := MBI.State = MEM_COMMIT;
    if Result then
      Result := MBI.Protect and (
        PAGE_EXECUTE_WRITECOPY or
        PAGE_EXECUTE_READWRITE or
        PAGE_WRITECOPY or
        PAGE_READWRITE or
        PAGE_WRITECOMBINE) <> 0;
    if Result then
      Result := (MBI.Protect and PAGE_GUARD) = 0;
  end;

var
  dwLength: Cardinal;
  OldProtect: Cardinal;
begin
  Result := False;
  if not Settings.SuspendProcess then
    if ReadCondition = rcReadAllwais then
      ReadCondition := rcReadIfReadAccessPresent;
  dwLength := SizeOf(TMemoryBasicInformation);
  RegionSize := 0;
  if VirtualQueryEx(Process,
    Address, MBI, dwLength) <> dwLength then Exit;
  RegionSize := MBI.RegionSize -
    (NativeUInt(Address) - NativeUInt(MBI.BaseAddress));
  case ReadCondition of
    rcReadIfReadAccessPresent:
      if not CanRead then
      begin
        Size := 0;
        Exit;
      end;
    rcReadIfReadWriteAccessPresent:
      if not (CanRead and CanWrite) then
      begin
        Size := 0;
        Exit;
      end;
    rcReadAllwais:
      VirtualProtectEx(Process, MBI.BaseAddress, MBI.RegionSize,
        PAGE_READONLY, OldProtect);
  end;
  if Size > RegionSize then
    Size := RegionSize;
  Result := ReadProcessMemory(Process, Address,
    OutBuffer, Size, Size);
  if ReadCondition = rcReadAllwais then
    VirtualProtectEx(Process, MBI.BaseAddress, MBI.RegionSize,
      OldProtect, OldProtect);
end;

end.
