////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Wow64.pas
//  * Purpose   : Модуль для поддержки WOW64 вызовов при чтении информации
//  *           : из 32 битного процесса в 64 битном.
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.0.11
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.Wow64;

interface

  {$I rawscanner.inc}

uses
  Windows,
  SysUtils,
  {$IFNDEF DISABLE_LOGGER}
  RawScanner.Logger,
  {$ENDIF}
  RawScanner.Types;

type
  TWow64Support = class
  strict private
    class var FInstance: TWow64Support;
    class destructor ClassDestroy;
  private
    FAvailable: Boolean;
    FDisableRedirection: function(
      out Wow64FsEnableRedirection: LongBool): LongBool; stdcall;
    FIsWow64Process: function(hProcess: THandle;
      var Wow64Process: LongBool): BOOL; stdcall;
    FRevertRedirection: function(OldValue: LongBool): LongBool; stdcall;
    FQueryInformationProcess64: function(ProcessHandle: THandle;
      ProcessInformationClass: ULONG; ProcessInformation: Pointer;
      ProcessInformationLength: ULONG; var ReturnLength: ULONG): DWORD; stdcall;
    FReadVirtualMemory64: function(ProcessHandle: THandle;
      BaseAddress: ULONG64; pBuffer: Pointer; Size: ULONG64;
      var NumberOfBytesRead: ULONG64): DWORD; stdcall;
    FOldRedirection: LongBool;
    FRedirectionCount: Integer;
    FUse64AddrMode: Boolean;
    FSystemDirectory, FSysWow64Directory: string;
    function Init: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    function DisableRedirection: Boolean;
    function EnableRedirection: Boolean;
    function IsWow64Process(hProcess: THandle;
      var Wow64Process: LongBool): BOOL;
    class function GetInstance: TWow64Support;
    function ReadVirtualMemory(hProcess: THandle; const lpBaseAddress: ULONG64;
      lpBuffer: Pointer; nSize: ULONG64;
      var lpNumberOfBytesRead: ULONG64): BOOL;
    function QueryInformationProcess(ProcessHandle: THandle;
      ProcessInformationClass: ULONG; ProcessInformation: Pointer;
      ProcessInformationLength: ULONG; var ReturnLength: ULONG):BOOL;
    property Available: Boolean read FAvailable;
    property Use64AddrMode: Boolean read FUse64AddrMode;
    property SystemDirectory: string read FSystemDirectory;
    property SysWow64Directory: string read FSysWow64Directory;
  end;

  function Wow64Support: TWow64Support;

implementation

function Wow64Support: TWow64Support;
begin
  Result := TWow64Support.GetInstance;
end;

procedure Error(const Description: string);
begin
  {$IFNDEF DISABLE_LOGGER}
  RawScannerLogger.Error(llWow64, Description);
  {$ENDIF}
end;

{ TWow64Support }

class destructor TWow64Support.ClassDestroy;
begin
  FreeAndNil(FInstance);
end;

  function GetSystemWow64Directory(lpBuffer: LPWSTR; uSize: UINT): UINT; stdcall;
    external kernel32 name 'GetSystemWow64DirectoryW';

constructor TWow64Support.Create;
begin
  FAvailable := Init;
  SetLength(FSystemDirectory, MAX_PATH);
  SetLength(FSystemDirectory, GetSystemDirectory(@FSystemDirectory[1], MAX_PATH));
  SetLength(FSysWow64Directory, MAX_PATH);
  SetLength(FSysWow64Directory, GetSystemWow64Directory(@FSysWow64Directory[1], MAX_PATH));
end;

destructor TWow64Support.Destroy;
begin
  if Available and (FRedirectionCount > 0) then
    FRevertRedirection(FOldRedirection);
  inherited;
end;

function TWow64Support.DisableRedirection: Boolean;
begin
  Result := Available and
    ((FRedirectionCount > 0) or FDisableRedirection(FOldRedirection));
  if Result then
    Inc(FRedirectionCount);
end;

function TWow64Support.EnableRedirection: Boolean;
begin
  Result := Available and (FRedirectionCount > 0) and
    ((FRedirectionCount > 1) or FRevertRedirection(FOldRedirection));
  if Result then
    Dec(FRedirectionCount);
end;

class function TWow64Support.GetInstance: TWow64Support;
begin
  if FInstance = nil then
    FInstance := TWow64Support.Create;
  Result := FInstance;
end;

function TWow64Support.Init: Boolean;
const
  StrError = 'Can not get %s module handle. Error %d %s';
var
  hLib: THandle;
  Wow64Process: LongBool;
begin
  Result := False;
  hLib := GetModuleHandle('kernel32.dll');
  if hLib <= HINSTANCE_ERROR then
  begin
    Error(
      Format(StrError, ['kernel32.dll', GetLastError, SysErrorMessage(GetLastError)]));
    Exit;
  end;
  FIsWow64Process := GetProcAddress(hLib, 'IsWow64Process');
  FDisableRedirection := GetProcAddress(hLib, 'Wow64DisableWow64FsRedirection');
  FRevertRedirection := GetProcAddress(hLib, 'Wow64RevertWow64FsRedirection');
  hLib := GetModuleHandle('ntdll.dll');
  if hLib <= HINSTANCE_ERROR then
  begin
    Error(
      Format(StrError, ['ntdll.dll', GetLastError, SysErrorMessage(GetLastError)]));
    Exit;
  end;
  FQueryInformationProcess64 := GetProcAddress(hLib, 'NtWow64QueryInformationProcess64');
  FReadVirtualMemory64 := GetProcAddress(hLib, 'NtWow64ReadVirtualMemory64');
  Result :=
    Assigned(FDisableRedirection) and
    Assigned(FIsWow64Process) and
    Assigned(FRevertRedirection) and
    Assigned(FQueryInformationProcess64) and
    Assigned(FReadVirtualMemory64) and
    FIsWow64Process(GetCurrentProcess, Wow64Process) and
    Wow64Process;
  if Result then
    FUse64AddrMode := Wow64Process;
end;

function TWow64Support.IsWow64Process(hProcess: THandle;
  var Wow64Process: LongBool): BOOL;
begin
  Result := Assigned(FIsWow64Process) and
    FIsWow64Process(hProcess, Wow64Process);
end;

function TWow64Support.QueryInformationProcess(ProcessHandle: THandle;
  ProcessInformationClass: ULONG; ProcessInformation: Pointer;
  ProcessInformationLength: ULONG; var ReturnLength: ULONG): BOOL;
begin
  Result := Available and (FQueryInformationProcess64(ProcessHandle,
    ProcessInformationClass, ProcessInformation, ProcessInformationLength,
    ReturnLength) = 0);
end;

function TWow64Support.ReadVirtualMemory(hProcess: THandle; const lpBaseAddress: ULONG64;
  lpBuffer: Pointer; nSize: ULONG64; var lpNumberOfBytesRead: ULONG64): BOOL;
begin
  Result := Available and (FReadVirtualMemory64(hProcess, lpBaseAddress,
    lpBuffer, nSize, lpNumberOfBytesRead) = 0);
end;

end.
