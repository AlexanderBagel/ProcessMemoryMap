////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uUtils.pas
//  * Purpose   : Модуль с различными вспомогательными функциями и процедурами
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2017.
//  * Version   : 1.01
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

type
  TMemoryDump = array of Byte;

  function CheckIsAdmin: Boolean;
  function RestartAsAdmin: Boolean;
  function Run64App(const FilePath, Param: string): THandle;
  function SetDebugPriv: Boolean;
  function GetProcessFullPath(APid: Cardinal): string;
  function GetProcessIco(APid: Cardinal): HICON;
  procedure ConcatenateStrings(var A: string; const B: string);
  function SizeToStr(Value: NativeUInt): string;
  function SizeToStr2(Value: NativeUInt): string;
  function UInt64ToStr(Value: NativeUInt): string; overload;
  function UInt64ToStr(Value: Pointer): string; overload;
  procedure ShowErrorHint(AHandle: THandle);
  function CRC32(RawBuff: TMemoryDump): DWORD;
  function HexValueToInt64(Value: string; out HexValue: Int64): Boolean;

type
  TReadCondition = (
    rcReadIfReadAccessPresent,
    rcReadIfReadWriteAccessPresent,
    rcReadAllwais);

  function ReadProcessData(Process: THandle; Address, OutBuffer: Pointer;
    var Size: NativeUInt; out RegionSize: NativeUInt;
    ReadCondition: TReadCondition): Boolean;

  function OpenProcessWithReconnect: THandle;

implementation

uses
  uProcessMM,
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
  // Rouse_ 16.10.2015
  // Если на регион в котором расположена KUSER_SHARED_DATA
  // и который имеет атрибуты защиты PAGE_READONLY
  // принудительно выставить еще раз PAGE_READONLY
  // то в Windows 7 64 бита отключается обновление этой структуры
  // и как следствие перестает работать GetTickCount и прочее
  // поэтому отключаем лишние телодвижения
  if ReadCondition = rcReadAllwais then
    if MBI.Protect = PAGE_READONLY then
      ReadCondition := rcReadIfReadAccessPresent;
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

function CRC32(RawBuff: TMemoryDump): DWORD;
const
  CRC32Table : array[0..255] of DWORD =
    (
      $00000000, $77073096, $ee0e612c, $990951ba, $076dc419, $706af48f, $e963a535, $9e6495a3,
      $0edb8832, $79dcb8a4, $e0d5e91e, $97d2d988, $09b64c2b, $7eb17cbd, $e7b82d07, $90bf1d91,
      $1db71064, $6ab020f2, $f3b97148, $84be41de, $1adad47d, $6ddde4eb, $f4d4b551, $83d385c7,
      $136c9856, $646ba8c0, $fd62f97a, $8a65c9ec, $14015c4f, $63066cd9, $fa0f3d63, $8d080df5,
      $3b6e20c8, $4c69105e, $d56041e4, $a2677172, $3c03e4d1, $4b04d447, $d20d85fd, $a50ab56b,
      $35b5a8fa, $42b2986c, $dbbbc9d6, $acbcf940, $32d86ce3, $45df5c75, $dcd60dcf, $abd13d59,
      $26d930ac, $51de003a, $c8d75180, $bfd06116, $21b4f4b5, $56b3c423, $cfba9599, $b8bda50f,
      $2802b89e, $5f058808, $c60cd9b2, $b10be924, $2f6f7c87, $58684c11, $c1611dab, $b6662d3d,
      $76dc4190, $01db7106, $98d220bc, $efd5102a, $71b18589, $06b6b51f, $9fbfe4a5, $e8b8d433,
      $7807c9a2, $0f00f934, $9609a88e, $e10e9818, $7f6a0dbb, $086d3d2d, $91646c97, $e6635c01,
      $6b6b51f4, $1c6c6162, $856530d8, $f262004e, $6c0695ed, $1b01a57b, $8208f4c1, $f50fc457,
      $65b0d9c6, $12b7e950, $8bbeb8ea, $fcb9887c, $62dd1ddf, $15da2d49, $8cd37cf3, $fbd44c65,
      $4db26158, $3ab551ce, $a3bc0074, $d4bb30e2, $4adfa541, $3dd895d7, $a4d1c46d, $d3d6f4fb,
      $4369e96a, $346ed9fc, $ad678846, $da60b8d0, $44042d73, $33031de5, $aa0a4c5f, $dd0d7cc9,
      $5005713c, $270241aa, $be0b1010, $c90c2086, $5768b525, $206f85b3, $b966d409, $ce61e49f,
      $5edef90e, $29d9c998, $b0d09822, $c7d7a8b4, $59b33d17, $2eb40d81, $b7bd5c3b, $c0ba6cad,
      $edb88320, $9abfb3b6, $03b6e20c, $74b1d29a, $ead54739, $9dd277af, $04db2615, $73dc1683,
      $e3630b12, $94643b84, $0d6d6a3e, $7a6a5aa8, $e40ecf0b, $9309ff9d, $0a00ae27, $7d079eb1,
      $f00f9344, $8708a3d2, $1e01f268, $6906c2fe, $f762575d, $806567cb, $196c3671, $6e6b06e7,
      $fed41b76, $89d32be0, $10da7a5a, $67dd4acc, $f9b9df6f, $8ebeeff9, $17b7be43, $60b08ed5,
      $d6d6a3e8, $a1d1937e, $38d8c2c4, $4fdff252, $d1bb67f1, $a6bc5767, $3fb506dd, $48b2364b,
      $d80d2bda, $af0a1b4c, $36034af6, $41047a60, $df60efc3, $a867df55, $316e8eef, $4669be79,
      $cb61b38c, $bc66831a, $256fd2a0, $5268e236, $cc0c7795, $bb0b4703, $220216b9, $5505262f,
      $c5ba3bbe, $b2bd0b28, $2bb45a92, $5cb36a04, $c2d7ffa7, $b5d0cf31, $2cd99e8b, $5bdeae1d,
      $9b64c2b0, $ec63f226, $756aa39c, $026d930a, $9c0906a9, $eb0e363f, $72076785, $05005713,
      $95bf4a82, $e2b87a14, $7bb12bae, $0cb61b38, $92d28e9b, $e5d5be0d, $7cdcefb7, $0bdbdf21,
      $86d3d2d4, $f1d4e242, $68ddb3f8, $1fda836e, $81be16cd, $f6b9265b, $6fb077e1, $18b74777,
      $88085ae6, $ff0f6a70, $66063bca, $11010b5c, $8f659eff, $f862ae69, $616bffd3, $166ccf45,
      $a00ae278, $d70dd2ee, $4e048354, $3903b3c2, $a7672661, $d06016f7, $4969474d, $3e6e77db,
      $aed16a4a, $d9d65adc, $40df0b66, $37d83bf0, $a9bcae53, $debb9ec5, $47b2cf7f, $30b5ffe9,
      $bdbdf21c, $cabac28a, $53b39330, $24b4a3a6, $bad03605, $cdd70693, $54de5729, $23d967bf,
      $b3667a2e, $c4614ab8, $5d681b02, $2a6f2b94, $b40bbe37, $c30c8ea1, $5a05df1b, $2d02ef8d
    );
var
  I: Integer;
begin
  Result := $FFFFFFFF;
  for I := 0 to Length(RawBuff) - 1 do
    Result := ((Result shr 8) and $00FFFFFF) xor
      CRC32Table[(Result xor RawBuff[I]) and $FF];
  Result := Result xor $FFFFFFFF;
end;

function ByteValueToInt64(Value: string; out HexValue: Int64): Boolean;
var
  I: Integer;
  Tmp: string;
begin
  if Pos(' ', Value) = 0 then Exit(False);
  HexValue := 0;
  Tmp := '';
  for I := 0 to 7 do
  begin
    Tmp := Copy(Value, 1, 2) + Tmp;
    Delete(Value, 1, 3);
    if Value = '' then Break;
  end;
  Result := TryStrToInt64('$' + Tmp, HexValue);
end;

function HexValueToInt64(Value: string; out HexValue: Int64): Boolean;
begin
  HexValue := 0;
  Value := Trim(Value);
  Result := ByteValueToInt64(Value, HexValue);
  if Result then Exit;
  if Copy(Value, 1, 2) = '0x' then
    Delete(Value, 1, 2);
  if Value = '' then Exit(True);
  if LowerCase(Value[Length(Value)]) = 'h' then
    SetLength(Value, Length(Value) - 1);
  if Value = '' then Exit(True);
  if Value[1] = '$' then
    Result := TryStrToInt64(Value, HexValue)
  else
    Result := TryStrToInt64('$' + Value, HexValue);
end;

function OpenProcessWithReconnect: THandle;
begin
  Result := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
    False, MemoryMapCore.PID);
  if Result = 0 then
  begin
    if dlgProcessMM.Reconnect then
      Result := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
        False, MemoryMapCore.PID)
    else
      RaiseLastOSError;
  end;
end;

end.
