////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : MemoryMap.Utils.pas
//  * Purpose   : Various Auxiliary Procedures and Functions
//  * Author    : Alexander (Rouse_) Bagel
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.4.41
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : https://github.com/AlexanderBagel/ProcessMemoryMap/releases
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

unit MemoryMap.Utils;

interface

uses
  Winapi.Windows,
  Winapi.TlHelp32,
  System.SysUtils,
  Generics.Collections,
  MemoryMap.NtDll,
  MemoryMap.ImageHlp;

  function IsWow64(hProcess: THandle): BOOL;
  function Is64OS: Boolean;
  function NormalizePath(const Value: string): string;

  /// <summary>
  /// The function returns the size of the section,
  /// taking into account the alignment specified in the PE header.
  /// Generally speaking, it would be more accurate to check the
  /// IMAGE_SCN_ALIGN_XXXBYTES flags for the section,
  /// which specify individual alignment, but it's a hassle...
  /// </summary>
  /// <remarks>
  /// [ru] Функция возвращает размер секции с учетом выравнивания,
  /// указанного в PE заголовке.
  /// Вообще, правильней еще смотреть флаги IMAGE_SCN_ALIGN_XXXBYTES у секции,
  /// которые выставляют индивидуальное выравнивание, но лениво...
  /// </remarks>
  function AlignedSectionSize(const ImageInfo: LOADED_IMAGE;
    const Value: NativeUInt): NativeUInt;

  function CheckAddr(Value: NativeUInt): Boolean; overload;
  function CheckAddr(Value: Pointer): Boolean; overload;

  /// <summary>
  /// The function checks the characteristics of a section and returns a flag
  /// indicating whether the section contains executable code
  /// </summary>
  /// <remarks>
  /// [ru] Функция проверяет характеристики секции и возвращает флаг,
  /// содержит ли секция исполняемый код
  /// </remarks>
  function IsExecute(const Value: DWORD): Boolean;

  /// <summary>
  /// This function checks the properties of a section and returns a flag
  /// indicating whether the section is writable or contains uninitialized data
  /// </summary>
  /// <remarks>
  /// [ru] Функция проверяет характеристики секции и возвращает флаг, доступна
  /// ли секция на запись или содержит ли секция неинициализированные данные
  /// </remarks>
  function IsWrite(const Value: DWORD): Boolean;

  function CheckPEImage(hProcess: THandle; ImageBase: Pointer): Boolean; overload;
  function CheckPEImage(hProcess: THandle; ImageBase: Pointer;
    out Image64: Boolean): Boolean; overload;

type
  TProcessLockHandleList = TList<THandle>;
  function SuspendProcess(PID: DWORD): TProcessLockHandleList;
  procedure ResumeProcess(Value: TProcessLockHandleList);

implementation


function IsWow64(hProcess: THandle): BOOL;
var
  IsWow64Process: function(hProcess: THandle; var Wow64Process: BOOL): BOOL; stdcall;
begin
  Result := False;
  IsWow64Process := GetProcAddress(GetModuleHandle(kernel32), 'IsWow64Process');
  if Assigned(IsWow64Process) then
    if not IsWow64Process(hProcess, Result) then
      Result := False;
end;

function Is64OS: Boolean;
{$IFDEF WIN64}
begin
  Result := True;
{$ELSE}
asm
  xor eax, eax
  mov  ecx, fs:[$c0]
  test ecx, ecx
  setnz al
{$ENDIF}
end;

function NormalizePath(const Value: string): string;
const
  OBJ_CASE_INSENSITIVE         = $00000040;
  STATUS_SUCCESS               = 0;
  FILE_SYNCHRONOUS_IO_NONALERT = $00000020;
  FILE_READ_DATA = 1;
  ObjectNameInformation = 1;
  DriveNameSize = 4;
  VolumeCount = 26;
  DriveTotalSize = DriveNameSize * VolumeCount;
  DosDeviceName = '\Device\HarddiskVolume';
var
  US: UNICODE_STRING;
  OA: OBJECT_ATTRIBUTES;
  IO: IO_STATUS_BLOCK;
  hFile: THandle;
  NTSTAT, dwReturn: DWORD;
  ObjectNameInfo: TOBJECT_NAME_INFORMATION;
  Buff, Volume: string;
  I, Count, dwQueryLength: Integer;
  lpQuery: array [0..MAX_PATH - 1] of Char;
  AnsiResult: AnsiString;
begin
  Result := Value;

  if not Value.StartsWith(DosDeviceName, True) then
  begin
    RtlInitUnicodeString(@US, StringToOleStr(Value));

    // The equivalent of the InitializeObjectAttributes macro
    // [ru] Аналог макроса InitializeObjectAttributes

    FillChar(OA, SizeOf(OBJECT_ATTRIBUTES), #0);
    OA.Length := SizeOf(OBJECT_ATTRIBUTES);
    OA.ObjectName := @US;
    OA.Attributes := OBJ_CASE_INSENSITIVE;

    // The ZwOpenFile function easily opens files whose paths are specified
    // using symbolic links, for example:
    // \SystemRoot\System32\ntdll.dll
    // \??\C:\Windows\System32\ntdll.dll
    // \Device\HarddiskVolume1\WINDOWS\system32\ntdll.dll
    // Therefore, we will use it to obtain a handle

    // [ru] Функция ZwOpenFile спокойно открывает файлы, путь к которым
    // представлен с использованием символьных ссылок, например:
    // \SystemRoot\System32\ntdll.dll
    // \??\C:\Windows\System32\ntdll.dll
    // \Device\HarddiskVolume1\WINDOWS\system32\ntdll.dll
    // Поэтому будем использовать ее для получения хэндла

    NTSTAT := ZwOpenFile(@hFile, FILE_READ_DATA or SYNCHRONIZE, @OA, @IO,
      FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,
      FILE_SYNCHRONOUS_IO_NONALERT);
    if NTSTAT = STATUS_SUCCESS then
    try

      // the file is open, now we look at its formalized path
      // [ru] файл открыт, теперь смотрим его формализованный путь

      NTSTAT := NtQueryObject(hFile, ObjectNameInformation,
        @ObjectNameInfo, MAX_PATH * 2, @dwReturn);
      if NTSTAT = STATUS_SUCCESS then
      begin
        SetLength(AnsiResult, MAX_PATH);
        WideCharToMultiByte(CP_ACP, 0,
          @ObjectNameInfo.Name.Buffer[ObjectNameInfo.Name.MaximumLength -
          ObjectNameInfo.Name.Length {$IFDEF WIN64} + 4{$ENDIF}],
          ObjectNameInfo.Name.Length, @AnsiResult[1],
          MAX_PATH, nil, nil);
        Result := string(PAnsiChar(AnsiResult));
      end;
    finally
      ZwClose(hFile);
    end;
  end;

  // The path to a file opened via ZwOpenFile
  // is returned in the format \Device\HarddiskVolumeX\blah-blah
  // All that's left is to map it to the actual disk

  // [ru] путь на открытый через ZwOpenFile файл
  // возвращается в виде \Device\HarddiskVolumeX\бла-бла
  // Осталось только его сопоставить с реальным диском

  SetLength(Buff, DriveTotalSize);
  Count := GetLogicalDriveStrings(DriveTotalSize, @Buff[1]) div DriveNameSize;
  for I := 0 to Count - 1 do
  begin
    Volume := PChar(@Buff[(I * DriveNameSize) + 1]);
    Volume[3] := #0;

    // We convert each drive letter to a symbolic link and
    // compare it to the formalized path

    // [ru] преобразуем имя каждого диска в символьную ссылку и
    // сравниваем с формализованным путем

    QueryDosDevice(PChar(Volume), @lpQuery[0], MAX_PATH);
    dwQueryLength := Length(string(lpQuery));
    if Copy(Result, 1, dwQueryLength) = string(lpQuery) then
    begin
      Volume[3] := '\';
      if lpQuery[dwQueryLength - 1] <> '\' then
        Inc(dwQueryLength);
      Delete(Result, 1, dwQueryLength);
      Result := Volume + Result;
      Break;
    end;
  end;

end;

function AlignedSectionSize(const ImageInfo: LOADED_IMAGE;
  const Value: NativeUInt): NativeUInt;
begin
  if Value = 0 then
  begin
    Result := 0;
    Exit;
  end;
  with ImageInfo.FileHeader^.OptionalHeader do
  begin
    if SectionAlignment mod Value = 0 then
      Result := Value
    else
    begin
      Result := Value div SectionAlignment;
      Inc(Result);
      Result := Result * SectionAlignment;
    end;
  end;
end;

function CheckAddr(Value: NativeUInt): Boolean;
begin
  Result := Value > $10000;
end;

function CheckAddr(Value: Pointer): Boolean;
begin
  Result := CheckAddr(NativeUInt(Value));
end;

function IsExecute(const Value: DWORD): Boolean;
begin
  Result := False;
  if (Value and IMAGE_SCN_CNT_CODE) =
    IMAGE_SCN_CNT_CODE then Result := True;
  if (Value and IMAGE_SCN_MEM_EXECUTE) =
    IMAGE_SCN_MEM_EXECUTE then Result := True;
end;

function IsWrite(const Value: DWORD): Boolean;
begin
  Result := False;
  if (Value and IMAGE_SCN_CNT_UNINITIALIZED_DATA) =
    IMAGE_SCN_CNT_UNINITIALIZED_DATA then Result := True;
  if (Value and IMAGE_SCN_MEM_WRITE) = IMAGE_SCN_MEM_WRITE then
    Result := True;
end;

function CheckPEImage(hProcess: THandle; ImageBase: Pointer): Boolean;
var
  Image64: Boolean;
begin
  Result := CheckPEImage(hProcess, ImageBase, Image64);
end;

function CheckPEImage(hProcess: THandle; ImageBase: Pointer;
  out Image64: Boolean): Boolean;
var
  ReturnLength: NativeUInt;
  IDH: TImageDosHeader;
  NT: TImageNtHeaders;
begin
  Result := False;
  Image64 := False;
  if not ReadProcessMemory(hProcess, ImageBase,
    @IDH, SizeOf(TImageDosHeader), ReturnLength) then Exit;
  if IDH.e_magic <> IMAGE_DOS_SIGNATURE then Exit;
  ImageBase := Pointer(NativeInt(ImageBase) + IDH._lfanew);
  if not ReadProcessMemory(hProcess, ImageBase,
    @NT, SizeOf(TImageNtHeaders), ReturnLength) then Exit;
  Result := NT.Signature = IMAGE_NT_SIGNATURE;
  if Result then
    Image64 := NT.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
end;

function SuspendProcess(PID: DWORD): TProcessLockHandleList;
const
  THREAD_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED or SYNCHRONIZE or $3FF;
  ThreadBasicInformation = 0;
  ThreadQuerySetWin32StartAddress = 9;
var
  hSnap, hThread: THandle;
  ThreadEntry: TThreadEntry32;
begin
  Result := TProcessLockHandleList.Create;
  if PID = GetCurrentProcessID then Exit;
  hSnap := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, PID);
  if hSnap <> INVALID_HANDLE_VALUE then
  try
    ThreadEntry.dwSize := SizeOf(TThreadEntry32);
    if Thread32First(hSnap, ThreadEntry) then
    repeat
      if ThreadEntry.th32OwnerProcessID <> PID then Continue;
      hThread := OpenThread(THREAD_ALL_ACCESS,
        False, ThreadEntry.th32ThreadID);
      if hThread <> 0 then
      begin
        SuspendThread(hThread);
        Result.Add(hThread);
      end;
    until not Thread32Next(hSnap, ThreadEntry);
  finally
     CloseHandle(hSnap);
  end;
end;

procedure ResumeProcess(Value: TProcessLockHandleList);
var
  hThread: THandle;
begin
  for hThread in Value do
  begin
    ResumeThread(hThread);
    CloseHandle(hThread);
  end;
  Value.Free;
end;

end.
