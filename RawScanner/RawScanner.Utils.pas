////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : RawScanner.Utils.pas
//  * Purpose   : A set of utility methods common to the RawScanner modules.
//  * Author    : Alexander (Rouse_) Bagel
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.2.30
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

unit RawScanner.Utils;

interface

  {$I rawscanner.inc}

uses
  Windows,
  Classes,
  SysUtils,
  PsApi,
  ImageHlp,
  StrUtils,
  RawScanner.Types,
  RawScanner.Elf,
  RawScanner.Wow64,
  RawScanner.X64Gates;

type
  TFilePathAtImageBase = reference to function(AddrVA: ULONG_PTR64): string;

var
  FilePathAtImageBase: TFilePathAtImageBase = nil;

  procedure InitNtQueryVirtualMemory64(Value: Pointer);
  procedure ReleaseNtQueryVirtualMemory64;
  function ReadRemoteMemory(hProcess: THandle; const lpBaseAddress: ULONG_PTR64;
    lpBuffer: Pointer; nSize: SIZE_T): Boolean;
  function QueryWorkingSet64(hProcess: THandle; pv: Pointer; cb: DWORD): Boolean;
  function GetMappedFileName64(hProcess: THandle; lpv: ULONG_PTR64;
    lpFilename: LPCWSTR; nSize: DWORD): DWORD;
  function VirtualQueryEx64(hProcess: THandle; lpAddress: ULONG_PTR64;
    var lpBuffer: TMemoryBasicInformation64; dwLength: NativeUInt): DWORD;
  function GetMappedModule(ProcessHandle: THandle; AddrVa: ULONG_PTR64): string;
  function UnDecorateSymbolName(const Value: string): string;
  function UnDecorateSymbolName2(const Value: string): string;

type
  TBinaryImageType = (bitUnknown, bitPe, bitElf, bitCoff, bitRes);

  function GetBinaryImageType(AStream: TStream): TBinaryImageType;

implementation

type
  TNtQueryVirtualMemory64 = function(hProcess: THandle;
    BaseAddress: ULONG_PTR64; MemoryInformationClass: DWORD;
    MemoryInformation: Pointer; MemoryInformationLength: DWORD;
    ReturnLength: PULONG64): NTSTATUS; stdcall;

var

  // The 64-bit NtQueryVirtualMemory is initialized from RawScanner.Core
  // [ru] 64-битная NtQueryVirtualMemory инициализируется из RawScanner.Core

  NtQueryVirtualMemory64: TNtQueryVirtualMemory64;

procedure InitNtQueryVirtualMemory64(Value: Pointer);
begin
  @NtQueryVirtualMemory64 := Value;
end;

procedure ReleaseNtQueryVirtualMemory64;
begin
  ReleaseX64Gate(@NtQueryVirtualMemory64);
  @NtQueryVirtualMemory64 := nil;
end;

{$IFDEF WIN32}
const
  MM_HIGHEST_USER_ADDRESS = $7FFEFFFF;

type
  NTSTATUS = LONG;

function NT_SUCCESS(Status: NTSTATUS): Boolean; inline;
begin
  Result := Status >= 0;
end;

function RtlNtStatusToDosError(Status: NTSTATUS): DWORD; stdcall;
  external 'ntdll.dll';

function BaseSetLastNTError(Status: NTSTATUS): ULONG;
begin
  Result := RtlNtStatusToDosError(Status);
  SetLastError(Result);
end;
{$ENDIF}

function ReadRemoteMemory(hProcess: THandle; const lpBaseAddress: ULONG_PTR64;
  lpBuffer: Pointer; nSize: SIZE_T): Boolean;
var
  {$IFDEF WIN32}
  uReturnLength: ULONG64;
  {$ENDIF}
  ReturnLength: NativeUInt;
begin
  {$IFDEF WIN32}
  if Wow64Support.Use64AddrMode then
    Result := Wow64Support.ReadVirtualMemory(hProcess, lpBaseAddress,
      lpBuffer, nSize, uReturnLength)
  else
    Result := ReadProcessMemory(hProcess, Pointer(lpBaseAddress),
      lpBuffer, nSize, ReturnLength);
  {$ELSE}
  Result := ReadProcessMemory(hProcess, Pointer(lpBaseAddress),
    lpBuffer, nSize, ReturnLength);
  {$ENDIF}
end;

{$IFDEF WIN32}
function InternalNtQueryVirtualMemory64(hProcess: THandle;
  BaseAddress: ULONG_PTR64; MemoryInformationClass: DWORD;
  MemoryInformation: Pointer; MemoryInformationLength: DWORD;
  ReturnLength: PULONG64): NTSTATUS;
var
  AlignedBuff: Pointer;
begin

  // The data buffer (MemoryInformation) must be aligned
  // to an 8-byte boundary, otherwise, an error will be returned
  // STATUS_DATATYPE_MISALIGNMENT

  // [ru] Буфер для данных (MemoryInformation) должен быть выровнен
  // по 8-байтной границе, в противном случае вернется ошибка
  // STATUS_DATATYPE_MISALIGNMENT

  AlignedBuff := VirtualAlloc(nil,
    MemoryInformationLength, MEM_COMMIT, PAGE_READWRITE);
  try
    Result := NtQueryVirtualMemory64(hProcess, BaseAddress,
      MemoryInformationClass, AlignedBuff, MemoryInformationLength,
      ReturnLength);

    // There is no need to analyze the result here, since, for example, a call to
    // MemoryWorkingSetList will return STATUS_INFO_LENGTH_MISMATCH without filling
    // the uReturnLength field, but the data on the required size will be placed
    // into the passed AlignedBuff buffer, and it must be returned to the calling code
    // as-is. The calling code will handle the analysis of the result itself

    // [ru] Анализировать результат тут не нужно, т.к., например, вызов
    // MemoryWorkingSetList вернет STATUS_INFO_LENGTH_MISMATCH, не заполнив
    // поле uReturnLength, но данные о необходимом размере будут помещены
    // в переданный буфер AlignedBuff, и их нужно вернуть вызывающему коду
    // как есть. Анализ результата уже будет обрабатывать он сам

    Move(AlignedBuff^, MemoryInformation^, MemoryInformationLength);
  finally
    VirtualFree(AlignedBuff, MemoryInformationLength, MEM_RELEASE);
  end;
end;
{$ENDIF}

function QueryWorkingSet32(hProcess: THandle; pv: Pointer; cb: DWORD): Boolean;
var
  WorksetBuff: array of ULONG_PTR;
  pCursor: PULONG_PTR64;
begin
  cb := cb shr 3;
  SetLength(WorksetBuff, cb);
  Result := QueryWorkingSet(hProcess, @WorksetBuff[0], cb shl 2);
  pCursor := pv;
  for var I := 0 to cb - 1 do
  begin
    pCursor^ := WorksetBuff[I];
    Inc(pCursor);
  end;
end;

function QueryWorkingSet64(hProcess: THandle; pv: Pointer; cb: DWORD): Boolean;
{$IFDEF WIN32}
const
  MemoryWorkingSetList = 1;
var
  Status: NTSTATUS;
{$ENDIF}
begin
  {$IFDEF WIN32}

  // If we're running on a pure 32-bit OS, we simply make a 32-bit call
  // and store the result in an array with 64-bit addresses

  // [ru] Если мы в чистой 32-битной ОС, то просто производим 32-битный вызов
  // с перекидыванием результата в массив с 64-битными адресами

  if not Wow64Support.Use64AddrMode then
  begin
    Result := QueryWorkingSet32(hProcess, pv, cb);
    Exit;
  end;

  // Otherwise, we need a full WorkSet with 64-bit pages
  // [ru] В противном случае нам нужен полный WorkSet с 64-битными страницами

  if Assigned(NtQueryVirtualMemory64) then
  begin
    Status := InternalNtQueryVirtualMemory64(
      hProcess, 0, MemoryWorkingSetList, pv, cb, nil);
    if NT_SUCCESS(Status) then
      Exit(True);
  end;

  Result := False;

  {$ELSE}
  Result := QueryWorkingSet(hProcess, pv, cb);
  {$ENDIF}
end;

function GetMappedFileName64(hProcess: THandle; lpv: ULONG_PTR64;
  lpFilename: LPCWSTR; nSize: DWORD): DWORD;
{$IFDEF WIN32}
const
  MemoryMappedFilenameInformation = 2;
type
  PMappedFileName = ^TMappedFileName;
  TMappedFileName = record
    ObjectNameInfo: UNICODE_STRING64;
    FileName: array [0..MAX_PATH - 1] of Char;
  end;

var
  MappedFileName: PMappedFileName;
  Status: NTSTATUS;
  cb: DWORD;
  ReturnLength: ULONG64;
{$ENDIF}
begin
{$IFDEF WIN32}

  // From the range of user addresses, the path to the mapped file can be
  // obtained by calling the standard API

  // [ru] Из диапазона пользовательских адресов путь к отмапленному файлу можно
  // получить вызовом штатной API

  if lpv < MM_HIGHEST_USER_ADDRESS then
  begin
    Result := GetMappedFileName(hProcess, Pointer(lpv), lpFilename, nSize);
    Exit;
  end;

  // But for higher-order addresses, this can be done
  // only by calling the 64-bit NtQueryVirtualMemory and emulating the implementation
  // of GetMappedFileName

  // [ru] Но по старшим адресам это можно сделать
  // только вызовом 64-битной NtQueryVirtualMemory, проэмулировав реализацию
  // GetMappedFileName

  Result := 0;
  if Assigned(NtQueryVirtualMemory64) then
  begin

    // To avoid cluttering the stack with the local TMappedFileName structure,
    // we'll allocate memory for it right away

    // [ru] Чтобы не захламлять стек под локальную структуру TMappedFileName,
    // сразу выделим под неё память

    MappedFileName := VirtualAlloc(nil,
      SizeOf(TMappedFileName), MEM_COMMIT, PAGE_READWRITE);
    try

      // After that, the intermediate call to InternalNtQueryVirtualMemory64
      // will no longer be needed, since the buffer for the return result
      // will already be aligned to an 8-byte boundary

      // [ru] После чего промежуточный вызов InternalNtQueryVirtualMemory64
      // будет не нужен, т.к. буфер для возвращаемого результата
      // уже будет выровнен по 8-байтной границе

      Status := NtQueryVirtualMemory64(hProcess, lpv,
        MemoryMappedFilenameInformation, MappedFileName,
        SizeOf(TMappedFileName), @ReturnLength);

      if not NT_SUCCESS(Status) then
      begin
        BaseSetLastNTError(Status);
        Exit(0);
      end;

      nSize := nSize shl 1;
      cb := MappedFileName^.ObjectNameInfo.MaximumLength;

      if nSize < cb then
        cb := nSize;

      Move(MappedFileName^.FileName[0], lpFilename^, cb);

      if cb = MappedFileName^.ObjectNameInfo.MaximumLength then
        Dec(cb, SizeOf(WChar));

      Result := cb shr 1;

    finally
      VirtualFree(MappedFileName, SizeOf(TMappedFileName), MEM_RELEASE);
    end;
  end;
{$ELSE}
  Result := GetMappedFileName(hProcess, Pointer(lpv), lpFilename, nSize);
{$ENDIF}
end;

function VirtualQueryEx64(hProcess: THandle; lpAddress: ULONG_PTR64;
  var lpBuffer: TMemoryBasicInformation64; dwLength: NativeUInt): DWORD;
{$IFDEF WIN32}
const
  MemoryBasicInformation = 0;
var
  MBI: TMemoryBasicInformation;
  Status: NTSTATUS;
  ReturnLength: ULONG64;
{$ENDIF}
begin
{$IFDEF WIN32}

  if lpAddress < MM_HIGHEST_USER_ADDRESS then
  begin
    Result := VirtualQueryEx(hProcess, Pointer(lpAddress),
      MBI, SizeOf(TMemoryBasicInformation));

    // If the call is successful, we transfer the data from the 32-bit structure
    // to the 64-bit structure

    // [ru] Если вызов успешен, перекидываем данные из 32-битной структуры
    // в 64-битную

    if Result = SizeOf(TMemoryBasicInformation) then
    begin
      Result := SizeOf(TMemoryBasicInformation64);
      lpBuffer.BaseAddress := ULONG_PTR64(MBI.BaseAddress);
      lpBuffer.AllocationBase := ULONG_PTR64(MBI.AllocationBase);
      lpBuffer.AllocationProtect := MBI.AllocationProtect;
      lpBuffer.RegionSize := ULONG_PTR64(MBI.RegionSize);
      lpBuffer.State := MBI.State;
      lpBuffer.Protect := MBI.Protect;
      lpBuffer.Type_9 := MBI.Type_9;
    end;
    Exit;
  end;

  Result := 0;
  if Assigned(NtQueryVirtualMemory64) then
  begin
    Status := InternalNtQueryVirtualMemory64(hProcess,
      lpAddress, MemoryBasicInformation, @lpBuffer, dwLength, @ReturnLength);
    if NT_SUCCESS(Status) then
      Result := ReturnLength
    else
      BaseSetLastNTError(Status);
  end;

{$ELSE}
  Result := VirtualQueryEx(hProcess, Pointer(lpAddress),
    TMemoryBasicInformation(lpBuffer), dwLength);
{$ENDIF}
end;

function GetMappedModule(ProcessHandle: THandle; AddrVa: ULONG_PTR64): string;
begin
  SetLength(Result, MAX_PATH);
  var MapedFilePathLen := GetMappedFileName64(ProcessHandle,
    AddrVa, @Result[1], MAX_PATH * SizeOf(Char));
  if MapedFilePathLen > 0 then
    Result := ExtractFileName(Copy(Result, 1, MapedFilePathLen))
  else
    Result := EmptyStr;
end;

function UnDecorateSymbolName(const Value: string): string;
const
  BuffLen = 4096;
var
  Index, Index2: Integer;
  TmpDecName, UnDecName: AnsiString;
begin

  // an equivalent of the SymUnDNameInternal function used by symbols
  // [ru] аналог функции SymUnDNameInternal, используемой символами

  Result := Value;
  if Result = EmptyStr then Exit;
  if (Result[1] = '?') or Result.StartsWith('.?') or Result.StartsWith('..?') then
  begin
    if Result.StartsWith('??_C@') then
    begin
      Result := 'string';
      Index := PosEx('@', Value, 6);
      Index2 := PosEx('@', Value, Index + 1);
      if Index2 > 6 then
      begin
        if Index2 = Length(Value) then
          Index2 := Index;
        Result := Format('string: "%s"', [Copy(Value, Index2 + 1, Length(Value) - Index2 - 1)]);
      end;
      Exit;
    end;
    Index := Pos('?', Value);
    TmpDecName := AnsiString(PChar(@Value[Index]));
    SetLength(UnDecName, BuffLen);
    SetLength(UnDecName, ImageHlp.UnDecorateSymbolName(@TmpDecName[1],
      @UnDecName[1], BuffLen, UNDNAME_NAME_ONLY));
    if Length(UnDecName) > 0 then
      Result := StringOfChar('.', Index - 1) + string(UnDecName);
    Exit;
  end;
  Index := 1;
  if CharInSet(Value[1], ['_', '.', '@']) then
    Inc(Index);
  Index2 := PosEx('@', Value, Index);
  if Index2 <> 0 then
    Index := Index2 + 1;
  if Index > 1 then
    Result := Copy(Value, Index, Length(Value));
end;

function UnDecorateSymbolName2(const Value: string): string;
const
  BuffLen = 4096;
var
  Index, Index2: Integer;
  TmpDecName, UnDecName: AnsiString;
begin

  // A separate option for removing name decoration
  // for the debug information stored in PDB files

  // [ru] Отдельный вариант снятия декорации для отладочной информации,
  // находящейся в PDB файлах

  Result := Value;
  if Result = EmptyStr then Exit;
  if Result.StartsWith('??_C@') then
  begin
    Result := 'string';
    Index := PosEx('@', Value, 6);
    Index2 := PosEx('@', Value, Index + 1);
    if Index2 > 6 then
    begin
      if Index2 = Length(Value) then
        Index2 := Index;
      Result := Format('string: "%s"', [Copy(Value, Index2 + 1, Length(Value) - Index2 - 1)]);
    end;
    Exit;
  end;
  TmpDecName := AnsiString(PChar(@Value[1]));
  SetLength(UnDecName, BuffLen);
  SetLength(UnDecName, ImageHlp.UnDecorateSymbolName(@TmpDecName[1],
    @UnDecName[1], BuffLen, UNDNAME_NAME_ONLY));
  Result := string(UnDecName);
end;

function GetBinaryImageType(AStream: TStream): TBinaryImageType;
const
  ID_WORD = $FFFF;
  RES_BINARY_HEADER: array [0..7] of ULONG = (0, $20, ID_WORD, ID_WORD, 0, 0, 0, 0);
var
  StartPos: Int64;
  IDH: TImageDosHeader;
  NTH: TImageNtHeaders64;
  IFH: TImageFileHeader;
  EID: EIdent;
  Res: array [0..7] of ULONG;
begin
  Result := bitUnknown;
  StartPos := AStream.Position;
  try
    if AStream.Read(IDH, SizeOf(IDH)) = SizeOf(IDH) then
    begin
      if IDH.e_magic = IMAGE_DOS_SIGNATURE then
      begin
        AStream.Position := StartPos + IDH._lfanew;
        if AStream.Read(NTH, SizeOf(NTH)) = SizeOf(NTH) then
        begin
          if NTH.Signature = IMAGE_NT_SIGNATURE then
            case NTH.FileHeader.Machine of
              IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64: Exit(bitPe);
            end;
        end;
      end;
    end;
    AStream.Position := StartPos;
    if AStream.Read(EID, EI_NIDENT) = EI_NIDENT then
    begin
      if (EID.e_magic = ELF_MAGIC) and (EID.e_class in [ELFCLASS32, ELFCLASS64]) then
        Exit(bitElf);
    end;
    AStream.Position := StartPos;
    if AStream.Read(IFH, SizeOf(IFH)) = SizeOf(IFH) then
      case IFH.Machine of
        IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64: Exit(bitCoff);
      end;
    AStream.Position := StartPos;
    if AStream.Read(Res, SizeOf(Res)) = SizeOf(Res) then
      if CompareMem(@Res[0], @RES_BINARY_HEADER[0], SizeOf(Res)) then
        Result := bitRes;
  finally
   AStream.Position := StartPos
  end;
end;

end.
