////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Utils.pas
//  * Purpose   : Набор утилитарных методов общих для модулей RawScanner.
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.0.8
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.Utils;

interface

uses
  Windows,
  SysUtils,
  PsApi,
  ImageHlp,
  StrUtils,
  RawScanner.Types,
  RawScanner.Wow64,
  RawScanner.X64Gates;

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

implementation

type
  TNtQueryVirtualMemory64 = function(hProcess: THandle;
    BaseAddress: ULONG_PTR64; MemoryInformationClass: DWORD;
    MemoryInformation: Pointer; MemoryInformationLength: DWORD;
    ReturnLength: PULONG64): NTSTATUS; stdcall;

var
  // 64 битная NtQueryVirtualMemory инициализируется из RawScanner.Core
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
  // Буфер для данных (MemoryInformation) должен быть выровнен
  // по 8-байтной границе, в противном случае вернется ошибка
  // STATUS_DATATYPE_MISALIGNMENT
  AlignedBuff := VirtualAlloc(nil,
    MemoryInformationLength, MEM_COMMIT, PAGE_READWRITE);
  try
    Result := NtQueryVirtualMemory64(hProcess, BaseAddress,
      MemoryInformationClass, AlignedBuff, MemoryInformationLength,
      ReturnLength);
    // анализировать результат тут не нужно, т.к. например вызов
    // MemoryWorkingSetList вернет STATUS_INFO_LENGTH_MISMATCH не заполнив
    // поле uReturnLength, но данные о необходимом размере будут помещены
    // в переданый буфер AlignedBuff, и их нужно вернуть вызывающему коду
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

  // если мы в чистой 32 битной ОС то просто производим 32 битный вызов
  // с перекидыванием результата в массив с 64 битными адресами
  if not Wow64Support.Use64AddrMode then
  begin
    Result := QueryWorkingSet32(hProcess, pv, cb);
    Exit;
  end;

  // в противном случае нам нужен полный WorkSet с 64 битными страницами
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

  // из диапазона пользовательских адресов путь к отмапленому файлу можно
  // получить вызовом штатной АПИ
  if lpv < MM_HIGHEST_USER_ADDRESS then
  begin
    Result := GetMappedFileName(hProcess, Pointer(lpv), lpFilename, nSize);
    Exit;
  end;

  // но по старшим адресам это можно сделать
  // только вызовом 64-битной NtQueryVirtualMemory проэмулировав реализацию
  // GetMappedFileName
  Result := 0;
  if Assigned(NtQueryVirtualMemory64) then
  begin
    // чтобы не захламлять стек под локальную структуру TMappedFileName
    // сразу выделим под неё память
    MappedFileName := VirtualAlloc(nil,
      SizeOf(TMappedFileName), MEM_COMMIT, PAGE_READWRITE);
    try
      // после чего промежуточный вызов InternalNtQueryVirtualMemory64
      // будет не нужен, т.к. буфер для возвращаемого результата
      // уже будет выравнен по 8-байтной границе
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
    // если вызов успешен, перекидываем данные из 32 битной структуры в 64
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
  // аналог функции SymUnDNameInternal используемой символами
  Result := Value;
  if Result = EmptyStr then Exit;
  if (Result[1] = '?') or Result.StartsWith('.?') or Result.StartsWith('..?') then
  begin
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

end.
