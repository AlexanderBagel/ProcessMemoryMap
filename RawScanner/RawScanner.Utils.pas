////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Utils.pas
//  * Purpose   : Набор утилитарных методов общих для модулей RawScanner.
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2022.
//  * Version   : 1.0
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
  RawScanner.Types,
  RawScanner.Wow64;

  procedure SetNtQueryVirtualMemoryAddr(AddrRva: ULONG_PTR64);
  function ReadRemoteMemory(hProcess: THandle; const lpBaseAddress: ULONG_PTR64;
    lpBuffer: Pointer; nSize: SIZE_T): Boolean;
  function QueryWorkingSet64(hProcess: THandle; pv: Pointer; cb: DWORD): Boolean;
  function GetMappedFileName64(hProcess: THandle; lpv: ULONG_PTR64;
    lpFilename: LPCWSTR; nSize: DWORD): DWORD;
  function VirtualQueryEx64(hProcess: THandle; lpAddress: ULONG_PTR64;
    var lpBuffer: TMemoryBasicInformation64; dwLength: NativeUInt): DWORD;
  function GetMappedModule(ProcessHandle: THandle; AddrVa: ULONG_PTR64): string;

implementation

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

function NtQueryVirtualMemory64(FuncRVA: ULONG_PTR64; hProcess: THandle;
  BaseAddress: ULONG_PTR64; MemoryInformationClass: DWORD;
  MemoryInformation: Pointer; MemoryInformationLength: DWORD;
  ReturnLength: PULONG64): NTSTATUS; assembler; stdcall;
asm
  // выравниваем стек по 8-байтной границе
  mov eax, esp
  and eax, 7
  cmp eax, 0
  je @stack_aligned

  // если стек не выровнен, в EAX будет оффсет от ESP на сколько
  // сдвинулись данные на 32-битном стеке
  sub esp, eax

@stack_aligned:

  // переключение в 64 битный режим
  push $33                        // пишем новый сегмент кода
  db $E8, 0, 0, 0, 0              // call +5
  add [esp], 5                    // правим адрес возврата на идущий за retf
  retf // дальний возврат со сменой сегмента кода на CS:0х33 + адрес

  // следующий код выполняется в 64 битном режиме
  // в коментариях даны реально выполняющиеся инструкции

  push ebp                              // push rbp
  sub esp, $30                          // sub rsp, $30
  mov ebp, esp                          // mov rbp, rsp

  // параметры пришедшие из 32 бит лежат на стеке
  // нам их нужно только забрать в правильном порядке и по правильным оффсетам
  db $48 lea eax, [esp + eax + $60]     // lea rax, [rsp + rax + $60]

  // на 64 битный стек идут два параметра
  // 1. ReturnLength
  mov ecx, [eax]                        // mov ecx, dword ptr [rax]
  db $48 mov [esp + $28], ecx           // mov [rsp + $28], rcx

  // 2. и размер данных "MemoryInformationLength"
  mov ecx, [eax - 4]                    // mov ecx, dword ptr [rax - 4]
  db $48 mov [esp + $20], ecx           // mov [rsp + $20], rcx

  // регистр R9 содержит указатель на память (MemoryInformation),
  // куда будет помещаться результат
  db $44 mov ecx, [eax - 8]             // mov r9d, dword ptr [rax - 8]

  // регистр R8 содержит идентификатор MemoryInformationClass
  db $44 mov eax, [eax - $C]            // mov r8d, dword ptr [rax - $С]

  // регистр RDX содержит BaseAddress
  db $48 mov edx, [eax - $14]           // mov rdx, [rax - $14]

  // RCX должен содержать hProcess
  mov ecx, [eax - $18]                  // mov ecx, dword ptr [rax - $18]

  // осталось сделать вызов по адресу FuncRVA, идущий из 32 бит через стек
  call [eax - $20]                      // call [rax - $20]

  // подчищаем за собой 64 битный стек
  lea esp, [ebp + $30]                  // lea rsp, [rbp + $30]
  pop ebp                               // pop rbp

  // обратное переключение в 32 битный режим
  // важный момент, в 64 битах RETF всеравно требует два дворда на стеке (8 байт)
  // поэтому выход через два PUSH будет не правильным!!!
  db $E8, 0, 0, 0, 0              // call +5
  mov [esp + 4], $23              // mov dword ptr [rsp + 4], $23
  add [esp], $0D                  // add dword ptr [rsp], $0D
  retf                            // дальний возврат со сменой сегмента кода на CS:0х23 + адрес

  // начиная отсюда мы опять в 32 битном режиме

  // схлопываем фрейм стека нивелируя выравнивание по границе 8 байт
  // сделанное перед переключением в 64 битный режим
  mov esp, ebp
end;
{$ENDIF}

var
  NtQueryVirtualMemoryAddr: ULONG_PTR64 = 0;

procedure SetNtQueryVirtualMemoryAddr(AddrRva: ULONG_PTR64);
begin
  NtQueryVirtualMemoryAddr := AddrRva;
end;

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
function InternalNtQueryVirtualMemory64(FuncRVA: ULONG_PTR64; hProcess: THandle;
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
    Result := NtQueryVirtualMemory64(FuncRVA, hProcess, BaseAddress,
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
  if NtQueryVirtualMemoryAddr <> 0 then
  begin
    Status := InternalNtQueryVirtualMemory64(NtQueryVirtualMemoryAddr,
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
  if NtQueryVirtualMemoryAddr <> 0 then
  begin
    // чтобы не захламлять стек под локальную структуру TMappedFileName
    // сразу выделим под неё память
    MappedFileName := VirtualAlloc(nil,
      SizeOf(TMappedFileName), MEM_COMMIT, PAGE_READWRITE);
    try
      // после чего промежуточный вызов InternalNtQueryVirtualMemory64
      // будет не нужен, т.к. буфер для возвращаемого результата
      // уже будет выравнен по 8-байтной границе
      Status := NtQueryVirtualMemory64(NtQueryVirtualMemoryAddr, hProcess, lpv,
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
  if NtQueryVirtualMemoryAddr <> 0 then
  begin
    Status := InternalNtQueryVirtualMemory64(NtQueryVirtualMemoryAddr, hProcess,
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

end.
