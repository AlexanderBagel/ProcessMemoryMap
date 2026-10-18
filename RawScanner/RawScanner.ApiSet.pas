////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : RawScanner.ApiSet.pas
//  * Purpose   : Class for handling ApiSet import/export redirects
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

unit RawScanner.ApiSet;

interface

  {$I rawscanner.inc}

uses
  Windows,
  Classes,
  SysUtils,
  Generics.Collections,
  {$IFNDEF DISABLE_LOGGER}
  RawScanner.Logger,
  {$ENDIF}
  RawScanner.SymbolStorage,
  RawScanner.Types;

type
  // https://github.com/lucasg/Dependencies/blob/master/ClrPhlib/include/ApiSet.h
  // https://lucasg.github.io/2017/10/15/Api-set-resolution/
  // https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-i.html
  // https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-ii.html

{$A4}

  TApiSetString = record
    Offset: ULONG;
    Length: USHORT;
  end;

  // ver 2 =====================================================================

  PApiSetNameSpace2 = ^TApiSetNameSpace2;
  TApiSetNameSpace2 = record
    Version,
    Count: ULONG;
    // === > array TApiSetNameSpaceEntry2
  end;

  PApiSetNameSpaceEntry2 = ^TApiSetNameSpaceEntry2;
  TApiSetNameSpaceEntry2 = record
    Name: TApiSetString;
    DataOffset: ULONG; // === > TApiSetValueEntry2
  end;

  PApiSetValueEntry2 = ^TApiSetValueEntry2;
  TApiSetValueEntry2 = record
    NumberOfRedirections: ULONG;
    // === > array TApiSetValueEntryRedirection2
  end;

  PApiSetValueEntryRedirection2 = ^TApiSetValueEntryRedirection2;
  TApiSetValueEntryRedirection2 = record
    Name: TApiSetString;
    Value: TApiSetString;
  end;

  // ver 4 =====================================================================

  PApiSetNameSpace4 = ^TApiSetNameSpace4;
  TApiSetNameSpace4 = record
    Version,
    Size,
    Flags,
    Count: ULONG;
    // === > array TApiSetNameSpaceEntry4
  end;

  PApiSetNameSpaceEntry4 = ^TApiSetNameSpaceEntry4;
  TApiSetNameSpaceEntry4 = record
    Flags: ULONG;
    Name: TApiSetString;
    Alias: TApiSetString;
    DataOffset: ULONG; // === > TApiSetValueEntry4
  end;

  PApiSetValueEntry4 = ^TApiSetValueEntry4;
  TApiSetValueEntry4 = record
    Flags,
    NumberOfRedirections: ULONG;
    // === > array TApiSetValueEntryRedirection4
  end;

  PApiSetValueEntryRedirection4 = ^TApiSetValueEntryRedirection4;
  TApiSetValueEntryRedirection4 = record
    Flags: ULONG;
    Name: TApiSetString;
    Value: TApiSetString;
  end;

  // ver 6 =====================================================================

  PApiSetNameSpace6 = ^TApiSetNameSpace6;
  TApiSetNameSpace6 = record
    Version,                // v2 on Windows 7, v4 on Windows 8.1 and v6 on Windows 10
    Size,                   // apiset map size (usually the .apiset section virtual size)
    Flags,                  // according to Geoff Chappell, tells if the map is sealed or not.
    Count,                  // hash table entry count
    EntryOffset,            // Offset to the api set entries values
    HashOffset,             // Offset to the api set entries hash indexes
    HashFactor: ULONG;      // multiplier to use when computing hash
  end;

  PApiSetNameSpaceEntry6 = ^TApiSetNameSpaceEntry6;
  TApiSetNameSpaceEntry6 = record
    Flags: ULONG;           // sealed flag in bit 0
    Name: TApiSetString;    // Offset to the ApiSet library name PWCHAR (e.g. "api-ms-win-core-job-l2-1-1")
    HashedLength: ULONG;    // Apiset library name length
    ValueOffset,            // Offset the list of hosts library implement the apiset contract (points to API_SET_VALUE_ENTRY array)
    ValueCount: ULONG;      // Number of hosts libraries
  end;

  PApiSetValueEntry6 = ^TApiSetValueEntry6;
  TApiSetValueEntry6 = record
    Flags: ULONG;           // sealed flag in bit 0
    Name: TApiSetString;    // Offset to the ApiSet library name PWCHAR (e.g. "api-ms-win-core-job-l2-1-1")
    Value: TApiSetString;   // Offset to the Host library name PWCHAR (e.g. "ucrtbase.dll")
  end;

  PApiSetHashEntry6 = ^TApiSetHashEntry6;
  TApiSetHashEntry6 = record
    Hash,
    Index: ULONG;
  end;

  TApiSetRedirector = class
  private const
    api = 'api-';
    ext = 'ext-';
  private
    class var FInstance: TApiSetRedirector;
    class destructor ClassDestroy;
  strict private
    FApiSet: Pointer;
    FApiSetSize,
    FApiSetVer: ULONG;
    FSymbolData: TSymbolData;
    FRemoteVA: ULONG_PTR64;
    FUniqueCount: Integer;
    FData: TDictionary<string, string>;
    procedure AddRedirection(Key, Value: string);
    procedure AddSymbol(AddrVA: ULONG_PTR64; SymType: TSymbolDataType);
    function RemoveSuffix(const Value: string): string;
    function GetString(Value: TApiSetString): string;
    function GetPEBApiSet: Pointer;
    procedure Init2;
    procedure Init4;
    procedure Init6;
    procedure Init;
  public
    constructor Create;
    destructor Destroy; override;
    class function GetInstance: TApiSetRedirector;
    function SchemaPresent(const LibName: string;
      var RedirectTo: string): Boolean;
    procedure LoadApiSet(AStream: TCustomMemoryStream = nil);
    property Count: Integer read FUniqueCount;
    property RemoteApiSetVA: ULONG_PTR64 read FRemoteVA write FRemoteVA;
    property Version: ULONG read FApiSetVer;
  end;

  function ApiSetRedirector: TApiSetRedirector;

implementation

function ApiSetRedirector: TApiSetRedirector;
begin
  Result := TApiSetRedirector.GetInstance;
end;

procedure Info(const Description: string);
begin
  {$IFNDEF DISABLE_LOGGER}
  RawScannerLogger.Info(llApiSet, Description);
  {$ENDIF}
end;

{ TApiSetRedirector }

procedure TApiSetRedirector.AddRedirection(Key, Value: string);
begin
  if not Value.IsEmpty then
  begin
    Key := Key.ToLower;
    Value := Value.ToLower;
    FData.Add(Key, Value);
    Inc(FUniqueCount);

    // The second and fourth versions of ApiSet do not include the "api-" and "ext-" prefixes
    // even though the exports in the libraries do have them, so you'll have to add them manually

    // [ru] Вторая и четвертая версии ApiSet не содержат префиксов "api-" и "ext-"
    // хотя экспорт в библиотеках его имеет, поэтому придется добавлять ручками

    if not (Key.StartsWith(api) or Key.StartsWith(ext)) then
    begin

      // It's not clear how to determine which prefix is correct -
      // so we add both!

      // [ru] Правда, как определить, какой префикс верный - неизвестно
      // поэтому добавляем оба!

      FData.Add(api + Key, Value);
      FData.Add(ext + Key, Value);
    end;
  end;
end;

procedure TApiSetRedirector.AddSymbol(AddrVA: ULONG_PTR64;
  SymType: TSymbolDataType);
begin
  if SymType = sdtApiSetNS then
    FSymbolData.ApiSet.NameSpaceSize := FApiSetSize;
  FSymbolData.AddrVA := AddrVA - ULONG_PTR64(FApiSet) + RemoteApiSetVA;
  FSymbolData.DataType := SymType;
  SymbolStorage.Add(FSymbolData);
end;

class destructor TApiSetRedirector.ClassDestroy;
begin
  FInstance.Free;
end;

constructor TApiSetRedirector.Create;
begin
  if FInstance = nil then
    FInstance := Self;
  FData := TDictionary<string, string>.Create;
end;

destructor TApiSetRedirector.Destroy;
begin
  FInstance := nil;
  FData.Free;
  inherited;
end;

class function TApiSetRedirector.GetInstance: TApiSetRedirector;
begin
  if FInstance = nil then
    TApiSetRedirector.Create;
  Result := FInstance;
end;

function TApiSetRedirector.GetPEBApiSet: Pointer;
asm
  {$IFDEF WIN32}
  mov eax, fs:[30h]
  mov eax, [eax + 38h]
  {$ELSE}
  mov rax, gs:[60h]
  mov rax, [rax + 68h]
  {$ENDIF}
end;

function TApiSetRedirector.GetString(Value: TApiSetString): string;
var
  pMem: PByte;
  Buff: array of Byte;
begin
  pMem := FApiSet;
  Inc(pMem, Value.Offset);
  SetLength(Buff, Value.Length + 2);
  Move(pMem^, Buff[0], Value.Length);
  Result := string(PWideChar(@Buff[0]));
end;

procedure TApiSetRedirector.Init;
begin
  FApiSetVer := PLONG(FApiSet)^;

  // Initialization for symbol filling
  // [ru] Инициализация под заполнение символов

  FSymbolData.ApiSet.Version := FApiSetVer;

  case FApiSetVer of
    2: Init2;
    4: Init4;
    6: Init6;
  end;
end;

procedure TApiSetRedirector.Init2;
var
  I, A: Integer;
  NameSpaceEntry: PApiSetNameSpaceEntry2;
  ValueEntry: PApiSetValueEntry2;
  EntryRedirection: PApiSetValueEntryRedirection2;
  LibFrom: string;
  Key, Redirection: string;
begin
  FApiSetSize := 0;
  AddSymbol(ULONG64(FApiSet), sdtApiSetNS);

  NameSpaceEntry := PApiSetNameSpaceEntry2(PByte(FApiSet) + SizeOf(TApiSetNameSpace2));
  for I := 0 to PApiSetNameSpace2(FApiSet)^.Count - 1 do
  begin
    AddSymbol(ULONG64(NameSpaceEntry), sdtApiSetNSEntry);
    LibFrom := GetString(NameSpaceEntry.Name).ToLower;
    ValueEntry := Pointer(PByte(FApiSet) + NameSpaceEntry.DataOffset);
    AddSymbol(ULONG64(ValueEntry), sdtApiSetValueEntry);
    EntryRedirection := Pointer(PByte(ValueEntry) + SizeOf(TApiSetValueEntry2));
    for A := 0 to ValueEntry.NumberOfRedirections - 1 do
    begin
      AddSymbol(ULONG64(EntryRedirection), sdtApiSetRedirection);
      Redirection := GetString(EntryRedirection.Value);
      Key := LibFrom + GetString(EntryRedirection.Name);
      AddRedirection(Key, Redirection);
      Inc(EntryRedirection);
    end;
    Inc(NameSpaceEntry);
  end;
  Info('ApiSet V2 initialized. Entries count: ' + IntToStr(FUniqueCount));
end;

procedure TApiSetRedirector.Init4;
var
  I, A: Integer;
  NameSpaceEntry: PApiSetNameSpaceEntry4;
  ValueEntry: PApiSetValueEntry4;
  EntryRedirection: PApiSetValueEntryRedirection4;
  LibFrom: string;
  Key, Redirection: string;
begin
  FApiSetSize := PApiSetNameSpace4(FApiSet).Size;
  AddSymbol(ULONG64(FApiSet), sdtApiSetNS);

  NameSpaceEntry := PApiSetNameSpaceEntry4(PByte(FApiSet) + SizeOf(TApiSetNameSpace4));
  for I := 0 to PApiSetNameSpace4(FApiSet)^.Count - 1 do
  begin
    AddSymbol(ULONG64(NameSpaceEntry), sdtApiSetNSEntry);
    LibFrom := GetString(NameSpaceEntry.Name);

    ValueEntry := Pointer(PByte(FApiSet) + NameSpaceEntry.DataOffset);
    AddSymbol(ULONG64(ValueEntry), sdtApiSetValueEntry);

    EntryRedirection := Pointer(PByte(ValueEntry) + SizeOf(TApiSetValueEntry4));
    for A := 0 to ValueEntry.NumberOfRedirections - 1 do
    begin
      AddSymbol(ULONG64(EntryRedirection), sdtApiSetRedirection);
      Redirection := GetString(EntryRedirection.Value);
      Key := LibFrom + GetString(EntryRedirection.Name);
      AddRedirection(Key, Redirection);
      Inc(EntryRedirection);
    end;
    Inc(NameSpaceEntry);
  end;
  Info('ApiSet V4 initialized. Entries count: ' + IntToStr(FUniqueCount));
end;

procedure TApiSetRedirector.Init6;
var
  I, A: Integer;
  NameSpaceEntry: PApiSetNameSpaceEntry6;
  ValueEntry: PApiSetValueEntry6;
  HashEntry: PApiSetHashEntry6;
  LibFrom: string;
  Key, Redirection: string;
begin
  FApiSetSize := PApiSetNameSpace6(FApiSet).Size;
  AddSymbol(ULONG64(FApiSet), sdtApiSetNS);

  NameSpaceEntry := PApiSetNameSpaceEntry6(PByte(FApiSet) +
    PApiSetNameSpace6(FApiSet)^.EntryOffset);
  HashEntry := PApiSetHashEntry6(PByte(FApiSet) +
    PApiSetNameSpace6(FApiSet)^.HashOffset);
  for I := 0 to PApiSetNameSpace6(FApiSet)^.Count - 1 do
  begin

    AddSymbol(ULONG64(NameSpaceEntry), sdtApiSetNSEntry);
    AddSymbol(ULONG64(HashEntry), sdtApiSetHashEntry);

    // The NameSpaceEntry.HashedLength field was introduced in version 6 of ApiSet.
    // It contains the length of the string from which the hash was calculated.
    // This is actually the total length of the string minus the suffix.
    // HashedLength = api-ms-win-core-apiquery-l1-1-0 -> len(api-ms-win-core-apiquery-l1-1)
    // Therefore, we immediately remove the suffix,
    // since we don't use the hash (we have a dictionary for that)

    // [ru] В шестой версии ApiSet появилось поле NameSpaceEntry.HashedLength
    // оно содержит длину строки, с которой считался хэш.
    // Это собственно полная длина строки минус суффикс.
    // HashedLength = api-ms-win-core-apiquery-l1-1-0 -> len(api-ms-win-core-apiquery-l1-1)
    // Поэтому сразу отрезаем суффикс,
    // т.к. мы не используем хэш (для этого у нас есть словарь)

    LibFrom := GetString(NameSpaceEntry.Name);
    SetLength(LibFrom, NameSpaceEntry.HashedLength div SizeOf(Char));

    ValueEntry := Pointer(PByte(FApiSet) + NameSpaceEntry.ValueOffset);
    for A := 0 to NameSpaceEntry.ValueCount - 1 do
    begin

      // Here's how redirection records are stored:
      // [ru] Вот как хранятся записи о перенаправлениях:

      AddSymbol(ULONG64(ValueEntry), sdtApiSetValueEntry);

      // This is a real redirect, the name of the library to which the redirect will take place
      // [ru] Вот это реальное перенаправление, имя библиотеки, куда произойдёт редирект

      Redirection := GetString(ValueEntry.Value);

      // and this is the name of the library for which an additional redirect is enabled
      // (usually empty)
      // [ru] а это имя библиотеки, для которой включён дополнительный редирект
      // (обычно пустое)

      Key := LibFrom + GetString(ValueEntry.Name);

      // = [EN] ================================================================

      // For example, oleaut32.dll has an import entry for TlsSetValue
      // which is exported by api-ms-win-core-processthreads-l1-1-0.dll
      // By default, redirection to kernel32.dll is enabled for such libraries
      // but kernel32.dll itself also has an entry for TlsSetValue in its import table
      // and it comes from the same library, api-ms-win-core-processthreads-l1-1-0.dll
      // For this situation, ApiSet includes an entry specifying that kernel32.dll
      // should be redirected not to itself, but to kernelbase.dll
      // Thus, for libraries with additional redirection
      // we create a key with an entry for the library itself (this will be in ValueEntry.Name)
      // and for the remaining libraries, ValueEntry.Name will be empty

      // To wrap up:
      // Key for all = api-ms-win-core-processthreads-l1-1
      // Key for kernel32.dll = api-ms-win-core-processthreads-l1-1kernel32.dll

      // But, by the way, not all entries have redirects, for example, those for kernel modules:
      {
        ext-ms-win-ntos-dg-l1-1
        ext-ms-win-ntos-ksecurity-l1-1
        ext-ms-win-ntos-ksr-l1-1
        ext-ms-win-ntos-processparameters-l1-1
        ext-ms-win-ntos-stateseparation-l1-1
        ext-ms-win-ntos-trace-l1-1
        ext-ms-win-ntos-vail-l1-1
      }
      // These entries are present in the import table of, for example, ntoskrnl.exe
      // This module can be loaded into a process's address space
      // but its import table will be rolled up into itself using placeholders
      // Therefore, modules with IMAGE_SUBSYSTEM_NATIVE are not processed.

      // = [RU] ================================================================

      // Например, oleaut32.dll имеет в импорте запись о TlsSetValue
      // которую экспортирует api-ms-win-core-processthreads-l1-1-0.dll
      // по умолчанию для таких библиотек включается перенаправление на kernel32.dll
      // но и сам kernel32.dll в таблице импорта имеет запись о TlsSetValue
      // причем из той же библиотеки api-ms-win-core-processthreads-l1-1-0.dll
      // Вот для такой ситуации в ApiSet включена запись, что kernel32.dll
      // должна быть перенаправлена не в саму себя, а в kernelbase.dll
      // Таким образом, для библиотек с дополнительным перенаправлением
      // мы формируем ключ с записью о самой библиотеке (это будет в ValueEntry.Name)
      // а для остальных библиотек ValueEntry.Name будет пустым

      // Подводя итог:
      // Key для всех = api-ms-win-core-processthreads-l1-1
      // Key для kernel32.dll = api-ms-win-core-processthreads-l1-1kernel32.dll

      // Но, кстати, не все записи имеют перенаправление, например для модулей ядра:
      {
        ext-ms-win-ntos-dg-l1-1
        ext-ms-win-ntos-ksecurity-l1-1
        ext-ms-win-ntos-ksr-l1-1
        ext-ms-win-ntos-processparameters-l1-1
        ext-ms-win-ntos-stateseparation-l1-1
        ext-ms-win-ntos-trace-l1-1
        ext-ms-win-ntos-vail-l1-1
      }
      // Эти записи присутствуют в таблице импорта, например, ntoskrnl.exe
      // Этот модуль может быть подгружен в адресное пространство процесса
      // но его таблица импорта будет свернута в саму себя на заглушки
      // Поэтому такие модули с IMAGE_SUBSYSTEM_NATIVE не обрабатываются.

      // =======================================================================

      if not Redirection.IsEmpty then
      begin
        Inc(FUniqueCount);
        FData.AddOrSetValue(Key, Redirection);
      end;

      Inc(ValueEntry);
    end;
    Inc(NameSpaceEntry);
    Inc(HashEntry);
  end;
  Info('ApiSet V6 initialized. Entries count: ' + IntToStr(FUniqueCount));
end;

procedure TApiSetRedirector.LoadApiSet(AStream: TCustomMemoryStream);
begin
  FApiSetVer := 0;
  FUniqueCount := 0;
  FData.Clear;
  if Assigned(AStream) then
    FApiSet := AStream.Memory
  else
    if CheckWin32Version(6, 1) then
      FApiSet := GetPEBApiSet
    else
      FApiSet := nil;

  // ApiSet is actually read from our process, so to remap
  // it to a remote address space, we need to store both bases

  // [ru] ApiSet по факту читается из нашего процесса, поэтому для ремапинга
  // на удаленное адресное пространство нужно сохранить обе базы

  if FRemoteVA = 0 then
    FRemoteVA := ULONG_PTR64(FApiSet);
  FSymbolData.ApiSet.RemoteVA := FRemoteVA;
  FSymbolData.ApiSet.OriginalVA := ULONG_PTR64(FApiSet);

  // We need to check whether ApiSet is even present.
  // For example, it's not present on Windows XP SP3 (x86).

  // [ru] Обязательная проверка, есть ли вообще ApiSet.
  // Например, на Windows XP SP3 (x86) его нет.

  if Assigned(FApiSet) then
    Init
  else
    Info('ApiSet disabled');
end;

function TApiSetRedirector.RemoveSuffix(const Value: string): string;
var
  LastSuffixIndex: Integer;
begin
  if FApiSetVer = 6 then
  begin
    LastSuffixIndex := Value.LastDelimiter('-');
    if LastSuffixIndex > 0 then
      Exit(Copy(Value, 1, LastSuffixIndex));
  end;
  Result := Value;
end;

function TApiSetRedirector.SchemaPresent(const LibName: string;
  var RedirectTo: string): Boolean;
var
  Tmp: string;
begin
  if FData.Count = 0 then Exit(False);
  Tmp := RemoveSuffix(RedirectTo.ToLower);

  // First, we retrieve it with a reference to the current library
  // [ru] Сначала получаем с привязкой к текущей библиотеке

  Result := FData.TryGetValue(Tmp + LibName.ToLower, RedirectTo);

  // And if there is no record, we get the default redirect
  // [ru] А если нет записи, то получаем перенаправление по умолчанию

  if not Result then
    Result := FData.TryGetValue(Tmp, RedirectTo);
end;

end.
