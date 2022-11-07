////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.ApiSet.pas
//  * Purpose   : Класс для обработки ApiSet редиректа импорта/экспорта
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2022.
//  * Version   : 1.0.1
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.ApiSet;

interface

uses
  Windows,
  Classes,
  SysUtils,
  Generics.Collections,
  RawScanner.Logger;

type
  // перенаправление экспорта штатных библиотек через ApiSet для поддержки MinWin

  // https://github.com/lucasg/Dependencies/blob/master/ClrPhlib/include/ApiSet.h
  // https://lucasg.github.io/2017/10/15/Api-set-resolution/
  // https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-i.html
  // https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-ii.html

{$A4} // обязательное выравнивание структур

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
    Flags,                  // according to Geoff Chappell,  tells if the map is sealed or not.
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
    FApiSetVer: ULONG;
    FUniqueCount: Integer;
    FData: TDictionary<string, string>;
    procedure AddRedirection(Key, Value: string);
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
    property Version: ULONG read FApiSetVer;
    property Count: Integer read FUniqueCount;
  end;

  function ApiSetRedirector: TApiSetRedirector;

implementation

function ApiSetRedirector: TApiSetRedirector;
begin
  Result := TApiSetRedirector.GetInstance;
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
    // вторая и четвертая версии аписета не содержат префиксов "api-" и "ext-"
    // хотя экспорт в библиотеках его имеет, поэтому придется добавлять ручками
    if not (Key.StartsWith(api) or Key.StartsWith(ext)) then
    begin
      // правда как определить какой префикс верный - не известно
      // поэтому добавляем оба!
      FData.Add(api + Key, Value);
      FData.Add(ext + Key, Value);
    end;
  end;
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
  NameSpaceEntry := PApiSetNameSpaceEntry2(PByte(FApiSet) + SizeOf(TApiSetNameSpace2));
  for I := 0 to PApiSetNameSpace2(FApiSet)^.Count - 1 do
  begin
    LibFrom := GetString(NameSpaceEntry.Name).ToLower;
    ValueEntry := Pointer(PByte(FApiSet) + NameSpaceEntry.DataOffset);
    EntryRedirection := Pointer(PByte(FApiSet) +
      NameSpaceEntry.DataOffset + SizeOf(TApiSetValueEntry2));
    for A := 0 to ValueEntry.NumberOfRedirections - 1 do
    begin
      Redirection := GetString(EntryRedirection.Value);
      Key := LibFrom + GetString(EntryRedirection.Name);
      AddRedirection(Key, Redirection);
      Inc(EntryRedirection);
    end;
    Inc(NameSpaceEntry);
  end;
  RawScannerLogger.Info(llApiSet,
    'ApiSet V2 initialized. Entries count: ' + IntToStr(FUniqueCount));
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
  NameSpaceEntry := PApiSetNameSpaceEntry4(PByte(FApiSet) + SizeOf(TApiSetNameSpace4));
  for I := 0 to PApiSetNameSpace4(FApiSet)^.Count - 1 do
  begin
    LibFrom := GetString(NameSpaceEntry.Name);
    ValueEntry := Pointer(PByte(FApiSet) + NameSpaceEntry.DataOffset);
    EntryRedirection := Pointer(PByte(FApiSet) +
      NameSpaceEntry.DataOffset + SizeOf(TApiSetValueEntry4));
    for A := 0 to ValueEntry.NumberOfRedirections - 1 do
    begin
      Redirection := GetString(EntryRedirection.Value);
      Key := LibFrom + GetString(EntryRedirection.Name);
      AddRedirection(Key, Redirection);
      Inc(EntryRedirection);
    end;
    Inc(NameSpaceEntry);
  end;
  RawScannerLogger.Info(llApiSet,
    'ApiSet V4 initialized. Entries count: ' + IntToStr(FUniqueCount));
end;

procedure TApiSetRedirector.Init6;
var
  I, A: Integer;
  NameSpaceEntry: PApiSetNameSpaceEntry6;
  ValueEntry: PApiSetValueEntry6;
  LibFrom: string;
  Key, Redirection: string;
begin
  NameSpaceEntry := PApiSetNameSpaceEntry6(PByte(FApiSet) +
    PApiSetNameSpace6(FApiSet)^.EntryOffset);
  for I := 0 to PApiSetNameSpace6(FApiSet)^.Count - 1 do
  begin

    // в шестой версии ApiSet появилось поле NameSpaceEntry.HashedLength
    // оно содержит длину строки с которой считался хэш.
    // Это собственно полная длина строки минус суффикс.
    // HashedLength = api-ms-win-core-apiquery-l1-1-0 -> len(api-ms-win-core-apiquery-l1-1)
    // Поэтому сразу отрезаем суффикс, т.к. мы не используем хэш, для этого у нас есть словарь
    LibFrom := RemoveSuffix(GetString(NameSpaceEntry.Name));

    ValueEntry := Pointer(PByte(FApiSet) + NameSpaceEntry.ValueOffset);
    for A := 0 to NameSpaceEntry.ValueCount - 1 do
    begin
      // Теперь как хранятся записи о перенаправлениях:

      // вот это реальное пренаправление, имя библиотеки куда произойдет редирект
      Redirection := GetString(ValueEntry.Value);

      // а это имя библиотеки для которой включен дополнительный редирект (обычно пустое)
      Key := LibFrom + GetString(ValueEntry.Name);

      // например oleaut32.dll имеет в экспорте запись об TlsSetValue
      // которую экспортирует api-ms-win-core-processthreads-l1-1-0.dll
      // по умолчанию для таких библиотек включается перенаправление на kernel32.dll
      // но и сам kernel32.dll в таблице импорта имеет запись об TlsSetValue
      // причем из той-же библиотеки api-ms-win-core-processthreads-l1-1-0.dll
      // Вот для такой ситуации в ApiSet включена запись что kernel32.dll
      // должна быть перенаправлена не в саму себя, а в kernelbase.dll
      // таким образом, для библиотек с дополнительным перенаправлением
      // мы формируем ключ с записью о самой библиотеке (оно будет в ValueEntry.Name)
      // а для остальных библиотек ValueEntry.Name будет пустым

      // финализируя:
      // Key для всех = api-ms-win-core-processthreads-l1-1
      // Key для kernel32.dll = api-ms-win-core-processthreads-l1-1kernel32.dll

      // но, кстати, не все записи имеют перенаправление, например для модулей ядра:
      {
        ext-ms-win-ntos-dg-l1-1
        ext-ms-win-ntos-ksecurity-l1-1
        ext-ms-win-ntos-ksr-l1-1
        ext-ms-win-ntos-processparameters-l1-1
        ext-ms-win-ntos-stateseparation-l1-1
        ext-ms-win-ntos-trace-l1-1
        ext-ms-win-ntos-vail-l1-1
      }
      // эти записи присутствует в таблице импорта например ntoskrnl.exe
      // этот модуль может быть подгружен в адресное пространство процесса
      // но его таблица импорта будет свернута в самого себя на заглушки
      // поэтому такие модули с IMAGE_SUBSYSTEM_NATIVE не обрабатываются.
      if not Redirection.IsEmpty then
      begin
        Inc(FUniqueCount);
        FData.AddOrSetValue(Key, Redirection);
      end;

      Inc(ValueEntry);
    end;
    Inc(NameSpaceEntry);
  end;
  RawScannerLogger.Info(llApiSet,
    'ApiSet V6 initialized. Entries count: ' + IntToStr(FUniqueCount));
end;

procedure TApiSetRedirector.LoadApiSet(AStream: TCustomMemoryStream);
begin
  FApiSetVer := 0;
  FUniqueCount := 0;
  FData.Clear;
  if Assigned(AStream) then
    FApiSet := AStream.Memory
  else
    FApiSet := GetPEBApiSet;
  // обязательная проверка, а есть ли вообще ApiSet?
  // Например на Windows XP SP3 (х86) его нет.
  if Assigned(FApiSet) then
    Init
  else
    RawScannerLogger.Info(llApiSet, 'ApiSet disabled');
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
  // сначала получаем с привязкой к текущей библиотеке
  Result := FData.TryGetValue(Tmp + LibName.ToLower, RedirectTo);
  // а если нет записи, то получаем перенаправление по умолчанию
  if not Result then
    Result := FData.TryGetValue(Tmp, RedirectTo);
end;

end.
