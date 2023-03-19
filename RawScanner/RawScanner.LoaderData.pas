////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.LoaderData.pas
//  * Purpose   : Класс получает список загруженых модулей процесса
//  *           : на основе прямого чтения списка LOADER_DATA из памяти процеса.
//  *           : Работает и с 32 и с 64 битными процессами, но нужен в оновном
//  *           : для 32 битных процессов, которым нужно получить информацию об
//  *           : 64 битных библиотеках.
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

unit RawScanner.LoaderData;

interface

  {$I rawscanner.inc}

uses
  Windows,
  SysUtils,
  Classes,
  {$IFNDEF DISABLE_LOGGER}
  RawScanner.Logger,
  {$ENDIF}
  RawScanner.SymbolStorage,
  RawScanner.Types,
  RawScanner.Wow64,
  RawScanner.Utils;

const
  LDRP_STATIC_LINK                = $00000002;
  LDRP_IMAGE_DLL                  = $00000004;
  LDRP_SHIMENG_SUPPRESSED_ENTRY   = $00000008; // ReactOS https://doxygen.reactos.org/d1/d97/ldrtypes_8h_source.html
  LDRP_IMAGE_INTEGRITY_FORCED     = $00000020; // ReactOS https://doxygen.reactos.org/d1/d97/ldrtypes_8h_source.html
  LDRP_LOAD_IN_PROGRESS           = $00001000;
  LDRP_UNLOAD_IN_PROGRESS         = $00002000;
  LDRP_ENTRY_PROCESSED            = $00004000;
  LDRP_ENTRY_INSERTED             = $00008000;
  LDRP_CURRENT_LOAD               = $00010000;
  LDRP_FAILED_BUILTIN_LOAD        = $00020000;
  LDRP_DONT_CALL_FOR_THREADS      = $00040000;
  LDRP_PROCESS_ATTACH_CALLED      = $00080000;
  LDRP_DEBUG_SYMBOLS_LOADED       = $00100000;
  LDRP_IMAGE_NOT_AT_BASE          = $00200000;
  LDRP_COR_IMAGE                  = $00400000;
  LDRP_COR_OWNS_UNMAP             = $00800000;
  LDRP_SYSTEM_MAPPED              = $01000000;
  LDRP_IMAGE_VERIFYING            = $02000000;
  LDRP_DRIVER_DEPENDENT_DLL       = $04000000;
  LDRP_ENTRY_NATIVE               = $08000000;
  LDRP_REDIRECTED                 = $10000000;
  LDRP_NON_PAGED_DEBUG_INFO       = $20000000;
  LDRP_MM_LOADED                  = $40000000;

type
  TLoaderData = class
  private
    FProcess: THandle;
    FRootModule: TModuleData;
    FModuleList: TModuleList;
    FUse64Addr: Boolean;
    function Scan32LdrData(LdrAddr: ULONG_PTR64): Integer;
    function Scan64LdrData(LdrAddr: ULONG_PTR64): Integer;
  public
    constructor Create(AProcess: THandle; AUse64Addr: Boolean);
    destructor Destroy; override;
    function Load32LoaderData(LdrAddr: ULONG_PTR64): Integer;
    function Load64LoaderData(LdrAddr: ULONG_PTR64): Integer;
    property RootModule: TModuleData read FRootModule;
    property Modules: TModuleList read FModuleList;
  end;

implementation

procedure Error(const Description: string);
begin
  {$IFNDEF DISABLE_LOGGER}
  RawScannerLogger.Error(llLoader, Description);
  {$ENDIF}
end;

procedure Warn(const Description: string); overload;
begin
  {$IFNDEF DISABLE_LOGGER}
  RawScannerLogger.Warn(llLoader, Description);
  {$ENDIF}
end;

type
  LIST_ENTRY32 = record
    FLink, BLink: ULONG;
  end;

  PEB_LDR_DATA32 = record
    Length: ULONG;
    Initialized: BOOL;
    SsHandle: ULONG;
    InLoadOrderModuleList: LIST_ENTRY32;
    InMemoryOrderModuleList: LIST_ENTRY32;
    InInitializationOrderModuleList: LIST_ENTRY32;
    // etc...
  end;

  // https://geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm

  LDR_DATA_TABLE_ENTRY32 = record
    InLoadOrderLinks: LIST_ENTRY32;
    InMemoryOrderLinks: LIST_ENTRY32;
    InInitializationOrderLinks: LIST_ENTRY32;
    DllBase: ULONG;
    EntryPoint: ULONG;
    SizeOfImage: ULONG;
    FullDllName: UNICODE_STRING32;
    BaseDllName: UNICODE_STRING32;
    Flags: ULONG;
    // etc...
  end;

  LIST_ENTRY64 = record
    FLink, BLink: ULONG_PTR64;
  end;

  PEB_LDR_DATA64 = record
    Length: ULONG;
    Initialized: BOOL;
    SsHandle: ULONG_PTR64;
    InLoadOrderModuleList: LIST_ENTRY64;
    InMemoryOrderModuleList: LIST_ENTRY64;
    InInitializationOrderModuleList: LIST_ENTRY64;
    // etc...
  end;

  LDR_DATA_TABLE_ENTRY64 = record
    InLoadOrderLinks: LIST_ENTRY64;
    InMemoryOrderLinks: LIST_ENTRY64;
    InInitializationOrderLinks: LIST_ENTRY64;
    DllBase: ULONG_PTR64;
    EntryPoint: ULONG_PTR64;
    SizeOfImage: ULONG_PTR64;
    FullDllName: UNICODE_STRING64;
    BaseDllName: UNICODE_STRING64;
    Flags: ULONG;
    // etc...
  end;

{ TLoaderData }

constructor TLoaderData.Create(AProcess: THandle; AUse64Addr: Boolean);
begin
  FProcess := AProcess;
  FUse64Addr := AUse64Addr;
  FModuleList := TModuleList.Create;
end;

destructor TLoaderData.Destroy;
begin
  FModuleList.Free;
  inherited;
end;

function TLoaderData.Load32LoaderData(LdrAddr: ULONG_PTR64): Integer;
begin
  if LdrAddr <> 0 then
    Result := Scan32LdrData(LdrAddr)
  else
    Result := 0;
end;

function TLoaderData.Load64LoaderData(LdrAddr: ULONG_PTR64): Integer;
begin
  if LdrAddr <> 0 then
    Result := Scan64LdrData(LdrAddr)
  else
    Result := 0;
end;

function NormalizePath(const Value: string): string;
const
  DriveNameSize = 4;
  VolumeCount = 26;
  DriveTotalSize = DriveNameSize * VolumeCount;
var
  Buff, Volume: string;
  I, Count, dwQueryLength: Integer;
  lpQuery: array [0..MAX_PATH - 1] of Char;
begin
  Result := Value;
  SetLength(Buff, DriveTotalSize);
  Count := GetLogicalDriveStrings(DriveTotalSize, @Buff[1]) div DriveNameSize;
  for I := 0 to Count - 1 do
  begin
    Volume := PChar(@Buff[(I * DriveNameSize) + 1]);
    Volume[3] := #0;
    // Преобразуем имя каждого диска в символьную ссылку и
    // сравниваем с формализированным путем
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

function TLoaderData.Scan32LdrData(LdrAddr: ULONG_PTR64): Integer;
const
  strEntry = 'LDR_DATA_TABLE_ENTRY32';
var
  Item: TSymbolData;
  Ldr: PEB_LDR_DATA32;
  Entry: LDR_DATA_TABLE_ENTRY32;
  Module: TModuleData;
  MapedFilePath: string;
  MapedFilePathLen: DWORD;
begin
  Result := 0;
  Item.DataType := sdtLdrData32;
  Item.AddrVA := LdrAddr;

  if not ReadRemoteMemory(FProcess, Item.AddrVA,
    @Ldr, SizeOf(PEB_LDR_DATA32)) then
  begin
    Error(Format(ReadError, ['PEB_LDR_DATA32',
      LdrAddr, GetLastError, SysErrorMessage(GetLastError)]));
    Exit;
  end;

  SymbolStorage.Add(Item);
  Item.DataType := sdtLdrEntry32;
  Item.AddrVA := Ldr.InLoadOrderModuleList.FLink;

  SetLength(MapedFilePath, MAX_PATH);

  while ReadRemoteMemory(FProcess, Item.AddrVA,
    @Entry, SizeOf(LDR_DATA_TABLE_ENTRY32)) and (Entry.DllBase <> 0) do
  begin
    Module.ImageBase := Entry.DllBase;
    Module.Is64Image := False;

    SetLength(Module.ImagePath, Entry.FullDllName.Length shr 1);
    if not ReadRemoteMemory(FProcess, Entry.FullDllName.Buffer,
      @Module.ImagePath[1], Entry.FullDllName.Length) then
    begin
      Item.AddrVA := Entry.InLoadOrderLinks.FLink;
      Error(Format(ReadError, ['Entry32.FullDllName',
        Entry.FullDllName.Buffer, GetLastError, SysErrorMessage(GetLastError)]));
      Continue;
    end;

    // нюанс, 32 битные библиотеки в списке LDR будут прописаны с путем из
    // дефолтной системной директории, хотя на самом деле они грузятся
    // из SysWow64 папки. Поэтому проверяем, если SysWow64 присутствует
    // то все 32 битные пути библиотек меняем на правильный посредством
    // вызова GetMappedFileName + нормализация.
    // Для 64 битных это делать не имеет смысла, т.к. они грузятся по старшим
    // адресам куда не может быть загружена 32 битная библиотека, а по младшим
    // мы и сами сможет прочитать данные из 32 битной сборки, но есть нюанс!!!
    // GetMappedFileName работает с адресами меньше MM_HIGHEST_USER_ADDRESS
    // если адрес будет больше - вернется ноль с ошибкой ERROR_INVALID_PARAMETER
    // поэтому вызов GetMappedFileName должен осуществляться 64-битный!
    if FUse64Addr then
    begin
      MapedFilePathLen := GetMappedFileName64(FProcess, Module.ImageBase,
        @MapedFilePath[1], MAX_PATH * SizeOf(Char));
      if MapedFilePathLen > 0 then
        Module.ImagePath := NormalizePath(Copy(MapedFilePath, 1, MapedFilePathLen));
    end;

    // инициализируе дополнительные флаги загруженого модуля
    Module.IsDll := Entry.Flags and LDRP_IMAGE_DLL <> 0;
    Module.IsBaseValid := Entry.Flags and LDRP_IMAGE_NOT_AT_BASE = 0;
    Module.IsILCoreImage := Entry.Flags and LDRP_COR_IMAGE <> 0;
    Module.IsRedirected := Entry.Flags and LDRP_REDIRECTED <> 0;

    if FRootModule.IsEmpty then
     FRootModule := Module
    else
      if FRootModule.ImageBase <> Module.ImageBase then
        FModuleList.Add(Module);

    SymbolStorage.Add(Item);
    Item.AddrVA := Entry.InLoadOrderLinks.FLink;
    Inc(Result);
  end;

  if Entry.DllBase <> 0 then
    Warn(Format(ReadError, [strEntry, Item.AddrVA,
      GetLastError, SysErrorMessage(GetLastError)]));
end;

function TLoaderData.Scan64LdrData(LdrAddr: ULONG_PTR64): Integer;
const
  strEntry = 'LDR_DATA_TABLE_ENTRY64';
var
  Item: TSymbolData;
  Ldr: PEB_LDR_DATA64;
  Entry: LDR_DATA_TABLE_ENTRY64;
  Module: TModuleData;
begin
  Result := 0;
  Item.DataType := sdtLdrData64;
  Item.AddrVA := LdrAddr;

  if not ReadRemoteMemory(FProcess, Item.AddrVA,
    @Ldr, SizeOf(PEB_LDR_DATA64)) then
  begin
    Error(Format(ReadError, ['PEB_LDR_DATA64',
      LdrAddr, GetLastError, SysErrorMessage(GetLastError)]));
    Exit;
  end;

  SymbolStorage.Add(Item);
  Item.DataType := sdtLdrEntry64;
  Item.AddrVA := Ldr.InLoadOrderModuleList.FLink;

  while (ReadRemoteMemory(FProcess, Item.AddrVA,
    @Entry, SizeOf(LDR_DATA_TABLE_ENTRY64))) and (Entry.DllBase <> 0) do
  begin
    Module.ImageBase := Entry.DllBase;
    Module.Is64Image := True;
    SetLength(Module.ImagePath, Entry.FullDllName.Length shr 1);
    if not ReadRemoteMemory(FProcess, Entry.FullDllName.Buffer,
      @Module.ImagePath[1], Entry.FullDllName.Length) then
    begin
      Item.AddrVA := Entry.InLoadOrderLinks.FLink;
      Error(Format(ReadError, ['Entry64.FullDllName',
        Entry.FullDllName.Buffer, GetLastError, SysErrorMessage(GetLastError)]));
      Continue;
    end;

    // инициализируе дополнительные флаги загруженого модуля
    Module.IsDll := Entry.Flags and LDRP_IMAGE_DLL <> 0;
    Module.IsBaseValid := Entry.Flags and LDRP_IMAGE_NOT_AT_BASE = 0;
    Module.IsILCoreImage := Entry.Flags and LDRP_COR_IMAGE <> 0;
    Module.IsRedirected := Entry.Flags and LDRP_REDIRECTED <> 0;

    // есть нюанс, в 64 битном списке 32 битного процесса первым
    // идет запись об исполняемом файле, даже не смотря на то что он 32 битный
    // поэтому делаем проверку - была ли загружена эта информация при чтении
    // 32 битного списка загрузчика?
    if FRootModule.IsEmpty then
     FRootModule := Module
    else
      if FRootModule.ImageBase <> Module.ImageBase then
        FModuleList.Add(Module);

    SymbolStorage.Add(Item);
    Item.AddrVA := Entry.InLoadOrderLinks.FLink;
    Inc(Result);
  end;

  if Entry.DllBase <> 0 then
    Warn(Format(ReadError, [strEntry, Item.AddrVA,
      GetLastError, SysErrorMessage(GetLastError)]));
end;

end.

