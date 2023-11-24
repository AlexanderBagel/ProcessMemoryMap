////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Core.pas
//  * Purpose   : Класс содержащий общий интерфейс работы с RawScanner
//  *           : и хранящий информацию об известных для анализа и отображения
//  *           : адресах
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.0.15
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.Core;

interface

  {$I rawscanner.inc}

uses
  Windows,
  SysUtils,
  Generics.Collections,
  {$IFNDEF DISABLE_ACTCTX}
  RawScanner.ActivationContext,
  {$ENDIF}
  RawScanner.Analyzer,
  RawScanner.ApiSet,
  RawScanner.LoaderData,
  {$IFNDEF DISABLE_LOGGER}
  RawScanner.Logger,
  {$ENDIF}
  RawScanner.ModulesData,
  RawScanner.SymbolStorage,
  RawScanner.Types,
  RawScanner.Utils,
  RawScanner.Wow64,
  RawScanner.X64Gates;

const
  RawScannerVersionInt = $0100000F;
  RawScannerVersionStr = '1.0 (revision 15)';

type
  TPEB64 = record
    InheritedAddressSpace: BOOLEAN;
    ReadImageFileExecOptions: BOOLEAN;
    BeingDebugged: BOOLEAN;
    BitField: BOOLEAN;
    Mutant: ULONG_PTR64;
    ImageBaseAddress: ULONG_PTR64;
    LoaderData: ULONG_PTR64;
    Dummy: array [0..$2D7] of Byte;
    ActivationContextData: ULONG_PTR64;
    ProcessAssemblyStorageMap: ULONG_PTR64;
    SystemDefaultActivationContextData: ULONG_PTR64;
    SystemAssemblyStorageMap: ULONG_PTR64;
    // ...
  end;

  TInitializationResult = record
    Loader32, Loader64: Integer;
    ApiSetVer: ULONG;
    ApiSetCount: Integer;
  end;

  TRawScanner = class
  strict private
    class var FInstance: TRawScanner;
    class destructor ClassDestroy;
  strict private
    {$IFNDEF DISABLE_ACTCTX}
    FProcessContext, FSystemContext: TActivationContext;
    {$ENDIF}
    FProcess: THandle;
    FIsWow64Mode: LongBool;
    FInitResult: TInitializationResult;
    FPEB32, FPEB64: TPEB64;
    FModules: TRawModules;
    FAnalizer: TPatchAnalyzer;
    FProgress: TProgressEvent;
    procedure Clear;
    procedure DoProgress(const Step: string; APecent: Integer);
    function GetPEB(AProcess: THandle;
      Read32Peb: Boolean; out APeb: TPEB64): Boolean;
    procedure InitModules(ALoader: TLoaderData);
    procedure InitNtQueryVirtualMemory;
  public
    constructor Create;
    destructor Destroy; override;
    class function GetInstance: TRawScanner;
    function Active: Boolean;
    procedure InitFromProcess(AProcessID: Cardinal);
    function IsActualState: Boolean;
    function GetDataTypeAtAddr(AdrrVA: ULONG_PTR64): TSymbolDataType;
    property Analizer: TPatchAnalyzer read FAnalizer;
    property InitializationResult: TInitializationResult read FInitResult;
    property Modules: TRawModules read FModules;
    property OnProgress: TProgressEvent read FProgress write FProgress;
  end;

  function RawScannerCore: TRawScanner;

implementation

const
  ntdll = 'ntdll.dll';
  ProcessBasicInformation = 0;
  ProcessWow64Information = 26;

type
  TPEB32 = record
    InheritedAddressSpace: BOOLEAN;
    ReadImageFileExecOptions: BOOLEAN;
    BeingDebugged: BOOLEAN;
    BitField: BOOLEAN;
    Mutant: ULONG;
    ImageBaseAddress: ULONG;
    LoaderData: ULONG;
    Dummy: array [0..$1E7] of Byte;
    ActivationContextData: ULONG;
    ProcessAssemblyStorageMap: ULONG;
    SystemDefaultActivationContextData: ULONG;
    SystemAssemblyStorageMap: ULONG;
    // ...
  end;

  TPEB = record
    InheritedAddressSpace: BOOLEAN;
    ReadImageFileExecOptions: BOOLEAN;
    BeingDebugged: BOOLEAN;
    BitField: BOOLEAN;
    Mutant: THandle;
    ImageBaseAddress: PVOID;
    LoaderData: PVOID;
    {$IFDEF WIN32}
    Dummy: array [0..$1E7] of Byte;
    {$ELSE}
    Dummy: array [0..$2D7] of Byte;
    {$ENDIF}
    ActivationContextData: PVOID;
    ProcessAssemblyStorageMap: PVOID;
    SystemDefaultActivationContextData: PVOID;
    SystemAssemblyStorageMap: PVOID;
    // ...
  end;

  PPROCESS_BASIC_INFORMATION = ^PROCESS_BASIC_INFORMATION;
  PROCESS_BASIC_INFORMATION = record
    ExitStatus: LONG;
    PebBaseAddress: PVOID;
    AffinityMask: ULONG_PTR;
    BasePriority: LONG;
    uUniqueProcessId: ULONG_PTR;
    uInheritedFromUniqueProcessId: ULONG_PTR;
  end;

  PPROCESS_BASIC_INFORMATION64 = ^PROCESS_BASIC_INFORMATION64;
  PROCESS_BASIC_INFORMATION64 = record
    ExitStatus: ULONG_PTR64;
    PebBaseAddress: ULONG_PTR64;
    AffinityMask: ULONG_PTR64;
    BasePriority: ULONG_PTR64;
    uUniqueProcessId: ULONG_PTR64;
    uInheritedFromUniqueProcessId: ULONG_PTR64;
  end;

  function NtQueryInformationProcess(ProcessHandle: Cardinal;
    ProcessInformationClass: Integer;
    ProcessInformation: Pointer;
    ProcessInformationLength: Cardinal;
    ReturnLength: PCardinal): NTSTATUS; stdcall; external ntdll;

function RawScannerCore: TRawScanner;
begin
  Result := TRawScanner.GetInstance;
end;

procedure Error(const Description: string);
begin
  {$IFNDEF DISABLE_LOGGER}
  RawScannerLogger.Error(llCore, Description);
  {$ENDIF}
end;

procedure Fatal(const FuncName, Description: string);
begin
  {$IFNDEF DISABLE_LOGGER}
  RawScannerLogger.Fatal(llCore, Description);
  {$ENDIF}
end;

{ TRawScanner }

function TRawScanner.Active: Boolean;
begin
  Result := Assigned(FAnalizer) and (FModules.Items.Count > 0);
end;

class destructor TRawScanner.ClassDestroy;
begin
  FInstance.Free;
end;

procedure TRawScanner.Clear;
begin
  if FProcess <> 0 then
    CloseHandle(FProcess);
  FProcess := 0;
  ZeroMemory(@FPEB32, SizeOf(TPEB64));
  ZeroMemory(@FPEB64, SizeOf(TPEB64));
  ZeroMemory(@FInitResult, SizeOf(TInitializationResult));  
  FreeAndNil(FAnalizer);
  {$IFNDEF DISABLE_ACTCTX}
  FreeAndNil(FProcessContext);
  FreeAndNil(FSystemContext);
  {$ENDIF}
  FModules.Clear;
  SymbolStorage.Clear;
end;

constructor TRawScanner.Create;
begin
  {$IFDEF WIN32}
  if Wow64Support.Use64AddrMode then
  begin
    Wow64Support.DisableRedirection;
    try
      InitNtQueryVirtualMemory;
    finally
      Wow64Support.EnableRedirection;
    end;
  end;
  {$ELSE}
  // чтобы в 64 битах не висел ворнинг - просто вызов заглушки
  InitNtQueryVirtualMemory;
  {$ENDIF}
  FModules := TRawModules.Create;
end;

destructor TRawScanner.Destroy;
begin
  Clear;
  FModules.Free;
  {$IFDEF WIN32}
  ReleaseNtQueryVirtualMemory64;
  {$ENDIF}
  FInstance := nil;
  inherited;
end;

procedure TRawScanner.DoProgress(const Step: string; APecent: Integer);
begin
  if Assigned(FProgress) then
    FProgress(Step, APecent);
end;

function TRawScanner.GetDataTypeAtAddr(AdrrVA: ULONG_PTR64): TSymbolDataType;
begin
  Result := SymbolStorage.GetDataTypeAtAddr(AdrrVA);
end;

class function TRawScanner.GetInstance: TRawScanner;
begin
  if FInstance = nil then
    FInstance := TRawScanner.Create;
  Result := FInstance;
end;

function TRawScanner.GetPEB(AProcess: THandle;
  Read32Peb: Boolean; out APeb: TPEB64): Boolean;
const
  QueryError = 'Query %s error %d, %s';
  strProcessWow64Information = 'ProcessWow64Information';
  strProcessBasicInformation = 'ProcessBasicInformation';
  strProcessBasicInformation64 = 'ProcessBasicInformation x64';

  procedure Convert32PebTo64(const Value: TPEB32);
  begin
    APeb.InheritedAddressSpace := Value.InheritedAddressSpace;
    APeb.ReadImageFileExecOptions := Value.ReadImageFileExecOptions;
    APeb.BeingDebugged := Value.BeingDebugged;
    APeb.BitField := Value.BitField;
    APeb.Mutant := Value.Mutant;
    APeb.ImageBaseAddress := Value.ImageBaseAddress;
    APeb.LoaderData := Value.LoaderData;
    APeb.ActivationContextData := Value.ActivationContextData;
    APeb.ProcessAssemblyStorageMap := Value.ProcessAssemblyStorageMap;
    APeb.SystemDefaultActivationContextData := Value.SystemDefaultActivationContextData;
    APeb.SystemAssemblyStorageMap := Value.SystemAssemblyStorageMap;
  end;

  function Read32PebFrom64Bit: Boolean;
  var
    PebWow64BaseAddress: ULONG_PTR;
    dwReturnLength: Cardinal;
    Peb32: TPEB32;
  begin
    // Чтение 32 битного PEB из 64 битного кода производится через PebWow64BaseAddress
    Result := NtQueryInformationProcess(AProcess,
      ProcessWow64Information, @PebWow64BaseAddress, SizeOf(ULONG_PTR),
      @dwReturnLength) = 0;
    if not Result then
    begin
      Error(
        Format(QueryError,[strProcessWow64Information,
        GetLastError, SysErrorMessage(GetLastError)]));
      Exit;
    end;

    Result := ReadRemoteMemory(AProcess, PebWow64BaseAddress,
      @Peb32, SizeOf(TPEB32));
    if Result then
      Convert32PebTo64(Peb32)
    else
      Error(
        Format(ReadError, [strProcessWow64Information,
        PebWow64BaseAddress, GetLastError, SysErrorMessage(GetLastError)]));
  end;

  function Read64PebFrom32Bit: Boolean;
  var
    PBI64: PROCESS_BASIC_INFORMATION64;
    dwReturnLength: Cardinal;
  begin
    // Чтение 64 битного PEB из 32 битного кода производится через Wow64 обертку
    Result := Wow64Support.QueryInformationProcess(AProcess,
      ProcessBasicInformation, @PBI64, SizeOf(PBI64), dwReturnLength);
    if not Result then
    begin
      Error(
        Format(QueryError, [strProcessBasicInformation64,
        GetLastError, SysErrorMessage(GetLastError)]));
      Exit;
    end;
    Result := ReadRemoteMemory(AProcess, PBI64.PebBaseAddress,
      @APeb, SizeOf(TPEB64));
    if not Result then
      Error(
        Format(ReadError, [strProcessBasicInformation64,
        PBI64.PebBaseAddress, GetLastError, SysErrorMessage(GetLastError)]));
  end;

  function ReadNativePeb: Boolean;
  var
    PBI: PROCESS_BASIC_INFORMATION;
    dwReturnLength: Cardinal;
    Peb: TPEB;
  begin
    // чтение PEB, совпадающего битностью с текущей сборкой
    Result := NtQueryInformationProcess(AProcess,
      ProcessBasicInformation, @PBI, SizeOf(PBI), @dwReturnLength) = 0;
    if not Result then
    begin
      Error(
        Format(QueryError, [strProcessBasicInformation,
        GetLastError, SysErrorMessage(GetLastError)]));
      Exit;
    end;

    Result := ReadRemoteMemory(AProcess, ULONG_PTR64(PBI.PebBaseAddress),
      @Peb, SizeOf(TPEB));
    if Result then
    {$IFDEF WIN32}
      Convert32PebTo64(TPEB32(Peb))
    {$ELSE}
      APeb := TPEB64(Peb)
    {$ENDIF}
    else
      Error(
        Format(ReadError, [strProcessBasicInformation,
        ULONG_PTR64(PBI.PebBaseAddress),
        GetLastError, SysErrorMessage(GetLastError)]));
  end;

begin
  ZeroMemory(@APeb, SizeOf(TPEB64));
  if Read32Peb then
  {$IFDEF WIN32}
    Result := ReadNativePeb
  else
    Result := Read64PebFrom32Bit;
  {$ELSE}
    Result := Read32PebFrom64Bit
  else
    Result := ReadNativePeb;
  {$ENDIF}
end;

procedure TRawScanner.InitFromProcess(
  AProcessID: Cardinal);
var
  Loader: TLoaderData;
  {$IFNDEF DISABLE_ACTCTX}
  ContextAddr: ULONG_PTR64;
  {$ENDIF}
begin
  Clear;

  ApiSetRedirector.LoadApiSet;

  FProcess := OpenProcess(
    PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
    False, AProcessID);
  if FProcess = 0 then
  begin
    Fatal('Can not open process ID: ' + IntToStr(AProcessID),
      Format('Error %d: %s', [GetLastError, SysErrorMessage(GetLastError)]));
    Exit;
  end;

  FAnalizer := TPatchAnalyzer.Create(FProcess, FModules);

  Wow64Support.IsWow64Process(FProcess, FIsWow64Mode);

  {$IFDEF WIN32}
  // если мы в 32 битном коде и в 32 битной системе
  if not Wow64Support.Use64AddrMode then
    // то нам доступен только 32 битный PEB
    GetPEB(FProcess, True, FPEB32)
  else
  {$ENDIF}
  begin
    // в противном случае мы в 64 битной OS,
    // где у любого процесса есть 64 битный PEB
    GetPEB(FProcess, False, FPEB64);
    // а 32 битный есть только у 32 битных процессов
    if FIsWow64Mode then
      GetPEB(FProcess, True, FPEB32);
  end;

  Loader := TLoaderData.Create(FProcess, FIsWow64Mode);
  try
    FInitResult.Loader32 := Loader.Load32LoaderData(FPEB32.LoaderData);
    FInitResult.Loader64 := Loader.Load64LoaderData(FPEB64.LoaderData);
    if FInitResult.Loader32 + FInitResult.Loader64 = 0 then Exit;
    InitModules(Loader);
  finally
    Loader.Free;
  end;

  FInitResult.ApiSetVer := ApiSetRedirector.Version;
  FInitResult.ApiSetCount := ApiSetRedirector.Count;

  {$IFNDEF DISABLE_ACTCTX}

  {$IFDEF WIN32}
  ContextAddr := FPEB32.ActivationContextData;
  {$ELSE}
  if FIsWow64Mode then
    ContextAddr := FPEB32.ActivationContextData
  else
    ContextAddr := FPEB64.ActivationContextData;
  {$ENDIF}
  FProcessContext := TActivationContext.Create(FProcess, ContextAddr, False);

  {$IFDEF WIN32}
  ContextAddr := FPEB32.SystemDefaultActivationContextData;
  {$ELSE}
  if FIsWow64Mode then
    ContextAddr := FPEB32.SystemDefaultActivationContextData
  else
    ContextAddr := FPEB64.SystemDefaultActivationContextData;
  {$ENDIF}
  FSystemContext := TActivationContext.Create(FProcess, ContextAddr, True);

  {$ENDIF DISABLE_ACTCTX}

  SymbolStorage.PrepareForWork;
end;

procedure TRawScanner.InitModules(ALoader: TLoaderData);
const
  ProgressHint = 'Loading image... [0x%x] %s';
var
  Cursor, MaxCursor, LastPercent, CurrentPercent: Integer;
  Module: TModuleData;
begin
  Wow64Support.DisableRedirection;
  try
    DoProgress(Format(ProgressHint,
      [ALoader.RootModule.ImageBase, ALoader.RootModule.ImagePath]), 0);
    FModules.AddImage(ALoader.RootModule);
    Cursor := 1;
    LastPercent := 0;
    MaxCursor := ALoader.Modules.Count;
    for Module in ALoader.Modules do
    begin
      CurrentPercent := Round(Cursor / (MaxCursor / 100));
      if CurrentPercent <> LastPercent then
      begin
        LastPercent := CurrentPercent;
        DoProgress(Format(ProgressHint,
          [Module.ImageBase, Module.ImagePath]), CurrentPercent);
      end;
      FModules.AddImage(Module);
      Inc(Cursor);
    end;
  finally
    Wow64Support.EnableRedirection;
  end;
end;

procedure TRawScanner.InitNtQueryVirtualMemory;
{$IFDEF WIN32}
var
  hProc: THandle;
  LocalLoader: TLoaderData;
  PEB: TPEB64;
  NtDll: TRawPEImage;
  Index: Integer;
begin
  // инициализируем адрес 64 битной NtQueryVirtualMemory необходимый
  // для чтения данных по 64-битным адресам из 32 битного кода

  // для чтения данных псевдохэндл не подойдет,
  // поэтому нужно открывать текущий процесс
  hProc := OpenProcess(
    PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
    False, GetCurrentProcessId);

  if hProc = 0 then
  begin
    Fatal(
      'Can not open self process ID: ' + IntToStr(GetCurrentProcessId),
      Format('Error %d: %s', [GetLastError, SysErrorMessage(GetLastError)]));
    Exit;
  end;

  try

    // получаем данные по 64 битному PEB
    if not GetPEB(hProc, False, PEB) then
    begin
      Fatal(
        'Can not read PEB64',
        Format('Error %d: %s', [GetLastError, SysErrorMessage(GetLastError)]));
      Exit;
    end;

    // создаем сканер для чтения списков загруззчика
    LocalLoader := TLoaderData.Create(hProc, True);
    try
      // получаем данные только по 64 битным модулям
      if LocalLoader.Load64LoaderData(PEB.LoaderData) > 0 then
        for var Module in LocalLoader.Modules do
        begin
          // ищем 64 битню ntdll
          if ExtractFileName(Module.ImagePath).ToLower = 'ntdll.dll' then
          begin
            // если нашли (а мы должны найти) инициализирем с учетом её инстанса
            NtDll := TRawPEImage.Create(Module.ImagePath, False, Module.ImageBase);
            try
              // и только теперь получаем адрес NtQueryVirtualMemory
              // который актуален применительно к нашему процессу
              Index := NtDll.ExportIndex('NtQueryVirtualMemory');
              if Index >= 0 then
                InitNtQueryVirtualMemory64(MakeX64Gate(
                  NtDll.ExportList.List[Index].FuncAddrVA,
                  [ps4Byte, ps8Byte, ps4Byte, ps4Byte, ps4Byte, ps4Byte]));
            finally
              NtDll.Free;
            end;
            Break;
          end;
        end;
    finally
      LocalLoader.Free;
    end;
  finally
    CloseHandle(hProc);
  end;
{$ELSE}
begin
{$ENDIF}
end;

function TRawScanner.IsActualState: Boolean;
var
  Loader: TLoaderData;
  Module: TModuleData;
  I: Integer;
begin
  Result := Active;
  if not Result then Exit;
  Loader := TLoaderData.Create(FProcess, FIsWow64Mode);
  try
    if FInitResult.Loader32 <> Loader.Load32LoaderData(FPEB32.LoaderData) then
      Exit(False);
    if FInitResult.Loader64 <> Loader.Load64LoaderData(FPEB64.LoaderData) then
      Exit(False);
    if FInitResult.Loader32 + FInitResult.Loader64 = 0 then Exit;
    if FModules.Items[0].ImageBase <> Loader.RootModule.ImageBase then
      Exit(False);
    I := 1;
    for Module in Loader.Modules do
    begin
      if Module.ImageBase <> FModules.Items[I].ImageBase then
        Exit(False);
      Inc(I);
    end;
  finally
    Loader.Free;
  end;
end;

end.
