////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Analyzer.pas
//  * Purpose   : Класс сравнивает состояние памяти процесса с рассчитаным
//  *           : на основе образов файлов с диска и отдает результаты наружу.
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

unit RawScanner.Analyzer;

interface

uses
  Windows,
  Classes,
  SysUtils,
  Math,
  Generics.Collections,
  Generics.Defaults,
  PsApi,
  Hash,
  RawScanner.Logger,
  RawScanner.Types,
  RawScanner.ModulesData,
  RawScanner.Utils,
  RawScanner.Wow64;

type
  TImportAdvanced = record
    OriginalForvardedTo,                // изначальное перенправление функции
    ForvardedTo: string;                // текущее перенаправление функции
  end;

  TExportAdvanced = record
    Patched: Boolean;                   // флаг признака модификации страницы
    RawOffset: DWORD;                   // оффсет в файле
    ExpRawRva, ExpRemoteRva: DWORD;     // рассчитаные и реальные данные в блоке (только для экспорта)
  end;

  THookData = record
    ProcessHandle: THandle;             // хэндл процесса, потребуется для получения допинформации
    Image64: Boolean;                   // флаг битности модуля
    ImageBase: ULONG_PTR64;             // инстанс модуля
    VirtualSize: UInt64;                // размер модуля в памяти
    AddrVA: ULONG_PTR64;                // VA адрес блока памяти
    HookType: THookType;                // тип блока импорт/экспорт
    RawVA, RemoteVA: ULONG_PTR64;       // рассчитаный и реальный VA адрес, на который указывает блок
    Calculated: Boolean;                // флаг показывающий что рассчитаны контрольные Raw данные
    ModuleName,                         // имя модуля в котором обьявлена функция
    FuncName: string;                   // имя функции, которую описывает блок
    ImportAdv: TImportAdvanced;
    ExportAdv: TExportAdvanced;
  end;
  TProcessTableHookCallBack = reference to procedure(const Data: THookData);

  TCodeHookData = record
    ProcessHandle: THandle;             // хэндл процесса, потребуется для получения допинформации
    Image64: Boolean;                   // флаг битности модуля
    ImageBase: ULONG_PTR64;             // инстанс модуля
    AddrVA: ULONG_PTR64;                // VA адрес блока в удаленном процессе
    RawOffset: DWORD;                   // оффсет в файле
    ExportFunc: string;                 // имя функции описываемой блоком
    Raw, Remote: PByte;                 // указатель на блоки данных
    BufSize: Integer;                   // размер блоков
    Patched: Boolean;                   // флаг признака модификации страницы
  end;
  TProcessCodeHookCallBack = reference to procedure(const Data: TCodeHookData);

  TRemoteStream = class
  private
    FProcess: THandle;
    FAddress: ULONG_PTR64;
    FMemory: TMemoryStream;
  public
    constructor Create(AProcess: THandle;
      BaseAddress: ULONG_PTR64; Size: DWORD);
    destructor Destroy; override;
    function ReadMemory(BaseAddress: ULONG_PTR64; Size: DWORD;
      Data: Pointer): Boolean;
    property BaseAddress: ULONG_PTR64 read FAddress;
  end;

  TAnalizedItem = record
    Scanned, Skipped: Integer;
  end;

  TAnalizeResult = record
    Modules: TAnalizedItem;
    Import: TAnalizedItem;
    Export: TAnalizedItem;
    Code: TAnalizedItem; // включая EntryPoint + TLS Callback
  end;

  TPatchAnalyzer = class
  private const
    PageMask = $FFFFFFFFFFFFF000;
  private
    FAnalizeResult: TAnalizeResult;
    FProcessHandle: THandle;
    FRaw: TMemoryStream;
    FProcessCodeHook: TProcessCodeHookCallBack;
    FProcessTableHook: TProcessTableHookCallBack;
    FRawModules: TRawModules;
    FWorkingSet: TDictionary<ULONG_PTR64, Byte>;
    FProgress: TProgressEvent;
    function CheckPageSharing(AddrVa: ULONG_PTR64;
      out SharedCount: Byte): Boolean;
    procedure CompareBinary(AddrVa: ULONG_PTR64; AddrRaw: DWORD;
      const FuncName: string; Module: TRawPEImage);
  protected
    procedure DoModifyed(HookData: THookData);
    procedure DoProgress(const Step: string; APecent: Integer);
    procedure InitWorkingSet;
    function Init(AModuleList: TModuleList): Integer;
    procedure ScanImport(Index: Integer; Module: TRawPEImage);
    procedure ScanExport(Index: Integer; Module: TRawPEImage);
    procedure ScanEntryPoints(Index: Integer; Module: TRawPEImage);
    procedure ScanModule(Index: Integer);
  public
    constructor Create(AProcessHandle: THandle; ARawModules: TRawModules);
    destructor Destroy; override;
    function Analyze(
      AProcessTableHook: TProcessTableHookCallBack;
      AProcessCodeHook: TProcessCodeHookCallBack): TAnalizeResult;
    property OnProgress: TProgressEvent read FProgress write FProgress;
  end;

implementation

{ TRemoteStream }

constructor TRemoteStream.Create(AProcess: THandle;
  BaseAddress: ULONG_PTR64; Size: DWORD);
begin
  FAddress := BaseAddress;
  FProcess := AProcess;
  FMemory := TMemoryStream.Create;
  FMemory.Size := Size;
  if not ReadRemoteMemory(FProcess, BaseAddress, FMemory.Memory, Size) then
    FMemory.Size := 0;
end;

destructor TRemoteStream.Destroy;
begin
  FMemory.Free;
  inherited;
end;

function TRemoteStream.ReadMemory(BaseAddress: ULONG_PTR64; Size: DWORD;
  Data: Pointer): Boolean;
begin
  Result := False;
  if (BaseAddress >= FAddress) and
    (BaseAddress + Size <= FAddress + NativeUInt(FMemory.Size)) then
  begin
    FMemory.Position := BaseAddress - FAddress;
    Result := NativeUInt(FMemory.Read(Data^, Size)) = Size;
  end;
  if not Result then
    Result := ReadRemoteMemory(FProcess, BaseAddress, Data, Size);
end;

{ TPatchAnalyzer }

function TPatchAnalyzer.Analyze(
  AProcessTableHook: TProcessTableHookCallBack;
  AProcessCodeHook: TProcessCodeHookCallBack): TAnalizeResult;
const
  ProgressHint = 'Scan image... [0x%x] %s';
var
  MaxCursor, LastPercent, CurrentPercent: Integer;
begin
  ZeroMemory(@FAnalizeResult, SizeOf(TAnalizeResult));

  FProcessTableHook := AProcessTableHook;
  FProcessCodeHook := AProcessCodeHook;

  InitWorkingSet;
  if FWorkingSet.Count = 0 then
    RawScannerLogger.Error(llAnalizer,
      'Can not init WorkingSet',
      Format('Error %d: %s', [GetLastError, SysErrorMessage(GetLastError)]));

  Wow64Support.DisableRedirection;
  try
    LastPercent := 0;
    MaxCursor := FRawModules.Items.Count;
    for var I := 0 to FRawModules.Items.Count - 1 do
    begin
      CurrentPercent := Round(I / (MaxCursor / 100));
      if CurrentPercent <> LastPercent then
      begin
        LastPercent := CurrentPercent;
        DoProgress(Format(ProgressHint,
          [FRawModules.Items[I].ImageBase,
          FRawModules.Items[I].ImagePath]), CurrentPercent);
      end;
      ScanModule(I);
    end;
  finally
    Wow64Support.EnableRedirection;
  end;

  Result := FAnalizeResult;
end;

function TPatchAnalyzer.CheckPageSharing(AddrVa: ULONG_PTR64;
  out SharedCount: Byte): Boolean;
var
  Tmp: Byte;
begin
  Result := FWorkingSet.TryGetValue(AddrVA and PageMask, SharedCount);
  if not Result then
  begin
    // Если информации по странице нет в кэше первичной инициализации ворксета,
    // то нужно её принудительно подгрузить в ворксет чтением 1 байта по адресу
    if not Result then
    begin
      if ReadRemoteMemory(FProcessHandle, AddrVa, @Tmp, 1) then
      begin
        InitWorkingSet;
        Result := FWorkingSet.TryGetValue(AddrVA and PageMask, SharedCount);
      end
      else
        RawScannerLogger.Error(llAnalizer, 'CheckPageSharing',
          'Can not read remote memory at addr: ' + IntToHex(AddrVa));
    end;
  end;
end;

procedure TPatchAnalyzer.CompareBinary(AddrVa: ULONG_PTR64; AddrRaw: DWORD;
  const FuncName: string; Module: TRawPEImage);
const
  DefaultBuffSize = 64;
var
  RawBuff, RemoteBuff: array of Byte;
  BuffSize: DWORD;
  SharedCount: Byte;
  Data: TCodeHookData;
begin

  Inc(FAnalizeResult.Code.Scanned);

  SetLength(RawBuff, DefaultBuffSize);
  SetLength(RemoteBuff, DefaultBuffSize);

  // Проверяем размер буфера который можно прочитать.
  // Если мы находимся в конце секции, то нужно ограничить размер
  // т.к. в Raw файле сразу за данными текущей секции пойдут данные следующей
  // секции, а в памяти они будут разнесены по своим VA адресам
  // в итоге получится что-то типа такого
  {
  [+] WARN: dclIndyProtocols270.bpl export: Finalize current: 0000000023425BF4 binary modified.
  [.]       Expected: B8 1C 4B 42 23 E8 F2 BB FF FF C3 90 ! FF 25 04 A1 42 23 8B C0...
  [.]       Present:  B8 1C 4B 42 23 E8 F2 BB FF FF C3 90 ! 00 00 00 00 00 00 00 00...
  }
  // здесь после восклицательного знака FF 25... это уже данные
  // из следующей секции по адресу 0х23426000
  BuffSize := DefaultBuffSize;
  Module.FixAddrSize(AddrVA, BuffSize);

  // проверка, если мы в конце секции и читать нечего, значит (скорее всего)
  // алгоритм рассчета ошибся с определением адреса.
  // пишем уведомление в лог
  if BuffSize = 0 then
  begin
    RawScannerLogger.Warn(llAnalizer,
      Format('Error reading function "%s" at address 0x%.1x',
      [FuncName, AddrVa]),
      'possibly incorrect AddrVA, available buffer size is zero');
    Exit;
  end;

  // зачитываем блок из файла
  FRaw.Position := AddrRaw;
  FRaw.ReadBuffer(RawBuff[0], BuffSize);

  // и из памяти
  if not ReadRemoteMemory(FProcessHandle, AddrVA,
    @RemoteBuff[0], BuffSize) then
  begin
    RawScannerLogger.Error(llAnalizer,
      Format('Error reading function "%s" at address 0x%.1x', [FuncName, AddrVa]),
      Format('(%d) %s', [GetLastError, SysErrorMessage(GetLastError)]));
    Exit;
  end;

  if not CompareMem(@RawBuff[0], @RemoteBuff[0], BuffSize) then
  begin

    Data.Patched :=
      CheckPageSharing(AddrVA, SharedCount) and
      (SharedCount = 0);

    // блоки не совпали
    // отдаем на анализ внешнему обработчику, если таковой назначен
    if Assigned(FProcessCodeHook) then
    begin
      Data.ProcessHandle := FProcessHandle;
      Data.Image64 := Module.Image64;
      Data.ImageBase := Module.ImageBase;
      Data.ExportFunc := ChangeFileExt(Module.ImageName, '.' + FuncName);
      Data.AddrVA := AddrVA;
      Data.RawOffset := AddrRaw;
      Data.Raw := @RawBuff[0];
      Data.Remote := @RemoteBuff[0];
      Data.BufSize := BuffSize;
      FProcessCodeHook(Data);
    end;

  end;
end;

constructor TPatchAnalyzer.Create(AProcessHandle: THandle;
  ARawModules: TRawModules);
begin
  FProcessHandle := AProcessHandle;
  FRawModules := ARawModules;
  FWorkingSet := TDictionary<ULONG_PTR64, Byte>.Create;
  FRaw := TMemoryStream.Create;
end;

destructor TPatchAnalyzer.Destroy;
begin
  FRaw.Free;
  FWorkingSet.Free;
  inherited;
end;

procedure TPatchAnalyzer.DoModifyed(HookData: THookData);
var
  SharedCount: Byte;
begin
  if Assigned(FProcessTableHook) then
  begin
    if HookData.HookType = htExport then
      HookData.ExportAdv.Patched := CheckPageSharing(
        HookData.AddrVA, SharedCount) and (SharedCount = 0);
    FProcessTableHook(HookData);
  end;
end;

procedure TPatchAnalyzer.DoProgress(const Step: string; APecent: Integer);
begin
  if Assigned(FProgress) then
    FProgress(Step, APecent);
end;

function TPatchAnalyzer.Init(AModuleList: TModuleList): Integer;
begin
  for var I := 0 to AModuleList.Count - 1 do
    FRawModules.AddImage(AModuleList.List[I]);
  Result := FRawModules.Items.Count;
end;

procedure TPatchAnalyzer.InitWorkingSet;
const
  SharedBitMask = $100;
  SharedCountMask = $E0;

  function GetSharedCount(Value: ULONG_PTR64): Byte; inline;
  begin
    Result := (Value and SharedCountMask) shr 5;
  end;

var
  WorksetBuff: array of ULONG_PTR64;
  I: Integer;
begin
  FWorkingSet.Clear;
  SetLength(WorksetBuff, $4000);
  while not QueryWorkingSet64(FProcessHandle, @WorksetBuff[0],
    Length(WorksetBuff) * SizeOf(ULONG_PTR64)) and (WorksetBuff[0] > 0) do
    SetLength(WorksetBuff, WorksetBuff[0] * 2);
  for I := 1 to NativeInt(WorksetBuff[0]) - 1 do
    FWorkingSet.TryAdd(WorksetBuff[I] and PageMask,
      GetSharedCount(WorksetBuff[I]));
end;

procedure TPatchAnalyzer.ScanEntryPoints(Index: Integer; Module: TRawPEImage);
begin
  // проверка, есть ли вообще функции на проверку?
  if Module.EntryPointList.Count = 0 then Exit;

  RawScannerLogger.Notify(llAnalizer, 'Process EntryPoint and TSL Callbacks',
    Format('(%d)', [Module.EntryPointList.Count]));

  for var I := 0 to Module.EntryPointList.Count - 1 do
    with Module.EntryPointList.List[I] do
      CompareBinary(AddrVA, AddrRaw, EntryPointName, Module);
end;

procedure TPatchAnalyzer.ScanExport(Index: Integer; Module: TRawPEImage);
var
  Exp, ForvardedExp: TExportChunk;
  ExportDirectory: TRemoteStream;
  HookData: THookData;
begin
  // проверка, есть ли вообще таблица экспорта?
  if Module.ExportList.Count = 0 then Exit;

  RawScannerLogger.Notify(llAnalizer, 'Process export',
    Format('(%d)',[Module.ExportList.Count]));

  ExportDirectory := TRemoteStream.Create(FProcessHandle,
    Module.ExportDirectory.VirtualAddress, Module.ExportDirectory.Size);
  try

    ZeroMemory(@HookData, SizeOf(THookData));
    HookData.HookType := htExport;
    HookData.ModuleName := Module.ImageName;
    HookData.ProcessHandle := FProcessHandle;
    HookData.Image64 := Module.Image64;
    HookData.ImageBase := Module.ImageBase;
    HookData.VirtualSize := Module.VirtualSizeOfImage;

    for Exp in Module.ExportList do
    begin

      Inc(FAnalizeResult.Export.Scanned);

      HookData.AddrVA := Exp.ExportTableVA;
      HookData.ExportAdv.RawOffset := Exp.ExportTableRaw;
      HookData.FuncName := Exp.ToString;
      HookData.RawVA := Exp.FuncAddrVA;
      HookData.ExportAdv.ExpRawRva := Exp.FuncAddrRVA;
      HookData.Calculated := True;

      // RVA адрес в таблице экспорта всегда 4 байта, даже в 64 битах
      if not ExportDirectory.ReadMemory(Exp.ExportTableVA, 4,
        @HookData.ExportAdv.ExpRemoteRva) then
      begin
        Dec(FAnalizeResult.Export.Scanned);
        Inc(FAnalizeResult.Export.Skipped);
        RawScannerLogger.Error(llAnalizer,
          Format('Error reading function "%s" at address 0x%.1x',
            [HookData.FuncName, Exp.ExportTableVA]),
          Format('(%d) %s', [GetLastError, SysErrorMessage(GetLastError)]));
        Continue;
      end;

      HookData.RemoteVA :=
        HookData.ExportAdv.ExpRemoteRva + Module.ImageBase;

      if HookData.RemoteVA <> HookData.RawVA then
      begin

        // если функция перенаправлена, пытаемся её подгрузить
        // это актуально только для 32 бит где в таблицу экспорта прописывается
        // полный оффсет до перенаправленой функции, в 64 битах это поле обычно не трогается
        // т.к. библиотеки могут быть разнесены больше чем позволяет в себя вместить
        // 32 битный RVA оффсет
        if Exp.ForvardedTo <> EmptyStr then
          if not FRawModules.GetProcData(Exp.ForvardedTo,
            Module.Image64, ForvardedExp, HookData.RemoteVA) then
          begin
            HookData.Calculated := False;
            DoModifyed(HookData);
            Continue;
          end
          else
            HookData.RawVA := ForvardedExp.FuncAddrVA;

        if HookData.RemoteVA <> HookData.RawVA then
        begin
          DoModifyed(HookData);
          Continue;
        end;

      end;

      // Подготовка перед проверкой кода функции:

      // 1. Если функция перенаправлена в другой модуль - пропускаем проверку
      if Exp.OriginalForvardedTo <> EmptyStr then
      begin
        Inc(FAnalizeResult.Code.Skipped);
        Continue;
      end;

      // 2. Если функция не содержит кода - пропускаем проверку
      if not Exp.Executable then
      begin
        Inc(FAnalizeResult.Code.Skipped);
        Continue;
      end;

      // после того как удостоверились что запись в таблице экспорта вадидная
      // и не перенаправлена в другой модуль, то тогда
      // проверяем бинарный код функции
      CompareBinary(Exp.FuncAddrVA, Exp.FuncAddrRaw, Exp.ToString, Module);

    end;

  finally
    ExportDirectory.Free;
  end;

end;

procedure TPatchAnalyzer.ScanImport(Index: Integer; Module: TRawPEImage);
var
  Import: TImportChunk;
  HookData: THookData;

  function CheckRemoteVA: Boolean;
  begin
    if Import.Delayed then
    begin
      if HookData.Calculated then
        Result :=
          (HookData.RemoteVA = Import.DelayedIATData) or
          (HookData.RemoteVA = HookData.RawVA)
      else
        Result := HookData.RemoteVA = Import.DelayedIATData;
    end
    else
      Result := HookData.Calculated and
        (HookData.RemoteVA = HookData.RawVA);
  end;

  function GetLogStr(VA: ULONG_PTR64): string;
  begin
    Result := '"' + Module.ImageName + '"';
    if Import.Delayed then
      Result := Result + ' delayed import '
    else
      Result := Result + ' import ';
    Result := Result + Import.ToString + '(0x' + IntToHex(VA, 1) + ')';
  end;

var
  MBI: TMemoryBasicInformation64;
  Exp: TExportChunk;
  AddrSize: NativeUInt;
  AIat: TRemoteStream;
  CacheVA: ULONG_PTR64;
  CacheSize: DWORD;
  ModuleIndex: Integer;
  ValidModule: Boolean;
begin
  // проверка, есть ли вообще таблица импорта?
  if Module.ImportList.Count = 0 then Exit;

  RawScannerLogger.Notify(llAnalizer, 'Process import',
    Format('(%d)', [Module.ImportList.Count]));

  // если модуль IMAGE_SUBSYSTEM_NATIVE, то импорт смотреть не имеет смысла
  if Module.NtHeader.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_NATIVE then
  begin
    Inc(FAnalizeResult.Import.Skipped, Module.ImportList.Count);
    RawScannerLogger.Info(llAnalizer, Module.ImageName + ' (imagebase: 0x' +
      IntToHex(Module.ImageBase, 1) +
      '), subsystem = IMAGE_SUBSYSTEM_NATIVE -> Import skipped.');
    Exit;
  end;

  // отдельная проверка .NET библиотек
  if Module.ComPlusILOnly then
  begin
    // В процес могут быть загружены библиотеки содержащие только IL код
    // не выполняемый нативно. У таких библиотек в COR20 заголовке
    // выставлен флаг COMIMAGE_FLAGS_ILONLY, а так-же у файла в таблице
    // импорта есть единственная заглушка ведущая на mscoree.dll -> _CorDllMain
    // Загрузчик, при наличии данного флага, не обрабатывает таблицу импорта,
    // что можно наглядно увидеть в "...base\ntdll\ldrapi.c" в функции LdrpLoadDll()
    {
      // if the image is COR-ILONLY, then don't walk the import descriptor
      // as it is assumed that it only imports %windir%\system32\mscoree.dll, otherwise
      // walk the import descriptor table of the dll.
    }
    // При наличии данного флага также не обрабатывается секция релокации.
    // Однако если библиотека должна загружаться в 32 битное приложение
    // ILAsm может исключить этот флаг, заменив его на COMIMAGE_FLAGS_32BITREQUIRED.
    // Функция TRawPEImage.LoadCor20Header при инициализации параметра ComPlusILOnly
    // учитывает этот нюанс.
    //
    // Определить такие библиотеки можно не только читая COM заголовок,
    // признак неисполняемого нативного образа содержится так-же и в флагах
    // таблицы загрузчика LDR_DATA_TABLE_ENTRYxx.Flags and LDRP_COR_IMAGE <> 0
    // Он выставляется в модуле "...base\ntdll\ldrinit.c" в LdrpInitializeProcess()
    //
    // Помимо этих двух проверок, можно сделать контрольную.
    // А именно: секция, на которую указывает точка входа, не исполняемая!
    if Module.EntryPoint <> 0 then
      if VirtualQueryEx64(FProcessHandle,
        Module.EntryPoint, MBI,
        SizeOf(TMemoryBasicInformation64)) = SizeOf(TMemoryBasicInformation64) then
        if MBI.Protect and (
          PAGE_EXECUTE_READ or
          PAGE_EXECUTE_READWRITE or
          PAGE_EXECUTE_WRITECOPY or
          PAGE_EXECUTE_READWRITE) = 0 then
        begin
          // если точка входа не исполняемая - пропускаем такой файл
          Inc(FAnalizeResult.Import.Skipped, Module.ImportList.Count);
          RawScannerLogger.Info(llAnalizer, Module.ImageName + ' (imagebase: 0x' +
            IntToHex(Module.ImageBase, 1) +
            '), non executable .NET image -> Import skipped.');
          Exit;
        end;

    // Еще можно проверить следующие два момента, но это немного спорно:
    // 1. инициализирована ли таблица импорта через сброшеный шаринг страницы.
    // Если не инициализирована (не сброшен шаринг) - пропускаем.
    // if CheckPageSharing(
    //   AIat.BaseAddress, SharedCount) and (SharedCount <> 0) then
    // Спорно потому что, судя по всему, модификация IAT происходит по причине
    // отработавшего BoundsImport, которого у таких библиотек нет.
    //
    // 2.еще у таких библиотек странная особенность, при их загрузке
    // 32 битный OptionalHeader полностью перезаписывается 64 битным аналогом
    // Можно сделать проверку на сброшеный шаринг страницы с РЕ заголовком
    // if CheckPageSharing(
    //   Module.ImageBase, SharedCount) and (SharedCount = 0) then

  end;

  // подгружаем кэш таблицы импорта, обычно она сидит в секции IAT
  // но в редких случаях эта секция отсутствует и таблица размещается
  // прямо в секции импорта
  CacheVA := IfThen(Module.ImportAddressTable.Size = 0,
    Module.ImportDirectory.VirtualAddress, Module.ImportAddressTable.VirtualAddress);
  CacheSize := IfThen(Module.ImportAddressTable.Size = 0,
    Module.ImportDirectory.Size, Module.ImportAddressTable.Size);

  if CacheSize > 0 then
    AIat := TRemoteStream.Create(FProcessHandle, CacheVA, CacheSize)
  else
  begin
    Inc(FAnalizeResult.Import.Skipped, Module.ImportList.Count);
    RawScannerLogger.Warn(llAnalizer, Module.ImageName + ' (imagebase: 0x' +
      IntToHex(Module.ImageBase, 1) +
      '), IAT not found -> Import skipped.');
    Exit;
  end;

  try
    AddrSize := IfThen(Module.Image64, 8, 4);

    ZeroMemory(@HookData, SizeOf(THookData));
    HookData.ModuleName := Module.ImageName;
    HookData.ProcessHandle := FProcessHandle;
    HookData.ImageBase := Module.ImageBase;
    HookData.VirtualSize := Module.VirtualSizeOfImage;
    HookData.Image64 := Module.Image64;

    for Import in Module.ImportList do
    begin

      Inc(FAnalizeResult.Import.Scanned);

      if Import.Delayed then
        HookData.HookType := htDelayedImport
      else
        HookData.HookType := htImport;

      HookData.AddrVA := Import.ImportTableVA;
      HookData.FuncName := Import.ToString;

      HookData.RemoteVA := 0;
      if Import.Delayed then
        HookData.RawVA := Import.DelayedIATData
      else
        HookData.RawVA := 0;

      // зачитываем текущий адрес из таблицы импорта
      // на основе него будем определять, на какую из библиотек идет перенаправление
      // в случае редиректа
      if not AIat.ReadMemory(Import.ImportTableVA, AddrSize, @HookData.RemoteVA) then
      begin
        RawScannerLogger.Error(llAnalizer,
          'AIat.ReadMemory at' + GetLogStr(Import.ImportTableVA),
          Format('Error %d: %s', [GetLastError, SysErrorMessage(GetLastError)]));
        Continue;
      end;

      if Import.FuncName = EmptyStr then
        HookData.Calculated := FRawModules.GetProcData(Import.LibraryName,
          Import.Ordinal, Module.Image64, Exp, HookData.RemoteVA)
      else
        HookData.Calculated := FRawModules.GetProcData(Import.LibraryName,
          Import.FuncName, Module.Image64, Exp, HookData.RemoteVA);

      // если пропатчен отложеный вызов, то технически можно еще проверить
      // инициализировано ли поле с HInst модуля, но это ничего не даст
      // т.к. в любом случае RemoteVA должно соответствовать или
      // неинициализированному значению, хранящемуся в DelayedIATData,
      // или FuncAddrVA найденого экспорта
      if Import.Delayed and (Import.DelayedModuleInstanceVA <> 0) then
      begin
        var DelayedModuleInst: ULONG_PTR64 := 0;
        if ReadRemoteMemory(FProcessHandle, Import.DelayedModuleInstanceVA,
          @DelayedModuleInst, AddrSize) and (DelayedModuleInst <> 0) then
        begin
          // впрочем мы можем проверить, соответствует ли HInst модуля
          // заявленному, и вывести предупреждение если это не так
          ModuleIndex := FRawModules.GetModule(DelayedModuleInst);
          ValidModule := (ModuleIndex >= 0) and AnsiSameText(
            FRawModules.Items.List[ModuleIndex].ImageName,
            Import.LibraryName);
          if not ValidModule then
            RawScannerLogger.Warn(llAnalizer,
              'Wrong ImgDelayDescr in ' + GetLogStr(Import.DelayedModuleInstanceVA),
              'invalid hInstance: ' + IntToHex(DelayedModuleInst) + Space +
              GetMappedModule(FProcessHandle, DelayedModuleInst));
        end;
      end;

      if HookData.Calculated then
        HookData.RawVA := Exp.FuncAddrVA
      else
        if not CheckRemoteVA then
        begin
          DoModifyed(HookData);
          Continue;
        end;

      if not CheckRemoteVA then
      begin
        // если функция перенаправлена, пытаемся её подгрузить
        if Exp.ForvardedTo <> EmptyStr then
          if not FRawModules.GetProcData(Exp.ForvardedTo,
            Module.Image64, Exp, HookData.RemoteVA) then
          begin
            HookData.Calculated := False;
            HookData.ImportAdv.OriginalForvardedTo := Exp.OriginalForvardedTo;
            HookData.ImportAdv.ForvardedTo := Exp.ForvardedTo;
            DoModifyed(HookData);
            Continue;
          end
          else
          begin
            HookData.RawVA := Exp.FuncAddrVA;
            HookData.ImportAdv.OriginalForvardedTo := EmptyStr;
            HookData.ImportAdv.ForvardedTo := EmptyStr;
          end;

        if not CheckRemoteVA then
          DoModifyed(HookData);

      end;
    end;
  finally
    AIat.Free;
  end;


end;

procedure TPatchAnalyzer.ScanModule(Index: Integer);
var
  Module: TRawPEImage;
begin
  Module := FRawModules.Items.List[Index];

  RawScannerLogger.Notify(llAnalizer, 'Process image',
    Format('%d: %s %s',
    [Index, IntToHex(Module.ImageBase, IfThen(Module.Image64, 16, 8)),
    Module.ImageName]));

  ScanImport(Index, Module);

  // для проверки машинного кода функций потребуется образ файла
  try
    FRaw.LoadFromFile(Module.ImagePath);
  except
    on E: Exception do
    begin
      Inc(FAnalizeResult.Modules.Skipped);
      RawScannerLogger.Notify(llAnalizer,
        'Image load error ' + Module.ImagePath,
        E.ClassName + ': ' + E.Message);
      Exit;
    end;
  end;
  // причем к нему необходимо применить релокейшены
  Module.ProcessRelocations(FRaw);
  ScanExport(Index, Module);
  if not Module.ComPlusILOnly then
    ScanEntryPoints(Index, Module);
  Inc(FAnalizeResult.Modules.Scanned);
end;

end.
