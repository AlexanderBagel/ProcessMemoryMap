////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : MemoryMap
//  * Unit Name : MemoryMap.Core.pas
//  * Purpose   : Базовый класс собирающий информацию о карте памяти процесса
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2022.
//  * Version   : 1.3.22
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit MemoryMap.Core;

interface

uses
  Winapi.Windows,
  System.Classes,
  System.SysUtils,
  Generics.Collections,
  Generics.Defaults,
  Winapi.PsAPI,
  MemoryMap.RegionData,
  MemoryMap.Workset,
  MemoryMap.Heaps,
  MemoryMap.Threads,
  MemoryMap.NtDll,
  MemoryMap.PEImage,
  MemoryMap.Symbols,
  MemoryMap.DebugMapData;

const
  MemoryMapVersionInt = $01031600;
  MemoryMapVersionStr = '1.3 (revision 22)';

type
  // Типы фильтров
  TFilters = (
    fiNone,       // отображать все регионы
    fiImage,      // только содержащие PE файлы
    fiPrivate,    // только приватную память
    fiShareable,  // только шареную память
    fiMapped,     // только отмапленные регионы
    fiHeap,       // только содержащие кучу
    fiThread,     // только содержащие данные нитей
    fiSystem,     // только содержащие системные структуры
    fiFree);      // только свободные регионы

  TModule = record
    Path: string;
    Is64Image, LoadAsImage: Boolean;
    BaseAddr: ULONG_PTR;
  end;

  EMemoryMapException = class(Exception);

  TTotalItem = record
    Size: NativeUInt;
    Commited: NativeUInt;
    Blocks: Integer;
  end;

  TTotalData = record
    Total: TTotalItem;
    Image: TTotalItem;
    _Private: TTotalItem;
    Shareable: TTotalItem;
    Mapped: TTotalItem;
    Heap: TTotalItem;
    Thread: TTotalItem;
    System: TTotalItem;
    Free: TTotalItem;
  end;

  TOnGetWow64HeapsEvent = procedure(Value: THeap) of object;
  TProgressEvent = procedure(const Step: string; APecent: Integer) of object;

  TMemoryMap = class
  private const
    HEADER = 'MemoryMap';
    Version = 2;
    MM_HIGHEST_USER_ADDRESS32 = $7FFEFFFF;
    MM_HIGHEST_USER_ADDRESS64 = $7FFFFFFF0000;
  private type
    TFriendlyRegionData = class(TRegionData);
  private
    FProcess: THandle;
    FProcessName, FProcessPath: string;
    FPID: Cardinal;
    FHighAddress: NativeUInt;
    FRegions: TObjectList<TRegionData>;
    FRegionFilters: TList<Integer>;
    FWorkset: TWorkset;
    FPEImage: TPEImage;
    FSymbols: TSymbols;
    FModules: TList<TModule>;
    FPeb: TPEB;
    FPebBaseAddress: Pointer;
    {$IFDEF WIN64}
    FPebWow64: TWOW64_PEB;
    FPebWow64BaseAddress: Pointer;
    {$ENDIF}
    FShowEmpty: Boolean;
    FProcess64: Boolean;
    FTotalData: TTotalData;
    FFilter: TFilters;
    FDetailedHeapData: Boolean;
    FSuspendProcess: Boolean;
    FGetWow64Heaps: TOnGetWow64HeapsEvent;
    FDebugMapData: TDebugMap;
    FProgress: TProgressEvent;
    function GetItem(Index: Integer): TRegionData;
    procedure SetShowEmpty(const Value: Boolean);
    procedure SetFilter(const Value: TFilters);
    procedure SetDetailedHeapData(const Value: Boolean);
  protected
    procedure DoProgress(const Step: string; APecent: Integer);
    function GetFriendlyRegion(Index: Integer): TFriendlyRegionData;
    function GetPageAtAddr(Address: Pointer): TMemoryBasicInformation;
    function GetRegionAtAddr(Address: Pointer): TFriendlyRegionData;
    function GetRegionIndex(Address: Pointer): Integer; overload;
    function NewRegionData: TFriendlyRegionData;
    function SplitRegionAtAddr(Address: Pointer; Index: Integer): Integer;
  protected
    procedure AddImagesData;
    procedure AddHeapsData; overload;
    procedure AddHeapsData(Value: THeap); overload;
    procedure AddWow64HeapsData;
    procedure AddPEBData;
    procedure AddThreadsData; overload;
    procedure AddThreadsData(Value: TThreads); overload;
    procedure GetAllRegions;
    procedure CalcTotal;
    procedure UpdateRegionFilters;
    procedure SortAllContainsBlocks;
  protected
    property PEImage: TPEImage read FPEImage;
    property Workset: TWorkset read FWorkset;
  public
    constructor Create;
    destructor Destroy; override;
    procedure SaveToFile(const FileName: string);
    procedure LoadFromFile(const FileName: string);
    procedure SaveToStream(AStream: TStream);
    procedure LoadFromStream(AStream: TStream);
    function Count: Integer;
    property DebugMapData: TDebugMap read FDebugMapData;
    function InitFromProcess(PID: Cardinal; const ProcessName: string): Boolean;
    function GetHiddenRegion(RootIndex, SubIndex: Integer): TRegionData;
    function GetRegionAtUnfilteredIndex(Index: Integer): TRegionData;
    function GetRegionIndex(Address: Pointer; out Index: Integer): Boolean; overload;
    function RegionToFilterType(Value: TRegionData): TFilters;
    function TotalCount: Integer;
    property DetailedHeapData: Boolean read FDetailedHeapData write SetDetailedHeapData;
    property Items[Index: Integer]: TRegionData read GetItem; default;
    property HighAddress: NativeUInt read FHighAddress;
    property Filter: TFilters read FFilter write SetFilter;
    property Modules: TList<TModule> read FModules;
    property PEB: TPEB read FPEB;
    property PebBaseAddress: Pointer read FPebBaseAddress;
    {$IFDEF WIN64}
    property PEBWow64: TWOW64_PEB read FPebWow64;
    property PebWow64BaseAddress: Pointer read FPebWow64BaseAddress;
    {$ENDIF}
    property PID: Cardinal read FPID;
    property Process64: Boolean read FProcess64;
    property ProcessName: string read FProcessName;
    property ProcessPath: string read FProcessPath;
    property ShowEmpty: Boolean read FShowEmpty write SetShowEmpty;
    property SuspendProcessBeforeScan: Boolean read FSuspendProcess write FSuspendProcess;
    property TotalData: TTotalData read FTotalData;
    property OnGetWow64Heaps: TOnGetWow64HeapsEvent
      read FGetWow64Heaps write FGetWow64Heaps;
    property OnProgress: TProgressEvent read FProgress write FProgress;
  end;

  // синглтон
  function MemoryMapCore: TMemoryMap;

  // процедура перезагружающая экземпляр синглтона, на новый экземпляр класса
  procedure ReplaceMemoryMap(Value: TMemoryMap);

implementation

uses
  MemoryMap.Utils;

var
  _MemoryMap: TMemoryMap = nil;

function MemoryMapCore: TMemoryMap;
begin
  if _MemoryMap = nil then
    _MemoryMap := TMemoryMap.Create;
  Result := _MemoryMap;
end;

procedure ReplaceMemoryMap(Value: TMemoryMap);
begin
  _MemoryMap.Free;
  _MemoryMap := Value;
end;

{ TMemoryMap }

//
//  Процедура рассчитывает общий размер регионов каждого типа
// =============================================================================
procedure TMemoryMap.CalcTotal;
var
  I: Integer;
  R: TRegionData;
  Size: NativeUInt;
begin
  ZeroMemory(@FTotalData, SizeOf(TTotalData));
  for I := 0 to FRegions.Count - 1 do
  begin
    R := FRegions[I];

    if R.MBI.State = MEM_FREE then
    begin
      Inc(FTotalData.Free.Size, R.MBI.RegionSize);
      Inc(FTotalData.Free.Blocks);
      Continue;
    end;

    if R.MBI.State = MEM_COMMIT then
      Size := R.MBI.RegionSize
    else
      Size := 0;

    Inc(FTotalData.Total.Size, R.MBI.RegionSize);
    Inc(FTotalData.Total.Commited, Size);
    Inc(FTotalData.Total.Blocks);

    case RegionToFilterType(R) of
      fiImage:
      begin
        Inc(FTotalData.Image.Size, R.MBI.RegionSize);
        Inc(FTotalData.Image.Commited, Size);
        Inc(FTotalData.Image.Blocks);
      end;
      fiPrivate:
      begin
        Inc(FTotalData._Private.Size, R.MBI.RegionSize);
        Inc(FTotalData._Private.Commited, Size);
        Inc(FTotalData._Private.Blocks);
      end;
      fiShareable:
      begin
        Inc(FTotalData.Shareable.Size, R.MBI.RegionSize);
        Inc(FTotalData.Shareable.Commited, Size);
        Inc(FTotalData.Shareable.Blocks);
      end;
      fiMapped:
      begin
        Inc(FTotalData.Mapped.Size, R.MBI.RegionSize);
        Inc(FTotalData.Mapped.Commited, Size);
        Inc(FTotalData.Mapped.Blocks);
      end;
      fiHeap:
      begin
        Inc(FTotalData.Heap.Size, R.MBI.RegionSize);
        Inc(FTotalData.Heap.Commited, Size);
        Inc(FTotalData.Heap.Blocks);
      end;
      fiThread:
      begin
        Inc(FTotalData.Thread.Size, R.MBI.RegionSize);
        Inc(FTotalData.Thread.Commited, Size);
        Inc(FTotalData.Thread.Blocks);
      end;
      fiSystem:
      begin
        Inc(FTotalData.System.Size, R.MBI.RegionSize);
        Inc(FTotalData.System.Commited, Size);
        Inc(FTotalData.System.Blocks);
      end;
    end;
  end;
end;

//
//  Функция возвращает количество доступных регионов после применения фильтра
// =============================================================================
function TMemoryMap.Count: Integer;
begin
  Result := FRegionFilters.Count;
end;

//
//  Стандартный конструктор
// =============================================================================
constructor TMemoryMap.Create;
begin
  FRegions := TObjectList<TRegionData>.Create(True);
  FRegionFilters := TList<Integer>.Create;
  FModules := TList<TModule>.Create;
  FDebugMapData := TDebugMap.Create;
end;

//
//  Стандартный деструктор
// =============================================================================
destructor TMemoryMap.Destroy;
begin
  FDebugMapData.Free;
  FModules.Free;
  FRegionFilters.Free;
  FRegions.Free;
  inherited;
end;

procedure TMemoryMap.DoProgress(const Step: string; APecent: Integer);
begin
  if Assigned(FProgress) then
    FProgress(Step, APecent);
end;

//
//  Процедура получает инфорацию о всех регионах в открытом процессе
// =============================================================================
procedure TMemoryMap.GetAllRegions;
var
  MBI: TMemoryBasicInformation;
  dwLength: NativeUInt;
  RegionData, LastRegionData: TFriendlyRegionData;
  OwnerName: array [0..MAX_PATH - 1] of Char;
  Shared, Is64Image: Boolean;
  SharedCount: Byte;
  Module: TModule;
  LastPercent, CurrentPercent: Integer;
  MaxAddr: ULONG64;
begin
  FRegions.Clear;
  FRegionFilters.Clear;
  FHighAddress := 0;

  // Инициализация параметров под калбэк прогресса
  LastPercent := 0;
  {$IFDEF WIN64}
  MaxAddr := MM_HIGHEST_USER_ADDRESS64;
  {$ELSE}
  MaxAddr := MM_HIGHEST_USER_ADDRESS32;
  {$ENDIF}

  // Перебираем в цикле все страницы памяти от нулевой,
  // до максимально доступной пользователю
  LastRegionData := nil;
  dwLength := SizeOf(TMemoryBasicInformation);
  while VirtualQueryEx(FProcess, Pointer(FHighAddress), MBI, dwLength) <> 0 do
  begin

    // получили информацию о регионе - создаем обьект, который будет ее хранить
    RegionData := NewRegionData;
    try

      RegionData.SetMBI(MBI);

      // Если регион содержит шареные данные, выставляем флаг и
      // указываем количество ссылок на эту память
      if Workset.GetPageSharedInfo(MBI.BaseAddress, Shared,
        SharedCount) and Shared then
      begin
        RegionData.SetShared(True);
        RegionData.SetSharedCount(SharedCount);
      end;

      if LastRegionData = nil then
        LastRegionData := RegionData
      else
        // проверяем, если регион имеет ту-же AllocationBase, что и предыдущий
        // скрываем текущий (он будет доступен посредством вызова GetHiddenRegion)
        if MBI.AllocationBase = LastRegionData.MBI.AllocationBase then
        begin
          LastRegionData.IncHiddenRegionCount;
          LastRegionData.IncTotalRegionSize(RegionData.TotalRegionSize);
          RegionData.SetRegionVisible(False);
          RegionData.SetParent(LastRegionData);
        end
        else
          LastRegionData := RegionData;

      // Проверка, содержит ли регион отмапленный файл?
      if GetMappedFileName(FProcess, MBI.BaseAddress,
        @OwnerName[0], MAX_PATH) > 0 then
      begin
        Module.Path := NormalizePath(string(OwnerName));
        // Если да, запоминаем его путь
        RegionData.SetDetails(Module.Path);
        // Проверяем, является ли файл исполняемым?
        if CheckPEImage(FProcess, MBI.BaseAddress, Is64Image) then
        begin
          // Если является - запоминаем его в списке модулей
          Module.BaseAddr := ULONG_PTR(MBI.BaseAddress);
          Module.Is64Image := Is64Image;
          Module.LoadAsImage := (MBI.State = MEM_COMMIT) and (MBI.Type_9 = MEM_IMAGE);
          FModules.Add(Module);
          // а самому региону назначаем тип rtExecutableImage
          if Is64Image then
            RegionData.SetRegionType(rtExecutableImage64)
          else
            RegionData.SetRegionType(rtExecutableImage);
          // до кучи получаем информацию по самому PE файлу
          PEImage.GetInfoFromImage(Module.Path, MBI.BaseAddress,
            MBI.RegionSize, Module.LoadAsImage);
          // и пробуем подтянуть его отладочную инфомацию, если есть MAP файл
          if FileExists(ChangeFileExt(Module.Path, '.map')) then
            DebugMapData.Init(ULONG_PTR(MBI.BaseAddress), Module.Path);
        end;
      end;

      // инициализация завершена, добавляем очередной регион в общий спикок
      FRegions.Add(RegionData);
    except
      RegionData.Free;
      raise;
    end;

    // данная переменная доступна извне и содержит адрес,
    // на котором заканчивается доступная процессу память
    Inc(FHighAddress, RegionData.MBI.RegionSize);

    CurrentPercent := Round(FHighAddress / (MaxAddr / 100));
    if CurrentPercent <> LastPercent then
    begin
      LastPercent := CurrentPercent;
      DoProgress(Format('Loading regions data... (%d%%) 0x%x',
        [CurrentPercent, FHighAddress]), CurrentPercent);
    end;
  end;

  DoProgress('All regions data loaded', 100);
end;

//
//  Для доступа к приватным методам TRegionData,
//  к которым запрещен доступ программисту извне,
//  применяется данная функция приводящая TRegionData к TFriendlyRegionData
// =============================================================================
function TMemoryMap.GetFriendlyRegion(Index: Integer): TFriendlyRegionData;
begin
  Result := TFriendlyRegionData(FRegions[Index]);
end;

//
//  Функция предоставляет доступ к дочерним (скрытым) регионам
// =============================================================================
function TMemoryMap.GetHiddenRegion(RootIndex, SubIndex: Integer): TRegionData;
begin
  Result := FRegions[FRegionFilters[RootIndex] + SubIndex];
end;

//
//  Функция предоставляет доступ к регионам с учетом фильтра
// =============================================================================
function TMemoryMap.GetItem(Index: Integer): TRegionData;
begin
  Result := FRegions[FRegionFilters[Index]];
end;

//
//  Обертка над VirtualQueryEx
// =============================================================================
function TMemoryMap.GetPageAtAddr(Address: Pointer): TMemoryBasicInformation;
var
  dwLength: NativeUInt;
begin
  dwLength := SizeOf(TMemoryBasicInformation);
  if VirtualQueryEx(FProcess,
    Pointer(Address), Result, dwLength) <> dwLength then
    RaiseLastOSError;
end;

//
//  Функция возвращает регион по переданному адресу.
//  Если таковой не найден, она создает его.
// =============================================================================
function TMemoryMap.GetRegionAtAddr(Address: Pointer): TFriendlyRegionData;
var
  MBI: TMemoryBasicInformation;
  Index: Integer;
begin
  if not GetRegionIndex(Address, Index) then
  begin
    MBI := GetPageAtAddr(Pointer(Address));
    Index := GetRegionIndex(MBI.BaseAddress);
  end;
  Result := GetFriendlyRegion(Index);
end;

//
//  Доступ к регионам без учета фильтра
// =============================================================================
function TMemoryMap.GetRegionAtUnfilteredIndex(Index: Integer): TRegionData;
begin
  Result := FRegions[Index];
end;

//
//  Функция ищет индекс региона по его BaseAddress.
//  Если не находит, то возвращает индекс, где он должен располагаться
// =============================================================================
function TMemoryMap.GetRegionIndex(Address: Pointer;
  out Index: Integer): Boolean;
var
  L, C, C1, R: Integer;
begin
  Result := False;
  if FRegions.Count = 0 then Exit;
  Index := 0;
  L := 0;
  R := FRegions.Count - 1;
  if ULONG_PTR(Address) <= ULONG_PTR(FRegions[L].MBI.BaseAddress) then Exit(True);
  if ULONG_PTR(Address) >= ULONG_PTR(FRegions[R].MBI.BaseAddress) then
  begin
    Index := R;
    Exit(True);
  end;
  C := (L + R) shr 1;
  repeat
    if ULONG_PTR(Address) = ULONG_PTR(FRegions[C].MBI.BaseAddress) then
    begin
      Index := C;
      Exit(True);
    end;
    if ULONG_PTR(Address) < ULONG_PTR(FRegions[C].MBI.BaseAddress) then
      R := C
    else
      L := C;
    C1 := (L + R) shr 1;
    if C = C1 then
    begin
      Index := C;
      Exit;
    end;
    C := C1;
  until False;
end;

//
//  Функция возвращает индекс региона по переданному адресу.
//  Если таковой не найден, она создает его.
// =============================================================================
function TMemoryMap.GetRegionIndex(Address: Pointer): Integer;
begin
  if not GetRegionIndex(Address, Result) then
    Result := SplitRegionAtAddr(Address, Result);
end;

//
//  Основная функция класса.
//  Получает данные о карте памяти процесса с указанным PID
// =============================================================================
function TMemoryMap.InitFromProcess(PID: Cardinal;
  const ProcessName: string): Boolean;
var
  ProcessLock: TProcessLockHandleList;
begin

  DoProgress('Open process: ' + IntToStr(PID), 0);

  Result := False;
  FRegions.Clear;
  FModules.Clear;
  FDebugMapData.Items.Clear;
  FFilter := fiNone;
  ProcessLock := nil;
  FProcessPath := EmptyStr;
  // Открываем процесс на чтение
  FProcess := OpenProcess(
    PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
    False, PID);
  if FProcess = 0 then
    RaiseLastOSError;
  try
    FPID := PID;
    FProcessName := ProcessName;

    // определяем битность процесса
    FProcess64 := False;
    {$IFDEF WIN64}
      if not IsWow64(FProcess) then
        FProcess64 := True;
    {$ELSE}
      // если наше приложение 32 битное, а исследуемый процесс 64-битный
      // кидаем исключение
      if Is64OS and not IsWow64(FProcess) then
        raise Exception.Create('Can''t scan process.');
    {$ENDIF}

    // проверяем необходимость суспенда процесса
    if SuspendProcessBeforeScan then
      ProcessLock := SuspendProcess(PID);
    try
      FSymbols := TSymbols.Create(FProcess);
      try
        FPEImage := TPEImage.Create(FProcess);
        try
          FWorkset := TWorkset.Create(FProcess);;
          try
            // получаем данные по регионам и отмапленым файлам
            GetAllRegions;
          finally
            FWorkset.Free;
          end;

          {$IFDEF WIN64}
          // если есть возможность получаем данные о 32 битных кучах
          AddWow64HeapsData;
          {$ENDIF}

          // добавляем данные о потоках
          AddThreadsData;

          // добавляем данные о кучах
          AddHeapsData;

          DoProgress('Finalization...', 100);

          // добавляем данные о Process Environment Block
          AddPEBData;
          // добавляем данные о загруженых PE файлах
          AddImagesData;
        finally
          FPEImage.Free;
        end;
      finally
        FSymbols.Free;
      end;
    finally
      if SuspendProcessBeforeScan then
        ResumeProcess(ProcessLock);
    end;
    // сортируем
    SortAllContainsBlocks;
    // считаем общую информацию о регионах
    CalcTotal;
    // применяем текущий фильтр
    UpdateRegionFilters;
  finally
    CloseHandle(FProcess);
  end;
end;

//
//  Процедура загружает ранее сохраненную карту памяти процесса
// =============================================================================
procedure TMemoryMap.LoadFromFile(const FileName: string);
var
  F: TFileStream;
begin
  F := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    LoadFromStream(F);
  finally
    F.Free;
  end;
end;

//
//  Процедура загружает ранее сохраненную карту памяти процесса
// =============================================================================
procedure TMemoryMap.LoadFromStream(AStream: TStream);
var
  S: TStringList;
  I: Integer;
  Region, LastVisibleRegion: TFriendlyRegionData;
  Module: TModule;
begin
  FRegions.Clear;
  FModules.Clear;
  S := TStringList.Create;
  try
    S.LoadFromStream(AStream);
    if S[0] <> HEADER then
      raise EMemoryMapException.Create('Wrong file format.');
    if S[1] <> IntToStr(Version) then
      raise EMemoryMapException.Create('Wrong file version.');
    FProcessName := S[2];
    FPID := StrToInt(S[3]);
    LastVisibleRegion := nil;
    for I := 4 to S.Count - 1 do
    begin
      Region := NewRegionData;
      Region.InitFromString(S[I]);
      if Region.RegionVisible then
        LastVisibleRegion := Region
      else
        Region.SetParent(LastVisibleRegion);
      if Region.RegionType in [rtExecutableImage, rtExecutableImage64] then
      begin
        Module.Path := Region.Details;
        Module.Is64Image := Region.RegionType = rtExecutableImage64;
        Module.LoadAsImage :=
          (Region.MBI.State = MEM_COMMIT) and (Region.MBI.Type_9 = MEM_IMAGE);
        Module.BaseAddr := NativeUInt(Region.MBI.BaseAddress);
        FModules.Add(Module);
      end;
      FRegions.Add(Region);
    end;
  finally
    S.Free;
  end;
  CalcTotal;
  UpdateRegionFilters;
end;

//
//  Создаем ноый обьект для хранения данных о регионе
// =============================================================================
function TMemoryMap.NewRegionData: TFriendlyRegionData;
begin
  Result := TFriendlyRegionData.Create;
end;

//
//  Функция рассчитывает как какому типу фильтра относится переданный регион
// =============================================================================
function TMemoryMap.RegionToFilterType(Value: TRegionData): TFilters;
var
  AResult: TFilters;
begin
  Result := fiNone;
  case Value.RegionType of
    rtDefault:
    begin
      if Value.MBI.State = MEM_FREE then Exit(fiFree);
      if Value.MBI.State = MEM_COMMIT then
        case Value.MBI.Type_9 of
          MEM_IMAGE: Result := fiImage;
          MEM_MAPPED:
          begin
            Result := fiMapped;
            if Value.Shared then
              Result := fiShareable;
          end;
          MEM_PRIVATE: Result := fiPrivate;
        end;
    end;
    rtHeap: Exit(fiHeap);
    rtThread: Exit(fiThread);
    rtSystem: Exit(fiSystem);
    rtExecutableImage, rtExecutableImage64: Exit(fiImage);
  end;
  if not Value.RegionVisible then
  begin
    AResult := RegionToFilterType(Value.Parent);
    if AResult <> fiNone then
      Result := AResult;
  end;
end;

//
//  Сохранение карты памяти
// =============================================================================
procedure TMemoryMap.SaveToFile(const FileName: string);
var
  F: TFileStream;
begin
  F := TFileStream.Create(FileName, fmCreate);
  try
    SaveToStream(F);
  finally
    F.Free;
  end;
end;

//
//  Сохранение карты памяти
// =============================================================================
procedure TMemoryMap.SaveToStream(AStream: TStream);
var
  S: TStringList;
  I: Integer;
begin
  S := TStringList.Create;
  try
    S.Add(HEADER);
    S.Add(IntToStr(Version));
    S.Add(FProcessName);
    S.Add(IntToStr(PID));
    for I := 0 to FRegions.Count - 1 do
      S.Add(GetFriendlyRegion(I).GetAsString);
    S.SaveToStream(AStream);
  finally
    S.Free;
  end;
end;

//
//  Переключение детализации при выводе списка куч
// =============================================================================
procedure TMemoryMap.SetDetailedHeapData(const Value: Boolean);
begin
  if DetailedHeapData <> Value then
  begin
    FDetailedHeapData := Value;
    if PID <> 0 then
      InitFromProcess(PID, ProcessName);
  end;
end;

//
//  Переключение фильтра
// =============================================================================
procedure TMemoryMap.SetFilter(const Value: TFilters);
begin
  if Filter <> Value then
  begin
    FFilter := Value;
    UpdateRegionFilters;
  end;
end;

//
//  Переключение флага о необходимости отображение регионов с невыделенной памятью
// =============================================================================
procedure TMemoryMap.SetShowEmpty(const Value: Boolean);
begin
  if ShowEmpty <> Value then
  begin
    FShowEmpty := Value;
    UpdateRegionFilters;
  end;
end;

//
//  Процедура сортирует данные содержащиеся в поле Contains каждого региона
// =============================================================================
procedure TMemoryMap.SortAllContainsBlocks;
var
  Region: TRegionData;
begin
  for Region in FRegions do
    Region.Contains.Sort(TComparer<TContainItem>.Construct(
      function (const A, B: TContainItem): Integer
      var
        AddrA, AddrB: NativeUInt;
      begin
        Result := 0;
        case A.ItemType of
          itHeapBlock: AddrA := A.Heap.Entry.Address;
          itThreadData: AddrA := NativeUInt(A.ThreadData.Address);
          itStackFrame: AddrA := NativeUInt(A.StackFrame.Data.AddrFrame.Offset);
          itSEHFrame: AddrA := NativeUInt(A.SEH.Address);
          itSystem: AddrA := NativeUInt(A.System.Address);
        else
          AddrA := 0;
        end;
        case B.ItemType of
          itHeapBlock: AddrB := B.Heap.Entry.Address;
          itThreadData: AddrB := NativeUInt(B.ThreadData.Address);
          itStackFrame: AddrB := NativeUInt(B.StackFrame.Data.AddrFrame.Offset);
          itSEHFrame: AddrB := NativeUInt(B.SEH.Address);
          itSystem: AddrB := NativeUInt(B.System.Address);
        else
          AddrB := 0;
        end;
        if AddrA < AddrB then
          Result := -1
        else
          if AddrA > AddrB then
            Result := 1;
      end));
end;

//
//  Функция разделяет существующий регион на два
//  и возвращает индекс вновь созданного региона
// =============================================================================
function TMemoryMap.SplitRegionAtAddr(Address: Pointer;
  Index: Integer): Integer;
var
  OriginalRegion, NextRegion, NewRegion: TFriendlyRegionData;
  MBI: TMemoryBasicInformation;
begin
  NewRegion := NewRegionData;
  try
    // новый регион всегда является чайлдом
    NewRegion.SetRegionVisible(False);
    MBI := GetPageAtAddr(Address);

    // Правим размер предыдущего региона
    OriginalRegion := GetFriendlyRegion(Index);
    OriginalRegion.SetMBIRegionSize(ULONG_PTR(MBI.BaseAddress) -
      ULONG_PTR(OriginalRegion.MBI.BaseAddress));
    // и размер текущего с учетом адреса следующего региона
    // т.к. MBI.RegionSize всегда указывает размер до конца группы регионов
    if Index < FRegions.Count - 1 then
    begin
      NextRegion := GetFriendlyRegion(Index + 1);
      MBI.RegionSize := NativeUInt(NextRegion.MBI.BaseAddress) -
        NativeUInt(MBI.BaseAddress);
    end;

    NewRegion.SetMBI(MBI);

    if OriginalRegion.RegionVisible then
    begin
      OriginalRegion.IncHiddenRegionCount;
      NewRegion.SetParent(OriginalRegion);
    end
    else
    begin
      TFriendlyRegionData(OriginalRegion.Parent).IncHiddenRegionCount;
      NewRegion.SetParent(OriginalRegion.Parent);
    end;

    Result := Index + 1;
    FRegions.Insert(Result, NewRegion);
  except
    NewRegion.Free;
    raise;
  end;
end;

//
//  Общее количество регионов
// =============================================================================
function TMemoryMap.TotalCount: Integer;
begin
  Result := FRegions.Count;
end;

//
//  Добавляем информацию о кучах
// =============================================================================
procedure TMemoryMap.AddHeapsData;
var
  Heap: THeap;
begin
  Heap := THeap.Create(FPID, FProcess, FProgress);
  try
    AddHeapsData(Heap);
  finally
    Heap.Free;
  end;
end;

//
//  Добавляем информацию о кучах
// =============================================================================
procedure TMemoryMap.AddHeapsData(Value: THeap);
var
  RegionData: TFriendlyRegionData;
  ContainItem: TContainItem;
  HeapData: THeapData;
  Index: Integer;
  Cursor, MaxCursor, LastPercent, CurrentPercent: Integer;
begin
  Cursor := 0;
  LastPercent := 0;
  MaxCursor := Value.Data.Count;

  for HeapData in Value.Data do
  begin

    Inc(Cursor);
    CurrentPercent := Round(Cursor / (MaxCursor / 100));
    if CurrentPercent <> LastPercent then
    begin
      LastPercent := CurrentPercent;
      DoProgress(Format('Loading heap data... (%d%%)',
        [CurrentPercent]), CurrentPercent);
    end;

    // если включена детализация, то добавляем все элементы кучи
    if DetailedHeapData then
      RegionData := GetRegionAtAddr(Pointer(HeapData.Entry.Address))
    else
    begin
      // если же детализация отключена, то добавляем только те записи из кучи
      // которые принадлежат рутовым регионам
      GetRegionIndex(Pointer(HeapData.Entry.Address), Index);
      RegionData := GetFriendlyRegion(Index);
      if RegionData.RegionVisible then
        RegionData := GetRegionAtAddr(Pointer(HeapData.Entry.Address));
    end;
    if RegionData.Heap.ID = $FFFFFFFF then
      RegionData.SetHeap(HeapData)
    else
      RegionData.IncTotalHeapSize(HeapData.Entry.Size);
    RegionData.SetRegionType(rtHeap);
    ContainItem.ItemType := itHeapBlock;
    ContainItem.Heap := HeapData;
    RegionData.Contains.Add(ContainItem);
  end;
end;

//
//  Добавляем информацию о загруженых PE файлах
// =============================================================================
procedure TMemoryMap.AddImagesData;
var
  MBI: TMemoryBasicInformation;
  I, Index: Integer;
  RegionData: TFriendlyRegionData;
  Section: TSection;
  SectionSize: NativeInt;
  Directory: TDirectoryArray;
  pEntryPoint: Pointer;
  EntryPoint, TLSCallback: TDirectory;
  pTLSCallback: TTLSCallback;
begin
  // все известные точки входа добавляем в параметр с директориями
  for pEntryPoint in FPEImage.EntryPoints do
  begin
    RegionData := GetRegionAtAddr(pEntryPoint);
    EntryPoint.Flag := dfEntryPoint;
    EntryPoint.Caption := 'EntryPoint';
    EntryPoint.Address := NativeInt(pEntryPoint);
    EntryPoint.Size := 0;
    RegionData.Directory.Add(EntryPoint);
  end;
  // все известные калбэки нитей добавляем в параметр с директориями
  for pTLSCallback in FPEImage.TLSCallbacks do
  begin
    RegionData := GetRegionAtAddr(pTLSCallback.Address);
    TLSCallback.Flag := dfTlsCallback;
    TLSCallback.Caption := pTLSCallback.Caption;
    TLSCallback.Address := ULONG_PTR(pTLSCallback.Address);
    TLSCallback.Size := 0;
    RegionData.Directory.Add(TLSCallback);
  end;
  // теперь добавляем сами директории
  for Directory in FPEImage.Directoryes do
  begin
    for I := 0 to 14 do
    begin
      if not CheckAddr(Directory.Data[I].Address) then Continue;
      RegionData := GetRegionAtAddr(Pointer(Directory.Data[I].Address));
      RegionData.Directory.Add(Directory.Data[I]);
    end;
  end;
  // ну и в конце секции исполняемого файла
  for Section in FPEImage.Sections do
  begin
    // сначала добавляем регионы с которых начинаются инвестные нам секции
    MBI := GetPageAtAddr(Pointer(Section.Address));
    Index := GetRegionIndex(MBI.BaseAddress);
    RegionData := GetFriendlyRegion(Index);
    // а потом добавляем признак секции во все последующие
    // в соответствии с размером секции
    SectionSize := Section.Size;
    repeat
      RegionData.SetSection(Section);
      Dec(SectionSize, RegionData.MBI.RegionSize);
      // Rouse_ 22.12.2022
      // Фикс критической ошибки при открытии процесса
      // Из-за отсутстующей проверки происходил выход за диапазон
      if SectionSize > 0 then
      begin
        Inc(Index);
        RegionData := GetFriendlyRegion(Index);
      end;
    until SectionSize <= 0;
  end;
end;

//
//  Добавляем информацию из PEB
// =============================================================================
procedure TMemoryMap.AddPEBData;

  procedure AddNewData(const Description: string; Address: Pointer);
  var
    RegionData: TFriendlyRegionData;
    ContainItem: TContainItem;
    SystemData: TSystemData;
  begin
    if not CheckAddr(Address) then Exit;
    SystemData.Description := ShortString(Description);
    SystemData.Address := Address;
    RegionData := GetRegionAtAddr(Address);
    if (RegionData.MBI.BaseAddress = Address) and
      (RegionData.RegionType = rtDefault) then
      RegionData.SetPEBData(SystemData)
    else
    begin
      ContainItem.ItemType := itSystem;
      if (RegionData.Contains.Count = 0) and
        CheckAddr(RegionData.SystemData.Address) then
      begin
        ContainItem.System := RegionData.SystemData;
        RegionData.Contains.Add(ContainItem);
      end;
      ContainItem.System := SystemData;
      RegionData.Contains.Add(ContainItem);
    end;
    if RegionData.RegionType = rtDefault then
      RegionData.SetRegionType(rtSystem);
  end;

const
  ProcessBasicInformation = 0;
  ProcessWow64Information = 26;

var
  pProcBasicInfo: PROCESS_BASIC_INFORMATION;
  ReturnLength: NativeUInt;
  ProcessParameters: RTL_USER_PROCESS_PARAMETERS;
  SBI: TSystemInfo;
  PPointerData: Pointer;
begin
  ReturnLength := 0;

  ReturnLength := 0;
  if NtQueryInformationProcess(FProcess, ProcessBasicInformation,
    @pProcBasicInfo, SizeOf(PROCESS_BASIC_INFORMATION),
    @ReturnLength) <> STATUS_SUCCESS then
    RaiseLastOSError;

  FPebBaseAddress := pProcBasicInfo.PebBaseAddress;
  AddNewData('Process Environment Block', FPebBaseAddress);

  if not ReadProcessMemory(FProcess, FPebBaseAddress,
    @FPeb, SizeOf(TPEB), ReturnLength) then
    RaiseLastOSError;

  {$IFDEF WIN64}
  if not Process64 then
  begin

    if NtQueryInformationProcess(FProcess, ProcessWow64Information,
      @FPebWow64BaseAddress, SizeOf(ULONG_PTR),
      @ReturnLength) <> STATUS_SUCCESS then
      RaiseLastOSError;

    AddNewData('Process Environment Block (Wow64)', FPebWow64BaseAddress);

    if not ReadProcessMemory(FProcess, FPebWow64BaseAddress,
      @FPebWow64, SizeOf(TWOW64_PEB), ReturnLength) then
      RaiseLastOSError;

    AddNewData('LoaderData (Wow64)', Pointer(FPebWow64.LoaderData));
    AddNewData('ProcessParameters (Wow64)', Pointer(FPebWow64.ProcessParameters));
    if FPebWow64.ReadOnlySharedMemoryBase <> Cardinal(FPeb.ReadOnlySharedMemoryBase) then
      AddNewData('ReadOnlySharedMemoryBase (Wow64)', Pointer(FPebWow64.ReadOnlySharedMemoryBase));
    if FPebWow64.HotpatchInformation <> Cardinal(FPeb.HotpatchInformation) then
      AddNewData('HotpatchInformation (Wow64)', Pointer(FPebWow64.HotpatchInformation));

    PPointerData := nil;
    if not ReadProcessMemory(FProcess, Pointer(FPebWow64.ReadOnlyStaticServerData),
      @PPointerData, 4, ReturnLength) then
      RaiseLastOSError;

    AddNewData('ReadOnlyStaticServerData (Wow64)', PPointerData);

    if FPebWow64.AnsiCodePageData <> Cardinal(FPeb.AnsiCodePageData) then
      AddNewData('AnsiCodePageData (Wow64)', Pointer(FPebWow64.AnsiCodePageData));
    if FPebWow64.OemCodePageData <> Cardinal(FPeb.OemCodePageData) then
      AddNewData('OemCodePageData (Wow64)', Pointer(FPebWow64.OemCodePageData));
    if FPebWow64.UnicodeCaseTableData <> Cardinal(FPeb.UnicodeCaseTableData) then
      AddNewData('UnicodeCaseTableData (Wow64)', Pointer(FPebWow64.UnicodeCaseTableData));

    if FPebWow64.GdiSharedHandleTable <> Cardinal(FPeb.GdiSharedHandleTable) then
      AddNewData('GdiSharedHandleTable (Wow64)', Pointer(FPebWow64.GdiSharedHandleTable));
    if FPebWow64.ProcessStarterHelper <> Cardinal(FPeb.ProcessStarterHelper) then
      AddNewData('ProcessStarterHelper (Wow64)', Pointer(FPebWow64.ProcessStarterHelper));
    if FPebWow64.PostProcessInitRoutine <> Cardinal(FPeb.PostProcessInitRoutine) then
      AddNewData('PostProcessInitRoutine (Wow64)', Pointer(FPebWow64.PostProcessInitRoutine));
    if FPebWow64.TlsExpansionBitmap <> Cardinal(FPeb.TlsExpansionBitmap) then
    AddNewData('TlsExpansionBitmap (Wow64)', Pointer(FPebWow64.TlsExpansionBitmap));

    // Compatilibity
    if FPebWow64.pShimData <> Cardinal(FPeb.pShimData) then
      AddNewData('pShimData (Wow64)', Pointer(FPebWow64.pShimData));
    if FPebWow64.AppCompatInfo <> Cardinal(FPeb.AppCompatInfo) then
     AddNewData('AppCompatInfo (Wow64)', Pointer(FPebWow64.AppCompatInfo));

    if FPebWow64.ActivationContextData <> Cardinal(FPeb.ActivationContextData) then
      AddNewData('ActivationContextData (Wow64)', Pointer(FPebWow64.ActivationContextData));
    if FPebWow64.ProcessAssemblyStorageMap <> Cardinal(FPeb.ProcessAssemblyStorageMap) then
      AddNewData('ProcessAssemblyStorageMap (Wow64)', Pointer(FPebWow64.ProcessAssemblyStorageMap));
    if FPebWow64.SystemDefaultActivationContextData <> Cardinal(FPeb.SystemDefaultActivationContextData) then
      AddNewData('SystemDefaultActivationContextData (Wow64)', Pointer(FPebWow64.SystemDefaultActivationContextData));
    if FPebWow64.SystemAssemblyStorageMap <> Cardinal(FPeb.SystemAssemblyStorageMap) then
      AddNewData('SystemAssemblyStorageMap (Wow64)', Pointer(FPebWow64.SystemAssemblyStorageMap));

    if FPebWow64.ApiSetMap <> Cardinal(FPeb.ApiSetMap) then
      AddNewData('ApiSetMap (Wow64)', Pointer(FPebWow64.ApiSetMap));
  end;
  {$ENDIF}

  AddNewData('LoaderData', Pointer(FPeb.LoaderData));
  AddNewData('ProcessParameters', Pointer(FPeb.ProcessParameters));
  AddNewData('ReadOnlySharedMemoryBase', Pointer(FPeb.ReadOnlySharedMemoryBase));
  AddNewData('HotpatchInformation', Pointer(FPeb.HotpatchInformation));

  PPointerData := nil;
  if not ReadProcessMemory(FProcess, FPeb.ReadOnlyStaticServerData,
    @PPointerData, 4, ReturnLength) then
    RaiseLastOSError;

  AddNewData('ReadOnlyStaticServerData', PPointerData);

  AddNewData('AnsiCodePageData', Pointer(FPeb.AnsiCodePageData));
  AddNewData('OemCodePageData', Pointer(FPeb.OemCodePageData));
  AddNewData('UnicodeCaseTableData', Pointer(FPeb.UnicodeCaseTableData));

  AddNewData('GdiSharedHandleTable', Pointer(FPeb.GdiSharedHandleTable));
  AddNewData('ProcessStarterHelper', Pointer(FPeb.ProcessStarterHelper));
  AddNewData('PostProcessInitRoutine', Pointer(FPeb.PostProcessInitRoutine));
  AddNewData('TlsExpansionBitmap', Pointer(FPeb.TlsExpansionBitmap));

  AddNewData('pShimData', Pointer(FPeb.pShimData));
  AddNewData('AppCompatInfo', Pointer(FPeb.AppCompatInfo));

  AddNewData('ActivationContextData', Pointer(FPeb.ActivationContextData));
  AddNewData('ProcessAssemblyStorageMap', Pointer(FPeb.ProcessAssemblyStorageMap));
  AddNewData('SystemDefaultActivationContextData', Pointer(FPeb.SystemDefaultActivationContextData));
  AddNewData('SystemAssemblyStorageMap', Pointer(FPeb.SystemAssemblyStorageMap));

  AddNewData('ApiSetMap', Pointer(FPeb.ApiSetMap));

  if not ReadProcessMemory(FProcess, FPeb.ProcessParameters,
    @ProcessParameters, SizeOf(RTL_USER_PROCESS_PARAMETERS), ReturnLength) then
    RaiseLastOSError;
  AddNewData('Process Environments', ProcessParameters.Environment);

  SetLength(FProcessPath, ProcessParameters.ImagePathName.Length div SizeOf(Char));
  if not ReadProcessMemory(FProcess, ProcessParameters.ImagePathName.Buffer,
    @FProcessPath[1], ProcessParameters.ImagePathName.Length, ReturnLength) then
    RaiseLastOSError;

  GetSystemInfo(SBI);
  AddNewData('KE_USER_SHARED_DATA',
    Pointer(NativeUInt(SBI.lpMaximumApplicationAddress) and $7FFF0000));
end;

//
//  Добавляем информацию о потоках
// =============================================================================
procedure TMemoryMap.AddThreadsData;
var
  Threads: TThreads;
begin
  DoProgress('Take threads snapshot...', 0);
  Threads := TThreads.Create(FPID, FProcess);
  try
    AddThreadsData(Threads);
  finally
    Threads.Free;
  end;
end;

//
//  Добавляем информацию о потоках
// =============================================================================
procedure TMemoryMap.AddThreadsData(Value: TThreads);

  function CheckRegionType(Value: TRegionType): Boolean;
  begin
    Result := not (Value in [rtExecutableImage, rtExecutableImage64]);
  end;

var
  RegionData, ImageRegion: TFriendlyRegionData;
  ThreadData: TThreadData;
  ContainItem: TContainItem;
  ThreadStackEntry: TThreadStackEntry;
  Index: Integer;
  SEHEntry: TSEHEntry;
  Cursor, MaxCursor, LastPercent, CurrentPercent: Integer;

  procedure CalcProgress(const Value: string);
  begin
    Inc(Cursor);
    CurrentPercent := Round(Cursor / (MaxCursor / 100));
    if CurrentPercent <> LastPercent then
    begin
      LastPercent := CurrentPercent;
      DoProgress(Format(Value, [CurrentPercent]), CurrentPercent);
    end;
  end;

begin
  Cursor := 0;
  MaxCursor :=
    Value.ThreadData.Count +
    Value.ThreadStackEntries.Count +
    Value.SEHEntries.Count;
  LastPercent := 0;

  // сначала информацию о стеке, адресе потоковой процедуры и TEB
  for ThreadData in Value.ThreadData do
  begin

    CalcProgress('Loading threads data... (%d%%)');

    if not CheckAddr(ThreadData.Address) then Continue;

    RegionData := GetRegionAtAddr(ThreadData.Address);

    if ThreadData.Flag = tiThreadProc then
    begin
      ContainItem.ItemType := itThreadData;
      ContainItem.ThreadData := ThreadData;
      RegionData.Contains.Add(ContainItem);

      ImageRegion := RegionData;
      if CheckRegionType(ImageRegion.RegionType) then
      begin
        ImageRegion := TFriendlyRegionData(RegionData.Parent);
        if ImageRegion <> nil then
          if CheckRegionType(ImageRegion.RegionType) then
            ImageRegion := nil;
      end;

      if ImageRegion <> nil then
        RegionData.SetDetails(FSymbols.GetDescriptionAtAddr(
          ULONG_PTR(ThreadData.Address),
          ULONG_PTR(ImageRegion.MBI.BaseAddress),
          ImageRegion.Details));

      Continue;
    end;

    if CheckRegionType(RegionData.RegionType) then
      RegionData.SetRegionType(rtThread);

    if RegionData.MBI.BaseAddress = ThreadData.Address then
      RegionData.SetThread(ThreadData)
    else
    begin
      ContainItem.ItemType := itThreadData;
      ContainItem.ThreadData := ThreadData;
      RegionData.Contains.Add(ContainItem);
    end;

    if ThreadData.Flag = tiThreadProc then Continue;
    if not RegionData.RegionVisible then
    begin
      TFriendlyRegionData(RegionData.Parent).SetRegionType(rtThread);
      if TFriendlyRegionData(RegionData.Parent).Thread.ThreadID = 0 then
        TFriendlyRegionData(RegionData.Parent).SetThreadIDAndWow(
          ThreadData.ThreadID, ThreadData.Wow64);
    end;


  end;

  // потом информацию о CallStack
  for ThreadStackEntry in Value.ThreadStackEntries do
  begin

    CalcProgress('Loading threads stack... (%d%%)');

    if not CheckAddr(ThreadStackEntry.Data.AddrFrame.Offset) then Continue;

    RegionData := GetRegionAtAddr(Pointer(ThreadStackEntry.Data.AddrFrame.Offset));
    ContainItem.ItemType := itStackFrame;

    GetRegionIndex(Pointer(ThreadStackEntry.Data.AddrPC.Offset), Index);
    ImageRegion := GetFriendlyRegion(Index);

    if CheckRegionType(ImageRegion.RegionType) then
    begin
      ImageRegion := TFriendlyRegionData(ImageRegion.Parent);
      if ImageRegion <> nil then
        if CheckRegionType(ImageRegion.RegionType) then
          ImageRegion := nil;
    end;

    if ImageRegion <> nil then
      ThreadStackEntry.SetFuncName(FSymbols.GetDescriptionAtAddr(
        ULONG_PTR(ThreadStackEntry.Data.AddrPC.Offset),
        ULONG_PTR(ImageRegion.MBI.BaseAddress),
        ImageRegion.Details));

    ContainItem.StackFrame := ThreadStackEntry;
    RegionData.Contains.Add(ContainItem);
  end;

  // и в завершение информацию о SEH фреймах
  for SEHEntry in Value.SEHEntries do
  begin

    CalcProgress('Loading SEH data... (%d%%)');

    if not CheckAddr(SEHEntry.Address) then Continue;
    RegionData := GetRegionAtAddr(SEHEntry.Address);
    ContainItem.ItemType := itSEHFrame;

    GetRegionIndex(SEHEntry.Handler, Index);
    ImageRegion := GetFriendlyRegion(Index);

    if CheckRegionType(ImageRegion.RegionType) then
    begin
      ImageRegion := TFriendlyRegionData(ImageRegion.Parent);
      if ImageRegion <> nil then
        if CheckRegionType(ImageRegion.RegionType) then
          ImageRegion := nil;
    end;

    if ImageRegion <> nil then
      SEHEntry.SetHandlerName(FSymbols.GetDescriptionAtAddr(
        ULONG_PTR(SEHEntry.Handler),
        ULONG_PTR(ImageRegion.MBI.BaseAddress),
        ImageRegion.Details));

    ContainItem.SEH := SEHEntry;
    RegionData.Contains.Add(ContainItem);
  end;
end;

//
//  Добавляем информацию о Wow64 кучах
// =============================================================================
procedure TMemoryMap.AddWow64HeapsData;
var
  Heaps: THeap;
begin
  if Process64 then Exit;
  if not Assigned(FGetWow64Heaps) then Exit;
  Heaps := THeap.Create;
  try
    FGetWow64Heaps(Heaps);
    AddHeapsData(Heaps);
  finally
    Heaps.Free;
  end;
end;

//
//  Процедура обновляем список FRegionFilters с индексами
//  отфильтрованных регионов на основании текущего фильтра
// =============================================================================
procedure TMemoryMap.UpdateRegionFilters;

  procedure AddToFilter(Index: Integer;
    ARegionData: TFriendlyRegionData; CheckParent: Boolean = False);
  begin
    if ARegionData.RegionVisible then
    begin
      FRegionFilters.Add(Index);
      ARegionData.SetFiltered(True);
      Exit;
    end;
    if not CheckParent then Exit;    
    if ARegionData.Parent = nil then Exit;
    if ARegionData.Parent.Filtered then Exit;
    FRegionFilters.Add(Index);
    ARegionData.SetFiltered(True);
  end;

var
  I, A: Integer;
  R: TFriendlyRegionData;
begin
  FRegionFilters.Clear;
  case Filter of
    fiNone:
    begin
      for I := 0 to FRegions.Count - 1 do
      begin
        R := GetFriendlyRegion(I);
        R.SetFiltered(False);
        if not R.RegionVisible then Continue;
        if ShowEmpty then
          AddToFilter(I, R)
        else
          if (R.MBI.State <> MEM_FREE) or (R.RegionType <> rtDefault) then
            AddToFilter(I, R);
      end;
    end;
    fiThread:
    begin
      for I := 0 to FRegions.Count - 1 do
      begin
        R := GetFriendlyRegion(I);
        R.SetFiltered(False);
        if RegionToFilterType(R) = Filter then
          AddToFilter(I, R, True)
        else
          for A := 0 to R.Contains.Count - 1 do
            if R.Contains[A].ItemType in [itThreadData, itStackFrame, itSEHFrame] then
            begin
              AddToFilter(I, R, True);
              Break;
            end;
      end;
    end;
    fiSystem:
    begin
      for I := 0 to FRegions.Count - 1 do
      begin
        R := GetFriendlyRegion(I);
        R.SetFiltered(False);
        if RegionToFilterType(R) = Filter then
          AddToFilter(I, R, True)
        else
          for A := 0 to R.Contains.Count - 1 do
            if R.Contains[A].ItemType = itSystem then
            begin
              AddToFilter(I, R, True);
              Break;
            end;
      end;
    end;
  else
    for I := 0 to FRegions.Count - 1 do
    begin
      R := GetFriendlyRegion(I);
      R.SetFiltered(False);
      if RegionToFilterType(R) = Filter then
        AddToFilter(I, R)
    end;
  end;

end;

initialization

finalization

  _MemoryMap.Free;

end.
