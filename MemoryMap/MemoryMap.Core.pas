////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : MemoryMap.Core.pas
//  * Purpose   : A base class that collects information about the process's
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
  MemoryMapVersionInt = $01040029;
  MemoryMapVersionStr = '1.4 (revision 41)';

type
  TFilters = (

    // show all regions
    // [ru] отображать все регионы

    fiNone,

    // only files containing PE
    // [ru] только содержащие PE файлы

    fiImage,

    // only private memory
    // [ru] только приватную память

    fiPrivate,

    // shared memory only
    // [ru] только шареную память

    fiShareable,

    // only mapped regions
    // [ru] только отмапленные регионы

    fiMapped,

    // only those containing a heap
    // [ru] только содержащие кучу

    fiHeap,

    // containing thread data
    // [ru] только содержащие данные нитей

    fiThread,

    // containing system structures
    // [ru] только содержащие системные структуры

    fiSystem,

    // only free regions
    // [ru] только свободные регионы

    fiFree,

    // containing at least some data
    // [ru] содержащие хоть какие-то данные

    fiNotNone);

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

    /// <summary>
    /// The function provides access to regions based on the filter
    /// </summary>
    /// <remarks>
    /// [ru] Функция предоставляет доступ к регионам с учетом фильтра
    /// </remarks>
    function GetItem(Index: Integer): TRegionData;
    procedure SetShowEmpty(const Value: Boolean);
    procedure SetFilter(const Value: TFilters);

    /// <summary>
    /// Toggling the level of detail when displaying a list of heaps with process reconnection
    /// </summary>
    /// <remarks>
    /// [ru] Переключение детализации при выводе списка куч с переподключением процесса
    /// </remarks>
    procedure SetDetailedHeapData(const Value: Boolean);
  protected
    procedure DoProgress(const Step: string; APecent: Integer);

    /// <summary>
    /// To access the private methods of TRegionData,
    /// which are not accessible from outside,
    /// this function is used to cast TRegionData to TFriendlyRegionData
    /// </summary>
    /// <remarks>
    /// [ru] Для доступа к приватным методам TRegionData,
    /// к которым запрещен доступ извне, применяется данная функция
    /// приводящая TRegionData к TFriendlyRegionData
    /// </remarks>
    function GetFriendlyRegion(Index: Integer): TFriendlyRegionData;

    /// <summary>
    /// A wrapper around VirtualQueryEx
    /// </summary>
    /// <remarks>
    /// [ru] Обертка над VirtualQueryEx
    /// </remarks>
    function GetPageAtAddr(Address: Pointer): TMemoryBasicInformation;

    /// <summary>
    /// The function returns a region based on the provided address.
    /// If no such region is found, it creates one.
    /// </summary>
    /// <remarks>
    /// [ru] Функция возвращает регион по переданному адресу.
    /// Если таковой не найден, она создает его.
    /// </remarks>
    function GetRegionAtAddr(Address: Pointer): TFriendlyRegionData;

    /// <summary>
    /// The function returns a region based on the provided address.
    /// If no such region is found, it creates one.
    /// </summary>
    /// <remarks>
    /// [ru] Функция возвращает регион по переданному адресу.
    /// Если таковой не найден, она создает его.
    /// </remarks>
    function GetRegionIndex(Address: Pointer): Integer; overload;

    /// <summary>
    /// This function creates a new object to store data about the region
    /// </summary>
    /// <remarks>
    /// [ru] Функция создает новый обьект для хранения данных о регионе
    /// </remarks>
    function NewRegionData: TFriendlyRegionData;

    /// <summary>
    /// This function splits an existing region into two
    /// and returns the index of the newly created region
    /// </summary>
    /// <remarks>
    /// [ru] Функция разделяет существующий регион на два
    /// и возвращает индекс вновь созданного региона
    /// </remarks>
    function SplitRegionAtAddr(Address: Pointer; Index: Integer): Integer;
  protected

    /// <summary>
    /// Adding information about uploaded PE files
    /// </summary>
    /// <remarks>
    /// [ru] Добавляем информацию о загруженых PE файлах
    /// </remarks>
    procedure AddImagesData;
    procedure AddHeapsData; overload;
    procedure AddHeapsData(Value: THeap); overload;
    procedure AddWow64HeapsData;
    procedure AddPEBData;
    procedure AddThreadsData; overload;
    procedure AddThreadsData(Value: TThreads); overload;

    /// <summary>
    /// The procedure retrieves information about all regions in an open process
    /// </summary>
    /// <remarks>
    /// [ru] Процедура получает информацию о всех регионах в открытом процессе
    /// </remarks>
    procedure GetAllRegions;

    /// <summary>
    /// The procedure calculates the total size of regions of each type
    /// </summary>
    /// <remarks>
    /// [ru] Процедура рассчитывает общий размер регионов каждого типа
    /// </remarks>
    procedure CalcTotal;

    /// <summary>
    /// This procedure updates the list of regions with the indexes
    /// of the filtered regions based on the current filter
    /// </summary>
    /// <remarks>
    /// [ru] Процедура обновляет список регионов с индексами
    /// отфильтрованных регионов на основании текущего фильтра
    /// </remarks>
    procedure UpdateRegionFilters;

    /// <summary>
    /// Sorting the data contained in the "Contains" field for each region
    /// </summary>
    /// <remarks>
    /// [ru] Cортировка данных содержащиеся в поле "Contains" каждого региона
    /// </remarks>
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

    /// <summary>
    /// The function returns the number of available regions after applying the filter
    /// </summary>
    /// <remarks>
    /// [ru] Функция возвращает количество доступных регионов после применения фильтра
    /// </remarks>
    function Count: Integer;

    /// <summary>
    /// Retrieves information about the memory map of the process with the specified PID
    /// </summary>
    /// <remarks>
    /// [ru] Получает данные о карте памяти процесса с указанным PID
    /// </remarks>
    function InitFromProcess(PID: Cardinal; const ProcessName: string): Boolean;

    /// <summary>
    /// This function provides access to child (hidden) regions
    /// </summary>
    /// <remarks>
    /// [ru] Функция предоставляет доступ к дочерним (скрытым) регионам
    /// </remarks>
    function GetHiddenRegion(RootIndex, SubIndex: Integer): TRegionData;

    /// <summary>
    /// Access to regions without applying a filter
    /// </summary>
    /// <remarks>
    /// [ru] Доступ к регионам без учета фильтра
    /// </remarks>
    function GetRegionAtUnfilteredIndex(Index: Integer): TRegionData;

    /// <summary>
    /// This function searches for a region's index based on its BaseAddress.
    /// If it doesn't find it, it returns the index where it should be located
    /// </summary>
    /// <remarks>
    /// [ru] Функция ищет индекс региона по его BaseAddress.
    /// Если не находит, то возвращает индекс, где он должен располагаться
    /// </remarks>
    function GetRegionIndex(Address: Pointer; out Index: Integer): Boolean; overload;

    /// <summary>
    /// This function determines which filter type the specified region belongs to
    /// </summary>
    /// <remarks>
    /// [ru] Функция рассчитывает как какому типу фильтра относится переданный регион
    /// </remarks>
    function RegionToFilterType(Value: TRegionData; PriorityFilter: TFilters): TFilters;

    /// <summary>
    /// Total number of regions
    /// </summary>
    /// <remarks>
    /// [ru] Общее количество регионов
    /// </remarks>
    function TotalCount: Integer;
    property DebugMapData: TDebugMap read FDebugMapData;
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

  EReadRemoteMemoryException = class(Exception)
    constructor Create(const AMessage: string; AddrVA: Pointer);
  end;

  function MemoryMapCore: TMemoryMap;

  /// <summary>
  /// A procedure that restarts a singleton instance based on the class instance passed as a parameter
  /// </summary>
  /// <remarks>
  /// [ru] Процедура перезагружающая экземпляр синглтона, на новый экземпляр класса переданый параметром
  /// </remarks>
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

    case RegionToFilterType(R, fiNotNone) of
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

function TMemoryMap.Count: Integer;
begin
  Result := FRegionFilters.Count;
end;

constructor TMemoryMap.Create;
begin
  FRegions := TObjectList<TRegionData>.Create(True);
  FRegionFilters := TList<Integer>.Create;
  FModules := TList<TModule>.Create;
  FDebugMapData := TDebugMap.Create;
end;

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

  // Initializing parameters for the progress callback
  // [ru] Инициализация параметров под калбэк прогресса

  LastPercent := 0;
  if Process64 then
    MaxAddr := MM_HIGHEST_USER_ADDRESS64
  else
    MaxAddr := MM_HIGHEST_USER_ADDRESS32;

  // We iterate through all memory pages in a loop, starting from page 0
  // up to the maximum page number available to the user

  // [ru] Перебираем в цикле все страницы памяти от нулевой,
  // до максимально доступной пользователю

  LastRegionData := nil;
  dwLength := SizeOf(TMemoryBasicInformation);
  while VirtualQueryEx(FProcess, Pointer(FHighAddress), MBI, dwLength) <> 0 do
  begin

    // Once we've received information about the region, we create an object to store it
    // [ru] получили информацию о регионе - создаем обьект, который будет ее хранить

    RegionData := NewRegionData;
    try

      RegionData.SetMBI(MBI);

      // If a region contains shared data, we set a flag
      // and specify the number of references to that memory

      // [ru] Если регион содержит шареные данные, выставляем флаг и
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
      begin

        // Check if the region has the same AllocationBase as the previous one,
        // if so, hide the current one (it will be accessible by calling GetHiddenRegion)

        // [ru] проверяем, если регион имеет ту-же AllocationBase, что и предыдущий
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

      end;

      // Check whether the region contains a mapped file
      // [ru] Проверка, содержит ли регион отмапленный файл

      if GetMappedFileName(FProcess, MBI.BaseAddress,
        @OwnerName[0], MAX_PATH) > 0 then
      begin
        Module.Path := NormalizePath(string(OwnerName));

        // If so, we save its path
        // [ru] Если да, запоминаем его путь

        RegionData.SetDetails(Module.Path);

        // Checking whether the file is an executable
        // [ru] Проверяем, является ли файл исполняемым

        if CheckPEImage(FProcess, MBI.BaseAddress, Is64Image) then
        begin

          // If so, we add it to the list of modules
          // [ru] Если да - добавляем его в список модулей

          Module.BaseAddr := ULONG_PTR(MBI.BaseAddress);
          Module.Is64Image := Is64Image;
          Module.LoadAsImage := (MBI.State = MEM_COMMIT) and (MBI.Type_9 = MEM_IMAGE);
          FModules.Add(Module);

          // and we assign the type rtExecutableImage to the region itself
          // [ru] а самому региону назначаем тип rtExecutableImage

          if Is64Image then
            RegionData.SetRegionType(rtExecutableImage64)
          else
            RegionData.SetRegionType(rtExecutableImage);

          // On top of that, we get information about the PE file itself
          // [ru] до кучи получаем информацию по самому PE файлу

          PEImage.GetInfoFromImage(Module.Path, MBI.BaseAddress,
            MBI.RegionSize, Module.LoadAsImage);

          // and we try to retrieve its debug information, if there is a MAP file
          // [ru] и пробуем подтянуть его отладочную информацию, если есть MAP файл

          if FileExists(ChangeFileExt(Module.Path, '.map')) then
            DebugMapData.Init(ULONG_PTR(MBI.BaseAddress), Module.Path);
        end;
      end;

      // Initialization is complete, we add the region to the general list
      // [ru] инициализация завершена, добавляем регион в общий список

      FRegions.Add(RegionData);
    except
      RegionData.Free;
      raise;
    end;

    // This variable is accessible from outside and contains the address
    // at which the memory accessible to the process ends

    // [ru] данная переменная доступна извне и содержит адрес,
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

function TMemoryMap.GetFriendlyRegion(Index: Integer): TFriendlyRegionData;
begin
  Result := TFriendlyRegionData(FRegions[Index]);
end;

function TMemoryMap.GetHiddenRegion(RootIndex, SubIndex: Integer): TRegionData;
begin
  Result := FRegions[FRegionFilters[RootIndex] + SubIndex];
end;

function TMemoryMap.GetItem(Index: Integer): TRegionData;
begin
  Result := FRegions[FRegionFilters[Index]];
end;

function TMemoryMap.GetPageAtAddr(Address: Pointer): TMemoryBasicInformation;
var
  dwLength: NativeUInt;
begin
  dwLength := SizeOf(TMemoryBasicInformation);
  if VirtualQueryEx(FProcess,
    Pointer(Address), Result, dwLength) <> dwLength then
    RaiseLastOSError;
end;

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

function TMemoryMap.GetRegionAtUnfilteredIndex(Index: Integer): TRegionData;
begin
  Result := FRegions[Index];
end;

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

function TMemoryMap.GetRegionIndex(Address: Pointer): Integer;
begin
  if not GetRegionIndex(Address, Result) then
    Result := SplitRegionAtAddr(Address, Result);
end;

function TMemoryMap.InitFromProcess(PID: Cardinal;
  const ProcessName: string): Boolean;
var
  ProcessLock: TProcessLockHandleList;
begin

  DoProgress('Open process: ' + IntToStr(PID), 0);

  Result := False;
  FRegions.Clear;
  FModules.Clear;
  FDebugMapData.Clear;
  FFilter := fiNone;
  ProcessLock := nil;
  FProcessPath := EmptyStr;
  FProcess := OpenProcess(
    PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
    False, PID);
  if FProcess = 0 then
    RaiseLastOSError;
  try
    FPID := PID;
    FProcessName := ProcessName;

    // determine the bit depth of the process
    // [ru] определяем битность процесса

    FProcess64 := False;
    {$IFDEF WIN64}
      if not IsWow64(FProcess) then
        FProcess64 := True;
    {$ELSE}

      // If our application is 32-bit and the process being examined is 64-bit,
      // we throw an exception

      // [ru] если наше приложение 32 битное, а исследуемый процесс 64-битный
      // кидаем исключение

      if Is64OS and not IsWow64(FProcess) then
        raise Exception.Create('Can''t scan process.');
    {$ENDIF}

    if SuspendProcessBeforeScan then
      ProcessLock := SuspendProcess(PID);
    try
      DoProgress('Init Symbols...', 25);
      FSymbols := TSymbols.Create(FProcess);
      try
        FPEImage := TPEImage.Create(FProcess);
        try
          DoProgress('Init Workset...', 50);
          FWorkset := TWorkset.Create(FProcess);;
          try
            GetAllRegions;
          finally
            FWorkset.Free;
          end;

          {$IFDEF WIN64}
          AddWow64HeapsData;
          {$ENDIF}

          AddThreadsData;
          AddPEBData;
          AddHeapsData;

          DoProgress('Finalization...', 100);

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
    SortAllContainsBlocks;
    CalcTotal;
    UpdateRegionFilters;
  finally
    CloseHandle(FProcess);
  end;
end;

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

function TMemoryMap.NewRegionData: TFriendlyRegionData;
begin
  Result := TFriendlyRegionData.Create;
end;

function TMemoryMap.RegionToFilterType(Value: TRegionData;
  PriorityFilter: TFilters): TFilters;
var
  AResult: TFilters;

  function IsFilterApply(CurrentFilter: TFilters): Boolean;
  begin
    if (PriorityFilter = fiNotNone) and (CurrentFilter <> fiNone) then
      Result := True
    else
      Result := PriorityFilter = CurrentFilter;
  end;

begin
  Result := fiNone;
  case Value.RegionType of
    rtHeap: Result := fiHeap;
    rtThread: Result := fiThread;
    rtSystem: Result := fiSystem;
    rtExecutableImage, rtExecutableImage64: Result := fiImage;
  end;
  if IsFilterApply(Result) then Exit;

  if Value.MBI.State = MEM_FREE then Result := fiFree;
  if IsFilterApply(Result) then Exit;

  if Value.MBI.State = MEM_COMMIT then
    case Value.MBI.Type_9 of
      MEM_IMAGE: Result := fiImage;
      MEM_MAPPED:
      begin
        if Value.Shared then
          Result := fiShareable
        else
          Result := fiMapped;
      end;
      MEM_PRIVATE: Result := fiPrivate;
    end;

  if IsFilterApply(Result) then Exit;

  if not Value.RegionVisible then
  begin
    AResult := RegionToFilterType(Value.Parent, PriorityFilter);
    if AResult <> fiNone then
      Result := AResult;
  end;
end;

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

procedure TMemoryMap.SetDetailedHeapData(const Value: Boolean);
begin
  if DetailedHeapData <> Value then
  begin
    FDetailedHeapData := Value;
    if PID <> 0 then
      InitFromProcess(PID, ProcessName);
  end;
end;

procedure TMemoryMap.SetFilter(const Value: TFilters);
begin
  if Filter <> Value then
  begin
    FFilter := Value;
    UpdateRegionFilters;
  end;
end;

procedure TMemoryMap.SetShowEmpty(const Value: Boolean);
begin
  if ShowEmpty <> Value then
  begin
    FShowEmpty := Value;
    UpdateRegionFilters;
  end;
end;

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

function TMemoryMap.SplitRegionAtAddr(Address: Pointer;
  Index: Integer): Integer;
var
  OriginalRegion, NextRegion, NewRegion: TFriendlyRegionData;
  MBI: TMemoryBasicInformation;
begin
  NewRegion := NewRegionData;
  try

    // a new region is always a child
    // [ru] новый регион всегда является чайлдом

    NewRegion.SetRegionVisible(False);
    MBI := GetPageAtAddr(Address);

    // Adjust the size of the previous region
    // [ru] Правим размер предыдущего региона

    OriginalRegion := GetFriendlyRegion(Index);
    OriginalRegion.SetMBIRegionSize(ULONG_PTR(MBI.BaseAddress) -
      ULONG_PTR(OriginalRegion.MBI.BaseAddress));

    // and the size of the current region, taking into account the address
    // of the next region, since MBI.RegionSize always specifies the size up
    // to the end of the region group

    // [ru] и размер текущего с учетом адреса следующего региона
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

function TMemoryMap.TotalCount: Integer;
begin
  Result := FRegions.Count;
end;

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

    // If detail mode is enabled, add all elements of the heap
    // [ru] если включена детализация, то добавляем все элементы кучи

    if DetailedHeapData then
      RegionData := GetRegionAtAddr(Pointer(HeapData.Entry.Address))
    else
    begin

      // If the breakdown is disabled, then we add only those records
      // from the heap that belong to root regions

      // [ru] если же детализация отключена, то добавляем только те записи из кучи
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

  // add all known entry points to the parameter containing the directories
  // [ru] все известные точки входа добавляем в параметр с директориями

  for pEntryPoint in FPEImage.EntryPoints do
  begin
    RegionData := GetRegionAtAddr(pEntryPoint);
    EntryPoint.Flag := dfEntryPoint;
    EntryPoint.Caption := 'EntryPoint';
    EntryPoint.Address := NativeInt(pEntryPoint);
    EntryPoint.Size := 0;
    RegionData.Directory.Add(EntryPoint);
  end;

  // add all known thread callbacks to the parameter containing the directories
  // [ru] все известные калбэки нитей добавляем в параметр с директориями

  for pTLSCallback in FPEImage.TLSCallbacks do
  begin
    RegionData := GetRegionAtAddr(pTLSCallback.Address);
    TLSCallback.Flag := dfTlsCallback;
    TLSCallback.Caption := pTLSCallback.Caption;
    TLSCallback.Address := ULONG_PTR(pTLSCallback.Address);
    TLSCallback.Size := 0;
    RegionData.Directory.Add(TLSCallback);
  end;

  // now we add the directories themselves
  // [ru] теперь добавляем сами директории

  for Directory in FPEImage.Directoryes do
  begin
    for I := 0 to 14 do
    begin
      if not CheckAddr(Directory.Data[I].Address) then Continue;
      RegionData := GetRegionAtAddr(Pointer(Directory.Data[I].Address));
      RegionData.Directory.Add(Directory.Data[I]);
    end;
  end;

  // and at the end of the executable file's section
  // [ru] ну и в конце секции исполняемого файла

  for Section in FPEImage.Sections do
  begin

    // first, we add the regions from which the sections we know begin
    // [ru] сначала добавляем регионы с которых начинаются известные нам секции

    MBI := GetPageAtAddr(Pointer(Section.Address));
    Index := GetRegionIndex(MBI.BaseAddress);
    RegionData := GetFriendlyRegion(Index);

    // and then add the section identifier to all subsequent ones
    // according to the section size

    // [ru] а потом добавляем признак секции во все последующие
    // в соответствии с размером секции

    SectionSize := Section.Size;
    repeat
      RegionData.SetSection(Section);
      Dec(SectionSize, RegionData.MBI.RegionSize);
      if SectionSize > 0 then
      begin
        Inc(Index);
        RegionData := GetFriendlyRegion(Index);
      end;
    until SectionSize <= 0;
  end;
end;

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
  if NtQueryInformationProcess(FProcess, ProcessBasicInformation,
    @pProcBasicInfo, SizeOf(PROCESS_BASIC_INFORMATION),
    @ReturnLength) <> STATUS_SUCCESS then
    RaiseLastOSError;

  FPebBaseAddress := pProcBasicInfo.PebBaseAddress;
  AddNewData('Process Environment Block', FPebBaseAddress);

  if not ReadProcessMemory(FProcess, FPebBaseAddress,
    @FPeb, SizeOf(TPEB), ReturnLength) then
    raise EReadRemoteMemoryException.Create('PEB', FPebBaseAddress);

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
      raise EReadRemoteMemoryException.Create('PebWow64', FPebWow64BaseAddress);

    AddNewData('LoaderData (Wow64)', Pointer(FPebWow64.LoaderData));
    AddNewData('ProcessParameters (Wow64)', Pointer(FPebWow64.ProcessParameters));
    if FPebWow64.ReadOnlySharedMemoryBase <> Cardinal(FPeb.ReadOnlySharedMemoryBase) then
      AddNewData('ReadOnlySharedMemoryBase (Wow64)', Pointer(FPebWow64.ReadOnlySharedMemoryBase));
    if FPebWow64.HotpatchInformation <> Cardinal(FPeb.HotpatchInformation) then
      AddNewData('HotpatchInformation (Wow64)', Pointer(FPebWow64.HotpatchInformation));

    PPointerData := nil;
    if ReadProcessMemory(FProcess, Pointer(FPebWow64.ReadOnlyStaticServerData),
      @PPointerData, 4, ReturnLength) then
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
  if ReadProcessMemory(FProcess, FPeb.ReadOnlyStaticServerData,
    @PPointerData, SizeOf(Pointer), ReturnLength) then
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

  if ReadProcessMemory(FProcess, FPeb.ProcessParameters,
    @ProcessParameters, SizeOf(RTL_USER_PROCESS_PARAMETERS), ReturnLength) then
    AddNewData('Process Environments', ProcessParameters.Environment);

  if ProcessParameters.ImagePathName.Length > 0 then
  begin
    SetLength(FProcessPath, ProcessParameters.ImagePathName.Length div SizeOf(Char));
    if not ReadProcessMemory(FProcess, ProcessParameters.ImagePathName.Buffer,
      @FProcessPath[1], ProcessParameters.ImagePathName.Length, ReturnLength) then
      raise EReadRemoteMemoryException.Create('ProcessParameters.ImagePathName',
        ProcessParameters.ImagePathName.Buffer);
  end
  else
    FProcessPath := '';

  GetSystemInfo(SBI);
  AddNewData('KE_USER_SHARED_DATA',
    Pointer(NativeUInt(SBI.lpMaximumApplicationAddress) and $7FFF0000));
end;

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

  // first, information about the stack,
  // the thread procedure address, and the TEB

  // [ru] сначала информацию о стеке, адресе потоковой процедуры и TEB

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

  // then information about the CallStack
  // [ru] потом информацию о CallStack

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

  // and finally, some information about SEH frames
  // [ru] и в завершение информацию о SEH фреймах

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
        if RegionToFilterType(R, Filter) = Filter then
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
        if RegionToFilterType(R, Filter) = Filter then
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
      if RegionToFilterType(R, Filter) = Filter then
        AddToFilter(I, R, True);
    end;
  end;

end;

{ EReadRemoteMemoryException }

constructor EReadRemoteMemoryException.Create(const AMessage: string; AddrVA: Pointer);
begin
  inherited CreateFmt('Error reading "%s" at address 0x%p. Code %d. %s',
    [AMessage, AddrVA, GetLastError, SysErrorMessage(GetLastError)]);
end;

initialization

finalization

  _MemoryMap.Free;

end.
