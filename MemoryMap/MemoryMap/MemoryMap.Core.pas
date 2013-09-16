unit MemoryMap.Core;

interface

uses
  Winapi.Windows,
  System.Classes,
  System.SysUtils,
  Generics.Collections,
  Winapi.PsAPI,
  MemoryMap.RegionData,
  MemoryMap.Workset,
  MemoryMap.Heaps,
  MemoryMap.Threads,
  MemoryMap.NtDll,
  MemoryMap.PEImage,
  MemoryMap.Symbols;

type
  TFilters = (fiNone, fiImage, fiPrivate, fiShareable, fiMapped,
    fiHeap, fiThread, fiSystem, fiFree);

  TModule = record
    Path: string;
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

  TMemoryMap = class
  private const
    HEADER = 'MemoryMap';
    Version = 1;
  private type
    TFriendlyRegionData = class(TRegionData);
  private
    FProcess: THandle;
    FProcessName: string;
    FPID: Cardinal;
    FHighAddress: NativeUInt;
    FRegions: TObjectList<TRegionData>;
    FRegionFilters: TList<Integer>;
    FWorkset: TWorkset;
    FPEImage: TPEImage;
    FSymbols: TSymbols;
    FModules: TList<TModule>;
    FPeb: TPEB;
    FShowEmpty: Boolean;
    FProcess64: Boolean;
    FTotalData: TTotalData;
    FFilter: TFilters;
    FDetailedHeapData: Boolean;
    FSuspendProcess: Boolean;
    function GetItem(Index: Integer): TRegionData;
    procedure SetShowEmpty(const Value: Boolean);
    procedure SetFilter(const Value: TFilters);
    procedure SetDetailedHeapData(const Value: Boolean);
  protected
    function GetFriendlyRegion(Index: Integer): TFriendlyRegionData;
    function GetPageAtAddr(Address: Pointer): TMemoryBasicInformation;
    function GetRegionAtAddr(Address: Pointer): TFriendlyRegionData;
    function GetRegionIndex(Address: Pointer): Integer; overload;
    function NewRegionData: TFriendlyRegionData;
    function SplitRegionAtAddr(Address: Pointer; Index: Integer): Integer;
  protected
    procedure AddImagesData;
    procedure AddHeapsData;
    procedure AddPEBData;
    procedure AddThreadsData;
    procedure GetAllRegions;
    procedure CalcTotal;
    procedure UpdateRegionFilters;
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
    property PID: Cardinal read FPID;
    property Process64: Boolean read FProcess64;
    property ProcessName: string read FProcessName;
    property ShowEmpty: Boolean read FShowEmpty write SetShowEmpty;
    property SuspendProcessBeforeScan: Boolean read FSuspendProcess write FSuspendProcess;
    property TotalData: TTotalData read FTotalData;
  end;

  function MemoryMapCore: TMemoryMap;
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

function TMemoryMap.Count: Integer;
begin
  Result := FRegionFilters.Count;
end;

constructor TMemoryMap.Create;
begin
  FRegions := TObjectList<TRegionData>.Create(True);
  FRegionFilters := TList<Integer>.Create;
  FModules := TList<TModule>.Create;
end;

destructor TMemoryMap.Destroy;
begin
  FModules.Free;
  FRegionFilters.Free;
  FRegions.Free;
  inherited;
end;

procedure TMemoryMap.GetAllRegions;
const
  MM_USER_PROBE_ADDRESS = $7FFF0000;
var
  pSectionAddr: UInt64;
  MBI: TMemoryBasicInformation;
  RegionData, LastRegionData: TFriendlyRegionData;
  OwnerName: array [0..MAX_PATH - 1] of Char;
  Info: TSystemInfo;
  Shared: Boolean;
  SharedCount: Byte;
  Module: TModule;
begin
  FRegions.Clear;
  FRegionFilters.Clear;
  pSectionAddr := 0;

  // ѕеребираем в цикле все страницы пам€ти от нулевой,
  // до максимально доступной пользователю

  GetSystemInfo(Info);
  FHighAddress := NativeUInt(Info.lpMaximumApplicationAddress);
  {$IFDEF WIN64}
    if not Process64 then
      FHighAddress := MM_USER_PROBE_ADDRESS;
  {$ELSE}
    if Is64OS then
      FHighAddress := MM_USER_PROBE_ADDRESS;
  {$ENDIF}

  LastRegionData := nil;
  while pSectionAddr < FHighAddress do
  begin
    RegionData := NewRegionData;

    try
      MBI := GetPageAtAddr(Pointer(pSectionAddr));

      RegionData.SetMBI(MBI);
      if Workset.GetPageSharedInfo(MBI.BaseAddress, Shared,
        SharedCount) and Shared then
      begin
        RegionData.SetShared(True);
        RegionData.SetSharedCount(SharedCount);
      end;

      if LastRegionData = nil then
        LastRegionData := RegionData
      else
        if MBI.AllocationBase = LastRegionData.MBI.AllocationBase then
        begin
          LastRegionData.IncHiddenRegionCount;
          LastRegionData.IncTotalRegionSize(RegionData.TotalRegionSize);
          RegionData.SetRegionVisible(False);
          RegionData.SetParent(LastRegionData);
        end
        else
          LastRegionData := RegionData;

      if GetMappedFileName(FProcess, MBI.BaseAddress,
        @OwnerName[0], MAX_PATH) > 0 then
      begin
        Module.Path := NormalizePath(string(OwnerName));
        RegionData.SetDetails(Module.Path);
        if CheckPEImage(FProcess, MBI.BaseAddress) then
        begin
          Module.BaseAddr := ULONG_PTR(MBI.BaseAddress);
          FModules.Add(Module);
          RegionData.SetRegionType(rtExecutableImage);
          PEImage.GetInfoFromImage(Module.Path, MBI.BaseAddress, MBI.RegionSize);
        end;
      end;

      FRegions.Add(RegionData);
    except
      RegionData.Free;
      raise;
    end;

    Inc(pSectionAddr, RegionData.MBI.RegionSize);
  end;
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
  dwLength: Cardinal;
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
  Result := False;
  FRegions.Clear;
  FModules.Clear;
  FFilter := fiNone;
  ProcessLock := nil;
  // ќткрываем процесс на чтение
  FProcess := OpenProcess(
    PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
    False, PID);
  if FProcess = 0 then
    RaiseLastOSError;
  try
    FPID := PID;
    FProcessName := ProcessName;

    FProcess64 := False;
    {$IFDEF WIN64}
      if not IsWow64(FProcess) then
        FProcess64 := True;
    {$ELSE}
      if Is64OS and not IsWow64(FProcess) then
        raise Exception.Create('Can''t scan process.');
    {$ENDIF}

    if SuspendProcessBeforeScan then
      ProcessLock := SuspendProcess(PID);
    try
      FSymbols := TSymbols.Create(FProcess);
      try
        FPEImage := TPEImage.Create;
        try
          FWorkset := TWorkset.Create(FProcess);;
          try
            GetAllRegions;
          finally
            FWorkset.Free;
          end;
          AddThreadsData;
          AddHeapsData;
          AddPEBData;
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
      if Region.RegionType = rtExecutableImage then
      begin
        Module.Path := Region.Details;
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
    rtExecutableImage: Exit(fiImage);
  end;
  if not Value.RegionVisible then
  begin
    AResult := RegionToFilterType(Value.Parent);
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

function TMemoryMap.SplitRegionAtAddr(Address: Pointer;
  Index: Integer): Integer;
var
  OriginalRegion, NextRegion, NewRegion: TFriendlyRegionData;
  MBI: TMemoryBasicInformation;
begin
  NewRegion := NewRegionData;
  try
    NewRegion.SetRegionVisible(False);
    MBI := GetPageAtAddr(Address);

    // ѕравим размер предыдущего региона
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

function TMemoryMap.TotalCount: Integer;
begin
  Result := FRegions.Count;
end;

procedure TMemoryMap.AddHeapsData;
var
  Heap: THeap;
  RegionData: TFriendlyRegionData;
  ContainItem: TContainItem;
  HeapData: THeapData;
  Index: Integer;
begin
  Heap := THeap.Create(FPID, FProcess);
  try
    for HeapData in Heap.Data do
    begin
      if DetailedHeapData then
        RegionData := GetRegionAtAddr(Pointer(HeapData.Entry.Address))
      else
      begin
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
  finally
    Heap.Free;
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
  EntryPoint: TDirectory;
begin
  for pEntryPoint in FPEImage.EntryPoints do
  begin
    RegionData := GetRegionAtAddr(pEntryPoint);
    EntryPoint.Caption := 'EntryPoint';
    EntryPoint.Address := NativeInt(pEntryPoint);
    EntryPoint.Size := 0;
    RegionData.Directory.Add(EntryPoint);
  end;
  for Directory in FPEImage.Directoryes do
  begin
    for I := 0 to 14 do
    begin
      if not CheckAddr(Directory.Data[I].Address) then Continue;
      RegionData := GetRegionAtAddr(Pointer(Directory.Data[I].Address));
      RegionData.Directory.Add(Directory.Data[I]);
    end;
  end;
  for Section in FPEImage.Sections do
  begin
    // сначала добавл€ем регионы с которых начинаютс€ инвестные нам секции
    MBI := GetPageAtAddr(Pointer(Section.Address));
    Index := GetRegionIndex(MBI.BaseAddress);
    RegionData := GetFriendlyRegion(Index);
    // а потом добавл€ем признак секции во все последующие
    // в соответствии с размером секции
    SectionSize := Section.Size;
    repeat
      RegionData.SetSection(Section);
      Dec(SectionSize, RegionData.MBI.RegionSize);
      Inc(Index);
      RegionData := GetFriendlyRegion(Index);
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
      ContainItem.System := SystemData;
      RegionData.Contains.Add(ContainItem);
    end;
    if RegionData.RegionType = rtDefault then
      RegionData.SetRegionType(rtSystem);
  end;

var
  pProcBasicInfo: PROCESS_BASIC_INFORMATION;
  ReturnLength: NativeUInt;
  ProcessParameters: RTL_USER_PROCESS_PARAMETERS;
  SBI: TSystemInfo;
begin
  ReturnLength := 0;
  if NtQueryInformationProcess(FProcess, 0,
    @pProcBasicInfo, SizeOf(PROCESS_BASIC_INFORMATION),
    @ReturnLength) <> STATUS_SUCCESS then
    RaiseLastOSError;
  AddNewData('Process Environment Block', pProcBasicInfo.PebBaseAddress);

  if not ReadProcessMemory(FProcess, pProcBasicInfo.PebBaseAddress,
    @FPeb, SizeOf(TPEB), ReturnLength) then
    RaiseLastOSError;
  AddNewData('Process Parameters', FPeb.ProcessParameters);
  AddNewData('LoaderData', FPeb.ProcessParameters);
  AddNewData('SubSystemData', FPeb.SubSystemData);
  AddNewData('KernelCallbackTable', FPeb.KernelCallbackTable);
  AddNewData('ReadOnlySharedMemoryBase', FPeb.ReadOnlySharedMemoryBase);
  AddNewData('ReadOnlySharedMemoryHeap', FPeb.ReadOnlySharedMemoryHeap);
  AddNewData('ReadOnlyStaticServerData', FPeb.ReadOnlyStaticServerData);
  AddNewData('AnsiCodePageData', FPeb.InitAnsiCodePageData);
  AddNewData('OemCodePageData', FPeb.InitOemCodePageData);
  AddNewData('UnicodeCaseTableData', FPeb.InitUnicodeCaseTableData);
  AddNewData('GdiSharedHandleTable', FPeb.GdiSharedHandleTable);
  if not ReadProcessMemory(FProcess, FPeb.ProcessParameters,
    @ProcessParameters, SizeOf(RTL_USER_PROCESS_PARAMETERS), ReturnLength) then
    RaiseLastOSError;
  AddNewData('Process Environments', ProcessParameters.Environment);
  GetSystemInfo(SBI);
  AddNewData('KE_USER_SHARED_DATA',
    Pointer(NativeUInt(SBI.lpMaximumApplicationAddress) and $7FFF0000));
end;

procedure TMemoryMap.UpdateRegionFilters;
var
  I, A: Integer;
  R: TRegionData;
begin
  FRegionFilters.Clear;
  case Filter of
    fiNone:
    begin
      for I := 0 to FRegions.Count - 1 do
      begin
        R := FRegions[I];
        if not R.RegionVisible then Continue;
        if ShowEmpty then
          FRegionFilters.Add(I)
        else
          if (R.MBI.State <> MEM_FREE) or (R.RegionType <> rtDefault) then
            FRegionFilters.Add(I);
      end;
    end;
    fiThread:
    begin
      for I := 0 to FRegions.Count - 1 do
      begin
        R := FRegions[I];
        if RegionToFilterType(R) = Filter then
        begin
          if not R.RegionVisible then Continue;
          FRegionFilters.Add(I);
        end
        else
          for A := 0 to R.Contains.Count - 1 do
            if R.Contains[A].ItemType = itThreadProc then
            begin
              FRegionFilters.Add(I);
              Break;
            end;
      end;
    end;
    fiSystem:
    begin
      for I := 0 to FRegions.Count - 1 do
      begin
        R := FRegions[I];
        if RegionToFilterType(R) = Filter then
        begin
          if not R.RegionVisible then Continue;
          FRegionFilters.Add(I);
        end
        else
          for A := 0 to R.Contains.Count - 1 do
            if R.Contains[A].ItemType = itSystem then
            begin
              FRegionFilters.Add(I);
              Break;
            end;
      end;
    end;
  else
    for I := 0 to FRegions.Count - 1 do
    begin
      R := FRegions[I];
      if not R.RegionVisible then Continue;
      if RegionToFilterType(R) = Filter then
        FRegionFilters.Add(I);
    end;
  end;

end;

procedure TMemoryMap.AddThreadsData;
var
  Threads: TThreads;
  RegionData, ImageRegion: TFriendlyRegionData;
  ThreadData: TThreadData;
  ContainItem: TContainItem;
begin
  Threads := TThreads.Create(FPID, FProcess);
  try
    for ThreadData in Threads.ThreadData do
    begin
      if not CheckAddr(ThreadData.Address) then Continue;

      RegionData := GetRegionAtAddr(ThreadData.Address);

      if ThreadData.Flag = tiThreadProc then
      begin
        ContainItem.ItemType := itThreadProc;
        ContainItem.ThreadProc := ThreadData;
        RegionData.Contains.Add(ContainItem);

        ImageRegion := RegionData;
        if ImageRegion.RegionType <> rtExecutableImage then
        begin
          ImageRegion := TFriendlyRegionData(RegionData.Parent);
          if ImageRegion <> nil then
            if ImageRegion.RegionType <> rtExecutableImage then
              ImageRegion := nil;
        end;

        if ImageRegion <> nil then
          RegionData.SetDetails(FSymbols.GetDescriptionAtAddr(
            ULONG_PTR(ThreadData.Address),
            ULONG_PTR(ImageRegion.MBI.BaseAddress),
            ImageRegion.Details));

        Continue;
      end;

      RegionData.SetRegionType(rtThread);
      RegionData.SetThread(ThreadData);
      if ThreadData.Flag = tiThreadProc then Continue;
      if not RegionData.RegionVisible then
      begin
        TFriendlyRegionData(RegionData.Parent).SetRegionType(rtThread);
        if TFriendlyRegionData(RegionData.Parent).Thread.ThreadID = 0 then
          TFriendlyRegionData(RegionData.Parent).SetThreadID(ThreadData.ThreadID);
      end;
    end;
  finally
    Threads.Free;
  end;
end;

initialization

finalization

  _MemoryMap.Free;

end.
