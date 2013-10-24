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

  TOnGetWow64ThreadsEvent = procedure(Value: TThreads) of object;
  TOnGetWow64HeapsEvent = procedure(Value: THeap) of object;

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
    FGetWow64Threads: TOnGetWow64ThreadsEvent;
    FGetWow64Heaps: TOnGetWow64HeapsEvent;
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
    procedure AddHeapsData; overload;
    procedure AddHeapsData(Value: THeap); overload;
    procedure AddWow64HeapsData;
    procedure AddPEBData;
    procedure AddThreadsData; overload;
    procedure AddThreadsData(Value: TThreads); overload;
    procedure AddWow64ThreadsData;
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
    property ShowEmpty: Boolean read FShowEmpty write SetShowEmpty;
    property SuspendProcessBeforeScan: Boolean read FSuspendProcess write FSuspendProcess;
    property TotalData: TTotalData read FTotalData;
    property OnGetWow64Threads: TOnGetWow64ThreadsEvent
      read FGetWow64Threads write FGetWow64Threads;
    property OnGetWow64Heaps: TOnGetWow64HeapsEvent
      read FGetWow64Heaps write FGetWow64Heaps;
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
var
  MBI: TMemoryBasicInformation;
  dwLength: NativeUInt;
  RegionData, LastRegionData: TFriendlyRegionData;
  OwnerName: array [0..MAX_PATH - 1] of Char;
  Shared: Boolean;
  SharedCount: Byte;
  Module: TModule;
begin
  FRegions.Clear;
  FRegionFilters.Clear;
  FHighAddress := 0;

  // ѕеребираем в цикле все страницы пам€ти от нулевой,
  // до максимально доступной пользователю
  LastRegionData := nil;
  dwLength := SizeOf(TMemoryBasicInformation);
  while VirtualQueryEx(FProcess, Pointer(FHighAddress), MBI, dwLength) <> 0 do
  begin
    RegionData := NewRegionData;
    try
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

    Inc(FHighAddress, RegionData.MBI.RegionSize);
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
          {$IFDEF WIN64}
          AddWow64ThreadsData;
          AddWow64HeapsData;
          {$ENDIF}
          AddThreadsData;
          AddHeapsData;
          AddPEBData;
          AddImagesData;
          SortAllContainsBlocks;
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
begin
  Heap := THeap.Create(FPID, FProcess);
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
begin
  for HeapData in Value.Data do
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
    AddNewData('ReadOnlySharedMemoryBase (Wow64)', Pointer(FPebWow64.ReadOnlySharedMemoryBase));
    AddNewData('HotpatchInformation (Wow64)', Pointer(FPebWow64.HotpatchInformation));

    PPointerData := nil;
    if not ReadProcessMemory(FProcess, Pointer(FPebWow64.ReadOnlyStaticServerData),
      @PPointerData, 4, ReturnLength) then
      RaiseLastOSError;

    AddNewData('ReadOnlyStaticServerData (Wow64)', PPointerData);

    AddNewData('AnsiCodePageData (Wow64)', Pointer(FPebWow64.AnsiCodePageData));
    AddNewData('OemCodePageData (Wow64)', Pointer(FPebWow64.OemCodePageData));
    AddNewData('UnicodeCaseTableData (Wow64)', Pointer(FPebWow64.UnicodeCaseTableData));

    AddNewData('GdiSharedHandleTable (Wow64)', Pointer(FPebWow64.GdiSharedHandleTable));
    AddNewData('ProcessStarterHelper (Wow64)', Pointer(FPebWow64.ProcessStarterHelper));
    AddNewData('PostProcessInitRoutine (Wow64)', Pointer(FPebWow64.PostProcessInitRoutine));
    AddNewData('TlsExpansionBitmap (Wow64)', Pointer(FPebWow64.TlsExpansionBitmap));

    // Compatilibity
    AddNewData('pShimData (Wow64)', Pointer(FPebWow64.pShimData));
    AddNewData('AppCompatInfo (Wow64)', Pointer(FPebWow64.AppCompatInfo));

    AddNewData('ActivationContextData (Wow64)', Pointer(FPebWow64.ActivationContextData));
    AddNewData('ProcessAssemblyStorageMap (Wow64)', Pointer(FPebWow64.ProcessAssemblyStorageMap));
    AddNewData('SystemDefaultActivationContextData (Wow64)', Pointer(FPebWow64.SystemDefaultActivationContextData));
    AddNewData('SystemAssemblyStorageMap (Wow64)', Pointer(FPebWow64.SystemAssemblyStorageMap));
  end;
  {$ENDIF}

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

  // Compatilibity
  AddNewData('pShimData', Pointer(FPeb.pShimData));
  AddNewData('AppCompatInfo', Pointer(FPeb.AppCompatInfo));

  AddNewData('ActivationContextData', Pointer(FPeb.ActivationContextData));
  AddNewData('ProcessAssemblyStorageMap', Pointer(FPeb.ProcessAssemblyStorageMap));
  AddNewData('SystemDefaultActivationContextData', Pointer(FPeb.SystemDefaultActivationContextData));
  AddNewData('SystemAssemblyStorageMap', Pointer(FPeb.SystemAssemblyStorageMap));

  if not ReadProcessMemory(FProcess, FPeb.ProcessParameters,
    @ProcessParameters, SizeOf(RTL_USER_PROCESS_PARAMETERS), ReturnLength) then
    RaiseLastOSError;
  AddNewData('Process Environments', ProcessParameters.Environment);

  GetSystemInfo(SBI);
  AddNewData('KE_USER_SHARED_DATA',
    Pointer(NativeUInt(SBI.lpMaximumApplicationAddress) and $7FFF0000));
end;

procedure TMemoryMap.AddThreadsData(Value: TThreads);
var
  RegionData, ImageRegion: TFriendlyRegionData;
  ThreadData: TThreadData;
  ContainItem: TContainItem;
  ThreadStackEntry: TThreadStackEntry;
  Index: Integer;
  SEHEntry: TSEHEntry;
begin
  for ThreadData in Value.ThreadData do
  begin
    if not CheckAddr(ThreadData.Address) then Continue;

    RegionData := GetRegionAtAddr(ThreadData.Address);

    if ThreadData.Flag = tiThreadProc then
    begin
      ContainItem.ItemType := itThreadData;
      ContainItem.ThreadData := ThreadData;
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

  for ThreadStackEntry in Value.ThreadStackEntries do
  begin
    if not CheckAddr(ThreadStackEntry.Data.AddrFrame.Offset) then Continue;
    RegionData := GetRegionAtAddr(Pointer(ThreadStackEntry.Data.AddrFrame.Offset));
    ContainItem.ItemType := itStackFrame;

    GetRegionIndex(Pointer(ThreadStackEntry.Data.AddrPC.Offset), Index);
    ImageRegion := GetFriendlyRegion(Index);

    if ImageRegion.RegionType <> rtExecutableImage then
    begin
      ImageRegion := TFriendlyRegionData(ImageRegion.Parent);
      if ImageRegion <> nil then
        if ImageRegion.RegionType <> rtExecutableImage then
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

  for SEHEntry in Value.SEHEntries do
  begin
    if not CheckAddr(SEHEntry.Address) then Continue;
    RegionData := GetRegionAtAddr(SEHEntry.Address);
    ContainItem.ItemType := itSEHFrame;

    GetRegionIndex(SEHEntry.Handler, Index);
    ImageRegion := GetFriendlyRegion(Index);

    if ImageRegion.RegionType <> rtExecutableImage then
    begin
      ImageRegion := TFriendlyRegionData(ImageRegion.Parent);
      if ImageRegion <> nil then
        if ImageRegion.RegionType <> rtExecutableImage then
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

procedure TMemoryMap.AddThreadsData;
var
  Threads: TThreads;
begin
  Threads := TThreads.Create(FPID, FProcess);
  try
    AddThreadsData(Threads);
  finally
    Threads.Free;
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

procedure TMemoryMap.AddWow64ThreadsData;
var
  Threads: TThreads;
begin
  if Process64 then Exit;
  if not Assigned(FGetWow64Threads) then Exit;
  Threads := TThreads.Create;
  try
    FGetWow64Threads(Threads);
    AddThreadsData(Threads);
  finally
    Threads.Free;
  end;
end;

initialization

finalization

  _MemoryMap.Free;

end.
