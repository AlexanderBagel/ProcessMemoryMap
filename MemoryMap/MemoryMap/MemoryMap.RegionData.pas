unit MemoryMap.RegionData;

interface

uses
  Winapi.Windows,
  System.Classes,
  System.TypInfo,
  System.SysUtils,
  Generics.Collections,
  MemoryMap.Heaps,
  MemoryMap.Threads,
  MemoryMap.PEImage;

type
  TRegionType = (
    rtDefault,
    rtHeap,
    rtThread,
    rtSystem,
    rtExecutableImage);

  TSystemData = record
    Description: ShortString;
    Address: Pointer;
  end;

  TContainItemType = (itHeapBlock, itThreadProc, itSystem);
  TContainItem = record
    ItemType: TContainItemType;
    function Hash: string;
    case Integer of
      0: (Heap: THeapData);
      1: (ThreadProc: TThreadData);
      2: (System: TSystemData);
  end;

  TRegionData = class
  private
    FParent: TRegionData;
    FRegionType: TRegionType;
    FMBI: TMemoryBasicInformation;
    FDetails: string;
    FRegionVisible: Boolean;
    FHiddenRegionCount: Integer;
    FTotalRegionSize: NativeUInt;
    FHeap: THeapData;
    FThread: TThreadData;
    FPEBData: TSystemData;
    FSection: TSection;
    FContains: TList<TContainItem>;
    FDirectories: TList<TDirectory>;
    FShared: Boolean;
    FSharedCount: Integer;
    FFiltered: Boolean;
  protected
    procedure IncHiddenRegionCount;
    procedure IncTotalRegionSize(Value: NativeUInt);
    procedure IncTotalHeapSize(Value: NativeUInt);
    procedure SetRegionType(Value: TRegionType);
    procedure SetMBI(Value: TMemoryBasicInformation);
    procedure SetMBIRegionSize(Value: SIZE_T);
    procedure SetDetails(Value: string);
    procedure SetRegionVisible(Value: Boolean);
    procedure SetTotalRegionSize(Value: NativeUInt);
    procedure SetParent(Value: TRegionData);
    procedure SetHeap(Value: THeapData);
    procedure SetThread(Value: TThreadData);
    procedure SetThreadIDAndWow(Value: Integer; Wow64: Boolean);
    procedure SetPEBData(Value: TSystemData);
    procedure SetSection(Value: TSection);
    procedure SetShared(const Value: Boolean);
    procedure SetSharedCount(const Value: Integer);
    procedure SetFiltered(Value: Boolean);
  protected
    procedure InitFromString(const Value: string);
    function GetAsString: string;
  public
    constructor Create;
    destructor Destroy; override;
    property RegionType: TRegionType read FRegionType;
    property MBI: TMemoryBasicInformation read FMBI;
    property Details: string read FDetails;
    property RegionVisible: Boolean read FRegionVisible;
    property HiddenRegionCount: Integer read FHiddenRegionCount;
    property TotalRegionSize: NativeUInt read FTotalRegionSize;
    property Parent: TRegionData read FParent;
    property Heap: THeapData read FHeap;
    property Thread: TThreadData read FThread;
    property SystemData: TSystemData read FPEBData;
    property Section: TSection read FSection;
    property Shared: Boolean read FShared;
    property SharedCount: Integer read FSharedCount;
    property Directory: TList<TDirectory> read FDirectories;
    property Contains: TList<TContainItem> read FContains;
    property Filtered: Boolean read FFiltered;
  end;

implementation

{ TContainItem }

function TContainItem.Hash: string;
begin
  Result := IntToStr(Integer(ItemType));
  case ItemType of
    itHeapBlock:
      Result := Result + IntToStr(Heap.ID) + IntToStr(Heap.Entry.Address) +
        IntToStr(Heap.Entry.Size) + IntToStr(Heap.Entry.Flags);
    itThreadProc:
      Result := Result +
        GetEnumName(TypeInfo(TThreadInfo), Integer(ThreadProc.Flag)) +
        IntToStr(ThreadProc.ThreadID) + IntToStr(NativeUInt(ThreadProc.Address));
    itSystem:
      Result := Result + string(System.Description) +
        IntToStr(NativeUInt(System.Address));
  end;
end;

{ TRegionData }

constructor TRegionData.Create;
begin
  FRegionVisible := True;
  FContains := TList<TContainItem>.Create;
  FDirectories := TList<TDirectory>.Create;
  FHeap.ID := $FFFFFFFF;
end;

destructor TRegionData.Destroy;
begin
  FDirectories.Free;
  FContains.Free;
  inherited;
end;

function TRegionData.GetAsString: string;
var
  S: TStringList;
  I: Integer;
  Dir: TDirectory;
  CI: TContainItem;

  procedure AddString(const Value: string);
  begin
    if Value = '' then
      S.Add(' ')
    else
      S.Add(Value);
  end;

  procedure AddHeapData(Value: THeapData);
  begin
    S.Add(IntToStr(Value.ID));
    S.Add(BoolToStr(Value.Wow64));
    S.Add(IntToStr(Value.Entry.Address));
    S.Add(IntToStr(Value.Entry.Size));
    S.Add(IntToStr(Value.Entry.Flags));
  end;

  procedure AddThreadData(Value: TThreadData);
  begin
    S.Add(GetEnumName(TypeInfo(TThreadInfo), Integer(Value.Flag)));
    S.Add(IntToStr(Value.ThreadID));
    S.Add(IntToStr(ULONG_PTR(Value.Address)));
    S.Add(BoolToStr(Value.Wow64));
  end;

  procedure AddPEBData(Value: TSystemData);
  begin
    AddString(string(Value.Description));
    S.Add(IntToStr(ULONG_PTR(Value.Address)));
  end;

begin
  S := TStringList.Create;
  try
    S.Add(GetEnumName(TypeInfo(TRegionType), Integer(RegionType)));
    S.Add(IntToStr(ULONG_PTR(MBI.BaseAddress)));
    S.Add(IntToStr(ULONG_PTR(MBI.AllocationBase)));
    S.Add(IntToStr(MBI.AllocationProtect));
    S.Add(IntToStr(MBI.RegionSize));
    S.Add(IntToStr(MBI.State));
    S.Add(IntToStr(MBI.Protect));
    S.Add(IntToStr(MBI.Type_9));
    AddString(Details);
    S.Add(BoolToStr(RegionVisible));
    S.Add(IntToStr(HiddenRegionCount));
    S.Add(IntToStr(TotalRegionSize));
    AddHeapData(Heap);
    AddThreadData(Thread);
    AddPEBData(SystemData);
    AddString(string(Section.Caption));
    S.Add(IntToStr(Section.Address));
    S.Add(IntToStr(Section.Size));
    try
      S.Add(BoolToStr(Section.IsCode));
    except
      S.Add(BoolToStr(Section.IsCode));
    end;
    S.Add(BoolToStr(Section.IsData));
    S.Add(BoolToStr(Shared));
    S.Add(IntToStr(SharedCount));
    S.Add(IntToStr(Directory.Count));
    for I := 0 to Directory.Count - 1 do
    begin
      Dir := Directory[I];
      AddString(string(Dir.Caption));
      S.Add(IntToStr(Dir.Address));
      S.Add(IntToStr(Dir.Size));
    end;
    S.Add(IntToStr(Contains.Count));
    for I := 0 to Contains.Count - 1 do
    begin
      CI := Contains[I];
      S.Add(GetEnumName(TypeInfo(TContainItemType), Integer(CI.ItemType)));
      case CI.ItemType of
        itHeapBlock: AddHeapData(CI.Heap);
        itThreadProc: AddThreadData(CI.ThreadProc);
        itSystem: AddPEBData(CI.System);
      end;
    end;
    S.Delimiter := #9;
    Result := S.DelimitedText;
  finally
    S.Free;
  end;
end;

procedure TRegionData.IncHiddenRegionCount;
begin
  Inc(FHiddenRegionCount);
end;

procedure TRegionData.IncTotalHeapSize(Value: NativeUInt);
begin
  Inc(FHeap.Entry.Size, Value);
end;

procedure TRegionData.IncTotalRegionSize(Value: NativeUInt);
begin
  Inc(FTotalRegionSize, Value);
end;

procedure TRegionData.InitFromString(const Value: string);
var
  S: TStringList;
  I, Cursor: Integer;
  Dir: TDirectory;
  CI: TContainItem;

  function CheckEnumType(CheckValue: Integer): Integer;
  begin
    if CheckValue >= 0 then
      Result := CheckValue
    else
      raise Exception.Create('Wrong enum type.');
  end;

  function NextValue: string;
  begin
    Result := Trim(S[Cursor]);
    Inc(Cursor);
  end;

  function GetHeapData: THeapData;
  begin
    Result.ID := StrToInt64(NextValue);
    Result.Wow64 := StrToBool(NextValue);
    Result.Entry.Address := StrToInt64(NextValue);
    Result.Entry.Size := StrToInt64(NextValue);
    Result.Entry.Flags := StrToInt64(NextValue);
  end;

  function GetThreadData: TThreadData;
  begin
    Result.Flag := TThreadInfo(CheckEnumType(
      GetEnumValue(TypeInfo(TThreadInfo), NextValue)));
    Result.ThreadID := StrToInt64(NextValue);
    Result.Address := Pointer(StrToInt64(NextValue));
    Result.Wow64 := StrToBool(NextValue);
  end;

  function GetPEBData: TSystemData;
  begin
    Result.Description := ShortString(ShortString(Trim(NextValue)));
    Result.Address := Pointer(StrToInt64(NextValue));
  end;

begin
  S := TStringList.Create;
  try
    S.Delimiter := #9;
    S.DelimitedText := Value;
    Cursor := 0;
    FRegionType := TRegionType(CheckEnumType(
      GetEnumValue(TypeInfo(TRegionType), NextValue)));
    FMBI.BaseAddress := Pointer(StrToInt64(NextValue));
    FMBI.AllocationBase := Pointer(StrToInt64(NextValue));
    FMBI.AllocationProtect := StrToInt64(NextValue);
    FMBI.RegionSize := StrToInt64(NextValue);
    FMBI.State := StrToInt64(NextValue);
    FMBI.Protect := StrToInt64(NextValue);
    FMBI.Type_9 := StrToInt64(NextValue);
    FDetails := NextValue;
    FRegionVisible := StrToBool(NextValue);
    FHiddenRegionCount := StrToInt64(NextValue);
    FTotalRegionSize := StrToInt64(NextValue);
    FHeap := GetHeapData;
    FThread := GetThreadData;
    FPEBData := GetPEBData;
    FSection.Caption := ShortString(ShortString(Trim(NextValue)));
    FSection.Address := StrToInt64(NextValue);
    FSection.Size := StrToInt64(NextValue);
    FSection.IsCode := StrToBool(NextValue);
    FSection.IsData := StrToBool(NextValue);
    FShared := StrToBool(NextValue);
    FSharedCount := StrToInt64(NextValue);
    for I := 0 to StrToInt64(NextValue) - 1 do
    begin
      Dir.Caption := ShortString(ShortString(Trim(NextValue)));
      Dir.Address := StrToInt64(NextValue);
      Dir.Size := StrToInt64(NextValue);
      Directory.Add(Dir);
    end;
    for I := 0 to StrToInt64(NextValue) - 1 do
    begin
      CI.ItemType := TContainItemType(CheckEnumType(
        GetEnumValue(TypeInfo(TContainItemType), NextValue)));
      case CI.ItemType of
        itHeapBlock: CI.Heap := GetHeapData;
        itThreadProc: CI.ThreadProc := GetThreadData;
        itSystem: CI.System := GetPEBData;
      end;
      Contains.Add(CI);
    end;
  finally
    S.Free;
  end;
end;

procedure TRegionData.SetHeap(Value: THeapData);
begin
  FHeap := Value;
end;

procedure TRegionData.SetDetails(Value: string);
begin
  FDetails := Value;
end;

procedure TRegionData.SetFiltered(Value: Boolean);
begin
  FFiltered := Value;
end;

procedure TRegionData.SetMBI(Value: TMemoryBasicInformation);
begin
  FMBI := Value;
  FTotalRegionSize := Value.RegionSize;
end;

procedure TRegionData.SetMBIRegionSize(Value: SIZE_T);
begin
  FMBI.RegionSize := Value;
end;

procedure TRegionData.SetRegionType(Value: TRegionType);
begin
  FRegionType := Value;
end;

procedure TRegionData.SetParent(Value: TRegionData);
begin
  FParent := Value;
end;

procedure TRegionData.SetPEBData(Value: TSystemData);
begin
  FPEBData := Value;
end;

procedure TRegionData.SetRegionVisible(Value: Boolean);
begin
  FRegionVisible := Value;
end;

procedure TRegionData.SetSection(Value: TSection);
begin
  FSection := Value;
end;

procedure TRegionData.SetShared(const Value: Boolean);
begin
  FShared := Value;
end;

procedure TRegionData.SetSharedCount(const Value: Integer);
begin
  FSharedCount := Value;
end;

procedure TRegionData.SetThread(Value: TThreadData);
begin
  FThread := Value;
end;

procedure TRegionData.SetThreadIDAndWow(Value: Integer; Wow64: Boolean);
begin
  FThread.ThreadID := Value;
  FThread.Wow64 := Wow64;
end;

procedure TRegionData.SetTotalRegionSize(Value: NativeUInt);
begin
  FTotalRegionSize := Value;
end;

end.
