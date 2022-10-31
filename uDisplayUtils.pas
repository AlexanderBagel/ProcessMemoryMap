////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uDisplayUtils.pas
//  * Purpose   : Вспомогательный модуль для отображения полученой информации
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

unit uDisplayUtils;

interface

uses
  Winapi.Windows,
  Winapi.TlHelp32,
  System.SysUtils,
  uUtils,
  uSettings,

  MemoryMap.Core,
  MemoryMap.RegionData,
  MemoryMap.Heaps,
  MemoryMap.Threads,
  MemoryMap.PEImage,
  MemoryMap.Utils;

type
  PNodeData = ^TNodeData;
  TNodeData = record
    Node: Pointer;
    Region: TRegionData;
    Address: NativeUInt;
    Size: NativeUInt;
    RegionType,
    Section,
    Contains,
    Access,
    InitialAccess,
    Details,
    SearchAddress,
    SearchDetails: string;
    Color: TColorRef;
  end;

  function AddDataToLevel1Node(ARegion: TRegionData;
    Node: PNodeData): TColorRef;
  function GetRegionColor(Value: TRegionData;
    FirstLevel: Boolean): TColorRef;
  procedure AddDataToLevel2Node(ARegion: TRegionData; Node:
    PNodeData; AColor: TColorRef; PEImage: Boolean);
  procedure AddDataToDirectoryesNode(ARegion: TRegionData;
    Node: PNodeData; Item: TDirectory);
  procedure AddDataToContainsNode(ARegion: TRegionData;
    Node: PNodeData; Item: TContainItem);
  function ExtractAccessString(const Value: DWORD): string;
  function ExtractInitialAccessString(const Value: DWORD): string;
  function ExtractRegionTypeString(Value: TRegionData): string; overload;
  function ExtractRegionTypeString(
    Value: TMemoryBasicInformation): string; overload;
  function GetLevel1RegionTypeString(ARegion: TRegionData): string;
  function GetLevel2RegionTypeString(ARegion: TRegionData): string;
  function ExtractHeapEntryString(Value: DWORD): string;

implementation

const
  NodeOffset = '      ';
  Wow64 = ' (Wow64)';

function ExtractInitialAccessString(const Value: DWORD): string;
begin
  Result := '';
  if (Value and PAGE_EXECUTE) = PAGE_EXECUTE then Result := 'E';
  if (Value and PAGE_EXECUTE_READ) = PAGE_EXECUTE_READ then Result := 'RE';
  if (Value and PAGE_EXECUTE_READWRITE) = PAGE_EXECUTE_READWRITE then
     Result := 'RWE';
  if (Value and PAGE_EXECUTE_WRITECOPY) = PAGE_EXECUTE_WRITECOPY then
    Result := 'RE, Write copy';
  if (Value and PAGE_NOACCESS) = PAGE_NOACCESS then Result := 'No access';
  if (Value and PAGE_READONLY) = PAGE_READONLY then Result := 'R';
  if (Value and PAGE_READWRITE) = PAGE_READWRITE then Result := 'RW';
  if (Value and PAGE_WRITECOPY) = PAGE_WRITECOPY then Result := 'Write copy';
end;

function ExtractAccessString(const Value: DWORD): string;
const
  PAGE_WRITECOMBINE = $400;
begin
  Result := ExtractInitialAccessString(Value);
  if (Value and PAGE_GUARD) = PAGE_GUARD then
    Result := Result + ', Guarded';
  if (Value and PAGE_NOCACHE) = PAGE_NOCACHE then
    Result := Result + ', No cache';
  if (Value and PAGE_WRITECOMBINE) = PAGE_WRITECOMBINE then
    Result := Result + ', Write Combine';
end;

function ExtractRegionTypeString(Value: TMemoryBasicInformation): string; overload;
begin
  Result := '';
  case Value.State of
    MEM_FREE: Result := 'Free';
    MEM_RESERVE: Result := 'Reserved';
    MEM_COMMIT:
    case Value.Type_9 of
      MEM_IMAGE: Result := 'Image';
      MEM_MAPPED: Result := 'Mapped';
      MEM_PRIVATE: Result := 'Private';
    end;
  end;
end;

function ExtractRegionTypeString(Value: TRegionData): string; overload;
begin
  Result := ExtractRegionTypeString(Value.MBI);
  if Value.Shared then
    Result := Format('Shared %s (count: %d)', [Result, Value.SharedCount]);
end;

function ExtractThreadDataString(RootNode: Boolean; Value: TRegionData): string;
begin
  if RootNode and (Value.HiddenRegionCount > 0) then
  begin
    if Value.Thread.Flag in [tiStackBase, tiStackLimit] then
      Result := 'Thread Stack'
    else
      Result := 'Thread Data';
  end
  else
    case Value.Thread.Flag of
      tiExceptionList: Result := 'Thread Exception List';
      tiStackBase: Result := 'Thread Stack Base';
      tiStackLimit: Result := 'Thread Stack Limit';
      tiTEB: Result := 'Thread Environment Block';
      tiThreadProc: Result := 'ThreadProc(' +
        UInt64ToStr(NativeUInt(Value.Thread.Address)) + ')';
    end;
  if Value.Thread.Flag <> tiThreadProc then
    if Value.Thread.Wow64 then
      Result := Result + Wow64;
end;

function ExtractHeapEntryString(Value: DWORD): string;
begin
  Result := 'Heap entry';
  if Value and LF32_FIXED <> 0 then
    Result := Result + ', fixed';
  if Value and LF32_FREE <> 0 then
    Result := Result + ', free';
  if Value and LF32_MOVEABLE <> 0 then
    Result := Result + ', moveable';
end;

function GetRegionColor(Value: TRegionData;
  FirstLevel: Boolean): TColorRef;
begin
  Result := $FFFFFF;
  if not Settings.ShowColors then Exit;
  case Value.RegionType of
    rtSystem: Result := Settings.SystemColor;
    rtHeap: Result := Settings.HeapColor;
    rtThread: Result := Settings.ThreadColor;
    rtExecutableImage, rtExecutableImage64: Result := Settings.ImageColor;
  else
    if Value.MBI.State = MEM_COMMIT then
      case Value.MBI.Type_9 of
        MEM_IMAGE: Result := Settings.ImagePartColor;
        MEM_MAPPED:
          if Value.Shared then
            Result := Settings.SharedColor
          else
            Result := Settings.MappedColor;
        MEM_PRIVATE: Result := Settings.PrivateColor;
      end;
  end;
end;

function ExtractHeapIDString(Value: THeapData): string;
begin
  if Value.ID = 0 then
    Result := 'Heap ID: 0 (default)'
  else
    Result := 'Heap ID: ' + IntToStr(Value.ID);
end;

function GetLevel1RegionTypeString(ARegion: TRegionData): string;
const
  DefImageName = 'PE Image';
begin
  Result := '';
  case ARegion.RegionType of
    rtHeap:
    begin
      Result := 'Heap';
      if ARegion.Heap.Wow64 then
        Result := Result + Wow64;
    end;
    rtThread: Result := ExtractThreadDataString(True, ARegion);
    rtSystem:
    begin
      Result := 'System';
      if ARegion.HiddenRegionCount = 0 then
        Result := Result + ', ' + string(ARegion.SystemData.Description);
    end;
    rtExecutableImage:
      if MemoryMapCore.Process64 then
        Result := DefImageName + ' (x86)'
      else
        Result := DefImageName;
    rtExecutableImage64:
      if MemoryMapCore.Process64 then
        Result := DefImageName
      else
        Result := DefImageName + ' (x64)';
  end;
  ConcatenateStrings(Result, ExtractRegionTypeString(ARegion));
end;

function GetLevel1DetailString(ARegion: TRegionData): string;
begin
  case ARegion.RegionType of
    rtHeap: Result := ExtractHeapIDString(ARegion.Heap);
    rtThread:
      Result := 'Thread ID: ' + IntToStr(ARegion.Thread.ThreadID);
  else
    Result := ARegion.Details;
  end;
end;

function AddDataToLevel1Node(ARegion: TRegionData; Node: PNodeData): TColorRef;
begin
  Node^.Region := ARegion;
  Node^.Address := NativeUInt(ARegion.MBI.BaseAddress);
  Node^.Size := ARegion.TotalRegionSize;
  Node^.RegionType := GetLevel1RegionTypeString(ARegion);
  Node^.Access := ExtractAccessString(ARegion.MBI.Protect);
  Node^.InitialAccess := ExtractInitialAccessString(ARegion.MBI.AllocationProtect);
  Node^.Details := GetLevel1DetailString(ARegion);
  Node^.SearchAddress := UInt64ToStr(Node^.Address);
  Node^.SearchDetails := AnsiUpperCase(Node^.Details);
  Result := GetRegionColor(ARegion, True);
  Node^.Color := Result;
end;

function GetLevel2Address(ARegion: TRegionData): NativeUInt;
begin
  if ARegion.RegionType = rtHeap then
    Result := ARegion.Heap.Entry.Address
  else
    Result := NativeUInt(ARegion.MBI.BaseAddress);
end;

function GetLevel2Size(ARegion: TRegionData): NativeUInt;
begin
  if ARegion.RegionType = rtHeap then
    Result := ARegion.Heap.Entry.Size
  else
    Result := ARegion.MBI.RegionSize;
end;

function GetLevel2RegionTypeString(ARegion: TRegionData): string;
begin
  Result := '';
  case ARegion.RegionType of
    rtHeap: Exit(NodeOffset + ExtractHeapEntryString(ARegion.Heap.Entry.Flags));
    rtThread:
      if ARegion.Thread.Flag <> tiNoData then
        Result := ExtractThreadDataString(False, ARegion);
    rtSystem:
    begin
      Result := 'System';
      if ARegion.Contains.Count = 0 then
        Result := Result + ', ' + string(ARegion.SystemData.Description);
    end;
  end;
  Result := NodeOffset + Result;
  ConcatenateStrings(Result, ExtractRegionTypeString(ARegion));
end;

function GetLevel2DetailString(ARegion: TRegionData; PEImage: Boolean): string;
begin
  case ARegion.RegionType of
    rtHeap: Result := ExtractHeapIDString(ARegion.Heap);
    rtThread:
      Result := 'Thread ID: ' + IntToStr(ARegion.Thread.ThreadID);
  else
    if not PEImage then
      Result := ARegion.Details;
  end;
end;

function GetRegionDirectoryes(ARegion: TRegionData): string;
var
  I: Integer;
begin
  Result := '';
  if ARegion.Section.IsCode then
    Result := 'code';
  if ARegion.Section.IsData then
    ConcatenateStrings(Result, 'data');
  for I := 0 to ARegion.Directory.Count - 1 do
  begin
    if not CheckAddr(ARegion.Directory[I].Address) then Continue;
    ConcatenateStrings(Result, string(ARegion.Directory[I].Caption));
  end;
end;

function GetLevel2NodeColor(ARegion: TRegionData; AColor: TColorRef): TColorRef;
begin
  if not Settings.ShowColors then Exit($FFFFFF);
  if AColor = 0 then
    AColor := GetRegionColor(ARegion, False);
  Result := AColor;
end;

procedure AddDataToLevel2Node(ARegion: TRegionData; Node: PNodeData;
  AColor: TColorRef; PEImage: Boolean);
begin
  Node^.Region := ARegion;
  Node^.Address := GetLevel2Address(ARegion);
  Node^.Size := GetLevel2Size(ARegion);
  Node^.RegionType := GetLevel2RegionTypeString(ARegion);
  Node^.Access := ExtractAccessString(ARegion.MBI.Protect);
  Node^.InitialAccess := ExtractInitialAccessString(ARegion.MBI.AllocationProtect);
  Node^.Details := GetLevel2DetailString(ARegion, PEImage);
  Node^.Section := string(ARegion.Section.Caption);
  Node^.Contains := GetRegionDirectoryes(ARegion);
  Node^.Color := GetLevel2NodeColor(ARegion, AColor);
  Node^.SearchAddress := UInt64ToStr(Node^.Address);
  Node^.SearchDetails := AnsiUpperCase(Node^.Details);
end;

procedure AddDataToDirectoryesNode(ARegion: TRegionData;
  Node: PNodeData; Item: TDirectory);
begin
  Node^.Region := ARegion;
  Node^.Address := Item.Address;
  Node^.Size := Item.Size;
  Node^.Contains := string(Item.Caption);
  Node^.Section := string(ARegion.Section.Caption);
  if Settings.ShowColors then
    Node^.Color := Settings.ImagePartColor
  else
    Node^.Color := $FFFFFF;
  Node^.SearchAddress := UInt64ToStr(Node^.Address);
end;

procedure AddDataToContainsNode(ARegion: TRegionData;
  Node: PNodeData; Item: TContainItem);
begin
  Node^.Region := ARegion;
  Node^.Color := $FFFFFF;
  case Item.ItemType of
    itThreadData:
    begin
      Node^.Address := NativeUInt(Item.ThreadData.Address);
      if Item.ThreadData.Flag = tiThreadProc then
        Node^.RegionType := NodeOffset + 'ThreadProc, Thread ID: ' +
          IntToStr(Item.ThreadData.ThreadID)
      else
        Node^.RegionType := NodeOffset + ThreadInfoStr[Item.ThreadData.Flag];
      Node^.Details := ARegion.Details;
      if Settings.ShowColors then
        Node^.Color := Settings.ThreadColor;
      if Item.ThreadData.Flag = tiOleTlsData then
        Node^.Contains := 'Structure holding per thread state needed by OLE32';
    end;
    itStackFrame:
    begin
      Node^.Address := Item.StackFrame.Data.AddrFrame.Offset;
      if Item.StackFrame.Data.AddrReturn.Offset <= 0 then
        Node^.RegionType := NodeOffset + 'Primary Stack Frame'
      else
        Node^.RegionType := NodeOffset + 'Stack Frame, ret addr: ' +
          UInt64ToStr(Item.StackFrame.Data.AddrReturn.Offset);
      Node^.Details := string(Item.StackFrame.FuncName);
      if Settings.ShowColors then
        Node^.Color := Settings.ThreadColor;
    end;
    itSEHFrame:
    begin
      Node^.Address := NativeUInt(Item.SEH.Address);
      if Integer(Item.SEH.Previous) <= 0 then
        Node^.RegionType := NodeOffset + 'Primary SEH Frame, handler addr: ' +
          UInt64ToStr(Item.SEH.Handler)
      else
        Node^.RegionType := NodeOffset + 'SEH Frame, handler addr: ' +
          UInt64ToStr(Item.SEH.Handler);
      Node^.Details := string(Item.SEH.HandlerName);
      if Settings.ShowColors then
        Node^.Color := Settings.ThreadColor;
    end;
    itHeapBlock:
    begin
      Node^.Address := Item.Heap.Entry.Address;
      Node^.Size := Item.Heap.Entry.Size;
      Node^.RegionType := NodeOffset + ExtractHeapEntryString(
        Item.Heap.Entry.Flags);
      Node^.Details := ExtractHeapIDString(Item.Heap);
      if Settings.ShowColors then
        Node^.Color := Settings.HeapColor;
    end;
    itSystem:
    begin
      Node^.Address := NativeUInt(Item.System.Address);
      Node^.Contains := string(Item.System.Description);
      if Settings.ShowColors then
        Node^.Color := Settings.SystemColor;
    end;
  end;
  Node^.SearchAddress := UInt64ToStr(Node^.Address);
  Node^.SearchDetails := AnsiUpperCase(Node^.Details);
end;

end.
