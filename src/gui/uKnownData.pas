////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uKnownData.pas
//  * Purpose   : Диалог для отображения списка всех известных структур
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.4.33
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uKnownData;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.ComCtrls, Generics.Collections, ClipBrd, System.ImageList,
  Vcl.ImgList, Vcl.Menus,

  VirtualTrees,
  VirtualTrees.Types,

  MemoryMap.Core,
  MemoryMap.RegionData,
  MemoryMap.Threads,
  MemoryMap.PEImage,

  uRegionProperties,
  uBaseForm, VirtualTrees.BaseAncestorVCL, VirtualTrees.BaseTree,
  VirtualTrees.AncestorVCL;

type
  TdlgKnownData = class(TBaseAppForm)
    il16: TImageList;
    tvData: TVirtualStringTree;
    pmCopy: TPopupMenu;
    mnuGotoAddress: TMenuItem;
    mnuSeparator1: TMenuItem;
    mnuCopyAddress: TMenuItem;
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure tvDataDblClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure tvDataGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
    procedure tvDataGetImageIndex(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Kind: TVTImageKind; Column: TColumnIndex; var Ghosted: Boolean;
      var ImageIndex: TImageIndex);
    procedure FormShow(Sender: TObject);
    procedure FormKeyPress(Sender: TObject; var Key: Char);
    procedure mnuGotoAddressClick(Sender: TObject);
    procedure pmCopyPopup(Sender: TObject);
    procedure mnuCopyAddressClick(Sender: TObject);
  private type
    PNodeData = ^TNodeData;
    TNodeData = record
      Address: Pointer;
      Caption: string;
      ImageIndex, OverlayIndex: Integer;
      IsCode, IsEntryPoint, IsTlsCallBack: Boolean;
      class function Default: TNodeData; static;
    end;
  private
    FThreadsNode: PVirtualNode;
    FImagesNode: PVirtualNode;
    FSystemNode: PVirtualNode;
    FNodeDataList: TList<TNodeData>;
    function GetImagesNode: PVirtualNode;
    function GetThreadNode: PVirtualNode;
    function GetSystemNode: PVirtualNode;
    function GetSelectedNodeIndex: Integer;
    function GetNodeByData(Root: PVirtualNode;
      const Data: TNodeData): PVirtualNode; overload;
    function GetNodeByCaption(Root: PVirtualNode;
      const Caption: string): PVirtualNode;
    function Add(Root: PVirtualNode; const Data: TNodeData): PVirtualNode;
  public
    procedure ShowKnownData;
  end;

var
  dlgKnownData: TdlgKnownData;

implementation

const
  Overlay32 = 0;
  Overlay64 = 1;

{$R *.dfm}

{ TdlgKnownData }

function TdlgKnownData.Add(Root: PVirtualNode;
  const Data: TNodeData): PVirtualNode;
begin
  Result := tvData.AddChild(Root, nil);
  PInteger(Result.GetData)^ := FNodeDataList.Add(Data);
end;

procedure TdlgKnownData.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  Action := caFree;
  dlgKnownData := nil;
end;

procedure TdlgKnownData.FormCreate(Sender: TObject);
begin
  FNodeDataList := TList<TNodeData>.Create;
  tvData.NodeDataSize := 4;
  il16.Overlay(8, Overlay32);
  il16.Overlay(9, Overlay64);
end;

procedure TdlgKnownData.FormDestroy(Sender: TObject);
begin
  FNodeDataList.Free;
end;

procedure TdlgKnownData.FormKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #27 then Close;
end;

procedure TdlgKnownData.FormShow(Sender: TObject);

  procedure ProcessThreadData(Value: TThreadData);
  var
    ThreadNode: PVirtualNode;
    Data: TNodeData;
  begin
    ThreadNode := GetNodeByCaption(GetThreadNode, IntToHex(Value.ThreadID));
    Data := TNodeData.Default;
    Data.Address := Value.Address;
    Data.IsCode := False;
    Data.ImageIndex := 6;
    case Value.Flag of
      tiExceptionList:
        Data.Caption := 'Exception';
      tiTEB:
        if Value.Wow64 then
          Data.Caption := 'Teb Wow'
        else
        begin
          Data.Caption := 'Teb';
          if not MemoryMapCore.Process64 then
            Data.OverlayIndex := Overlay64;
        end;
      tiThreadProc:
      begin
        Data.Caption := 'ThreadProc';
        Data.IsCode := True;
        Data.ImageIndex := 7;
      end;
      tiOleTlsData:
      begin
        if Value.Wow64 then
          Data.Caption := 'OleTlsData Wow'
        else
        begin
          Data.Caption := 'OleTlsData';
          if not MemoryMapCore.Process64 then
            Data.OverlayIndex := Overlay64;
        end;
      end
    else
      Exit;
    end;
    Data.Caption := Format('%s   -> [0x%s]',
      [Data.Caption, IntToHex(ULONG64(Data.Address), 1)]);
    Add(ThreadNode, Data);
  end;

  procedure UpdateImageRoot(Node: PVirtualNode);
  begin
    with FNodeDataList.List[PInteger(Node.GetData)^] do
    begin
      ImageIndex := 2;
      if IsEntryPoint then
        Inc(ImageIndex);
      if IsTlsCallBack then
        Inc(ImageIndex);
    end;
  end;

  procedure ProcessSystemData(Value: TSystemData);
  var
    Data: TNodeData;
  begin
    Data := TNodeData.Default;
    Data.Address := Value.Address;
    Data.Caption := Format('%s   -> [0x%s]',
      [string(Value.Description), IntToHex(ULONG64(Data.Address), 1)]);
    Data.ImageIndex := 6;
    GetNodeByData(GetSystemNode, Data);
  end;

var
  Region: TRegionData;
  Node: PVirtualNode;
  EntryPoint: TDirectory;
  Data: TNodeData;
  Is64Process: Boolean;
begin
  Is64Process := MemoryMapCore.Process64;
  tvData.BeginUpdate;
  try
    for var I := 0 to MemoryMapCore.TotalCount - 1 do
    begin

      Region := MemoryMapCore.GetRegionAtUnfilteredIndex(I);

      case Region.RegionType of
        rtThread:
          if Region.Thread.Flag <> tiNoData then
            ProcessThreadData(Region.Thread);

        rtExecutableImage, rtExecutableImage64:
        begin
          // заполняем рут
          Finalize(Data);
          Data := TNodeData.Default;
          Data.Caption := Region.Details;
          if (Region.RegionType = rtExecutableImage) and Is64Process then
            Data.OverlayIndex := Overlay32;
          if (Region.RegionType = rtExecutableImage64) and not Is64Process then
            Data.OverlayIndex := Overlay64;
          Node := GetNodeByData(GetImagesNode, Data);
          UpdateImageRoot(Node);

          Finalize(Data);
          Data := TNodeData.Default;
          Data.Address := Region.MBI.AllocationBase;
          Data.Caption := Format('PE_Header   -> [0x%s]',
            [IntToHex(ULONG64(Data.Address), 1)]);
          Data.IsCode := False;
          Data.ImageIndex := 6;
          Add(Node, Data);
        end;
        rtSystem:
          if Region.SystemData.Address <> nil then
            ProcessSystemData(Region.SystemData);
      end;

      // так и как дополнительные данные
      for var Contains in Region.Contains do
      begin
        if Contains.ItemType = itThreadData then
          ProcessThreadData(Contains.ThreadData);
        if Contains.ItemType = itSystem then
          ProcessSystemData(Contains.System);
      end;

      for EntryPoint in Region.Directory do
        if EntryPoint.Flag <> dfDirectory then
        begin
          if Region.Parent = nil then
            Node := GetNodeByCaption(GetImagesNode, 'Invalid Data!!!')
          else
            Node := GetNodeByCaption(GetImagesNode, Region.Parent.Details);

          with FNodeDataList.List[PInteger(Node.GetData)^] do
          begin
            if EntryPoint.Flag = dfEntryPoint then
              IsEntryPoint := True;
            if EntryPoint.Flag = dfTlsCallback then
              IsTlsCallBack := True;
          end;
          UpdateImageRoot(Node);

          Finalize(Data);
          Data := TNodeData.Default;
          Data.Address := Pointer(EntryPoint.Address);
          Data.Caption := Format('%s   -> [0x%s]',
            [string(EntryPoint.Caption), IntToHex(EntryPoint.Address, 1)]);
          Data.ImageIndex := 7;
          Data.IsCode := True;
          Add(Node, Data);
        end;
    end;
  finally
    tvData.EndUpdate;
  end;
end;

function TdlgKnownData.GetImagesNode: PVirtualNode;
var
  Data: TNodeData;
begin
  if FImagesNode = nil then
  begin
    Data := TNodeData.Default;
    Data.Caption := 'Images';
    Data.ImageIndex := 1;
    FImagesNode := Add(nil, Data);
  end;
  Result := FImagesNode;
  tvData.Expanded[FImagesNode] := True;
end;

function TdlgKnownData.GetNodeByCaption(Root: PVirtualNode;
  const Caption: string): PVirtualNode;
var
  Data: TNodeData;
begin
  Data := TNodeData.Default;
  Data.Caption := Caption;
  Result := GetNodeByData(Root, Data);
end;

function TdlgKnownData.GetNodeByData(Root: PVirtualNode;
  const Data: TNodeData): PVirtualNode;
var
  Tmp: PVirtualNode;
begin
  Tmp := tvData.GetNext(Root, True);
  while Assigned(Tmp) do
  begin
    if Data.Caption = FNodeDataList.List[PInteger(Tmp.GetData)^].Caption then
      Exit(Tmp);
    Tmp := tvData.GetNext(Tmp, True);
  end;
  Result := Add(Root, Data);
end;

function TdlgKnownData.GetSelectedNodeIndex: Integer;
var
  E: TVTVirtualNodeEnumerator;
begin
  Result := -1;
  E := tvData.SelectedNodes.GetEnumerator;
  if E.MoveNext then
    Result := PInteger(tvData.GetNodeData(E.Current))^;
end;

function TdlgKnownData.GetSystemNode: PVirtualNode;
var
  Data: TNodeData;
begin
  if FSystemNode = nil then
  begin
    Data := TNodeData.Default;
    Data.Caption := 'System';
    Data.ImageIndex := 5;
    FSystemNode := Add(nil, Data);
  end;
  Result := FSystemNode;
  tvData.Expanded[FSystemNode] := True;
end;

function TdlgKnownData.GetThreadNode: PVirtualNode;
var
  Data: TNodeData;
begin
  if FThreadsNode = nil then
  begin
    Data := TNodeData.Default;
    Data.Caption := 'Threads';
    Data.ImageIndex := 0;
    FThreadsNode := Add(nil, Data);
  end;
  Result := FThreadsNode;
  tvData.Expanded[FThreadsNode] := True;
end;

procedure TdlgKnownData.mnuCopyAddressClick(Sender: TObject);
begin
  var I := GetSelectedNodeIndex;
  if I < 0 then Exit;
  Clipboard.AsText := IntToHex(Int64(FNodeDataList.List[I].Address));
end;

procedure TdlgKnownData.mnuGotoAddressClick(Sender: TObject);
begin
  tvDataDblClick(nil);
end;

procedure TdlgKnownData.pmCopyPopup(Sender: TObject);
begin
  mnuGotoAddress.Enabled := GetSelectedNodeIndex >= 0;
  mnuCopyAddress.Enabled := mnuGotoAddress.Enabled;
end;

procedure TdlgKnownData.ShowKnownData;
begin
  Show;
end;

procedure TdlgKnownData.tvDataDblClick(Sender: TObject);
begin
  var I := GetSelectedNodeIndex;
  if I < 0 then Exit;
  if FNodeDataList.List[I].Address = nil then Exit;
  dlgRegionProps := TdlgRegionProps.Create(Application);
  dlgRegionProps.ShowPropertyAtAddr(FNodeDataList.List[I].Address);
end;

procedure TdlgKnownData.tvDataGetImageIndex(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: Boolean; var ImageIndex: TImageIndex);
begin
  if Kind = ikOverlay then
    ImageIndex := FNodeDataList.List[PInteger(Node.GetData)^].OverlayIndex
  else
    if Kind in [ikNormal, ikSelected] then
      ImageIndex := FNodeDataList.List[PInteger(Node.GetData)^].ImageIndex;
end;

procedure TdlgKnownData.tvDataGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; TextType: TVSTTextType;
  var CellText: string);
begin
  var I := PInteger(Node.GetData)^;
  if Column = 1 then
    CellText := IntToHex(Int64(FNodeDataList.List[I].Address))
  else
    CellText := FNodeDataList.List[I].Caption;
end;

{ TdlgKnownData.TNodeData }

class function TdlgKnownData.TNodeData.Default: TNodeData;
begin
  ZeroMemory(@Result, SizeOf(TNodeData));
  Result.OverlayIndex := -1;
end;

end.
