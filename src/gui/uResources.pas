////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uResources.pas
//  * Purpose   : Форма для отображения ресурсов процесса
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.6.47
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uResources;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, VirtualTrees.BaseAncestorVCL, VirtualTrees.BaseTree,
  VirtualTrees.AncestorVCL, VirtualTrees, Vcl.ExtCtrls, Vcl.StdCtrls, Vcl.ComCtrls, uBaseForm,

  jpeg, pngimage, GIFImg,

  Generics.Collections,

  MemoryMap.Core,
  MemoryMap.RegionData,
  MemoryMap.Utils,

  RawScanner.Core,
  RawScanner.Image.Pe,
  RawScanner.Resources,
  RawScanner.Resources.Helpers,
  RawScanner.Utils,

  uDumpResources;

type
  TResourceData = record
    Caption: string;
    AddrVA, DataAddrVA: UInt64;
    DirData: TImageResourceDirectory;
    Data: TResource;
  end;

  TdlgResources = class(TBaseAppForm)
    tvResources: TVirtualStringTree;
    pcResViewers: TPageControl;
    tsRaw: TTabSheet;
    memResRaw: TMemo;
    tsText: TTabSheet;
    memResText: TMemo;
    tsImage: TTabSheet;
    pbResImage: TPaintBox;
    spLeftSplitter: TSplitter;
    pnTop: TPanel;
    lblFilter: TLabel;
    cbTypes: TComboBox;
    ScrollBar1: TScrollBar;
    pnRight: TPanel;
    memResInfo: TMemo;
    spBottomSplitter: TSplitter;
    procedure FormShow(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure tvResourcesGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; TextType: TVstTextType; var CellText: string);
    procedure tvResourcesAddToSelection(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure cbTypesChange(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure FormKeyPress(Sender: TObject; var Key: Char);
    procedure pbResImagePaint(Sender: TObject);
  private
    FResTrees, FResTypes: TStringList;
    FResList: TList<TResourceData>;
    FResImage: TPicture;
    FCurrentImageType: TBinaryResType;
    FRootIdx: Integer;
    FProcess: THandle;
    procedure ClearView;
    procedure FillTree(ANode: PVirtualNode; AResource: TResource);
    procedure FillByFilter;
  public
    procedure ShowResources;
  end;

var
  dlgResources: TdlgResources;

implementation

uses
  StrUtils,
  uDumpDisplayUtils,
  uProgress,
  uSettings,
  uUtils;

{$R *.dfm}

{ TdlgResources }

procedure TdlgResources.cbTypesChange(Sender: TObject);
begin
  FillByFilter;
end;

procedure TdlgResources.ClearView();
begin
  memResText.Clear;
  memResRaw.Clear;
  memResInfo.Clear;
  FreeAndNil(FResImage);
  pbResImage.Invalidate;
end;

procedure TdlgResources.FillByFilter;
var
  ANode: PVirtualNode;
  NodeData: PInteger;
  ResourceData: TResourceData;
  Resource: TResource;
  I: Integer;
  FilterFound: Boolean;
  Root: string;
begin
  tvResources.BeginUpdate;
  try
    tvResources.Clear;
    ClearView;
    if FResTrees.Count = 0 then Exit;
    pcResViewers.TabIndex := 0;
    if FRootIdx < 0 then
    begin
      Root := FResTrees[0];
      FResTrees.Sort;
      FRootIdx := FResTrees.IndexOf(Root);
      FResTrees.Move(FRootIdx, 0);
    end;
    for I := 0 to FResTrees.Count - 1 do
    begin
      ResourceData.Caption := FResTrees[I];
      ResourceData.Data := TResourceTree(FResTrees.Objects[I]).Resources;
      if cbTypes.Text <> '' then
      begin
        FilterFound := False;
        for Resource in ResourceData.Data.Childs do
          if Resource.DisplayName = cbTypes.Text then
          begin
            FilterFound := True;
            Break;
          end;
        if not FilterFound then
          Continue;
      end;
      ANode := tvResources.AddChild(nil);
      NodeData := tvResources.GetNodeData(ANode);
      NodeData^ := FResList.Add(ResourceData);
      FillTree(ANode, ResourceData.Data);
    end;
  finally
    tvResources.EndUpdate;
  end;
end;

procedure TdlgResources.FillTree(ANode: PVirtualNode; AResource: TResource);
var
  NewNode: PVirtualNode;
  NodeData: PInteger;
  ResourceData: TResourceData;
  ResRoot, ResChild: TResource;
  AddrVA, Size, RegionSize: NativeUInt;
  Idx: Integer;
  DirData: TImageResourceDirectory;
begin
  NodeData := tvResources.GetNodeData(ANode);
  Idx := NodeData^;
  if FProcess <> 0 then
  begin
    ResRoot := GetResRoot(AResource);
    Size := SizeOf(DirData);
    AddrVA := TRawPEImage(ResRoot.Tag).RawToVa(AResource.RawAddr);
    if AResource.ResType <> rtLanguageId then
    begin
      ReadProcessData(FProcess, Pointer(AddrVA), @DirData, Size, RegionSize, rcReadAllwais);
      FResList.List[Idx].AddrVA := AddrVA;
      FResList.List[Idx].DirData := DirData;
      if (AResource.ResType = rtNameDirectory) and (AResource.Childs.Count = 1) then
        FResList.List[Idx].DataAddrVA := TRawPEImage(ResRoot.Tag).RawToVa(AResource.Childs[0].RawAddr);
    end;
  end;

  case AResource.ResType of
    rtNameDirectory:
    begin
      if AResource.Childs.Count = 1 then
      begin
        FResList.List[Idx].Data := AResource.Childs[0];
        Exit;
      end;
    end;
    rtLanguageId:
    begin
      FResList.List[Idx].Data := AResource;
      Exit;
    end;
  end;
  for ResChild in AResource.Childs do
  begin
    if (ResChild.ResType = rtTypeDirectory) and (cbTypes.Text <> '') then
      if cbTypes.Text <> ResChild.DisplayName then
        Continue;
    ResourceData.Caption := ResChild.DisplayName;
    ResourceData.Data := ResChild;
    NewNode := tvResources.AddChild(ANode);
    NodeData := tvResources.GetNodeData(NewNode);
    NodeData^ := FResList.Add(ResourceData);
    FillTree(NewNode, ResChild);
  end;
end;

procedure TdlgResources.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  Action := caFree;
  dlgResources := nil;
end;

procedure TdlgResources.FormCreate(Sender: TObject);
begin
  FResTrees := TStringList.Create(True);
  FResTypes := TStringList.Create;
  FResTypes.Sorted := True;
  FResTypes.Duplicates := dupIgnore;
  FResTypes.Add('');
  FResList := TList<TResourceData>.Create;
  FRootIdx := -1;
end;

procedure TdlgResources.FormDestroy(Sender: TObject);
begin
  FResList.Free;
  FResTypes.Free;
  FResTrees.Free;
  FResImage.Free;
end;

procedure TdlgResources.FormKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #27 then
    Close;
end;

procedure TdlgResources.FormShow(Sender: TObject);
var
  Image: TRawPEImage;
  Gate: TPeImageGate;
  PeResReader: TPeResourceReader;
  FilePath: string;
  FileStream: TBufferedFileStream;
  ResourceTree: TResourceTree;
  Resource: TResource;
  I: Integer;
  ProcessLock: TProcessLockHandleList;
begin
  ProcessLock := nil;
  dlgProgress := TdlgProgress.Create(nil);
  try
    dlgProgress.Show;
    FProcess := OpenProcessWithReconnect;
    try
      if Settings.SuspendProcess then
        ProcessLock := SuspendProcess(MemoryMapCore.PID);
      try
        tvResources.NodeDataSize := SizeOf(Integer);
        FResTypes.Clear;
        FResTypes.Add('');
        dlgProgress.ProgressBar.Max := RawScannerCore.Modules.Items.Count;
        for I := 0 to RawScannerCore.Modules.Items.Count - 1 do
        begin
          Image := RawScannerCore.Modules.Items[I];
          FilePath := Image.ImagePath;

          dlgProgress.UpdateCaption(FilePath, I);

          if not FileExists(FilePath) then
          begin
            // А файла на месте может и не быть ибо он перемещен, хотя в списках
            // загрузчика все еще будет путь по которому он должен находиться.
            // Тогда запросим актуальный путь у MemoryMapCore у которой всегда
            // актуальные пути.
            FilePath := FilePathAtImageBase(Image.ImageBase);
            if not FileExists(FilePath) then
              Continue;
          end;

          Gate := TPeImageGate.Create(Image);
          try
            FileStream := TBufferedFileStream.Create(FilePath, fmOpenRead or fmShareDenyWrite);
            try
              PeResReader := TPeResourceReader.Create(Gate, FileStream);
              try
                ResourceTree := PeResReader.Load;
                if ResourceTree = nil then Continue;
                if ResourceTree.Resources.Childs.Count = 0 then
                  ResourceTree.Free
                else
                begin
                  ResourceTree.Resources.Tag := NativeUInt(Image);
                  FResTrees.AddObject(ExtractFileName(Image.ImagePath), ResourceTree);
                  for Resource in ResourceTree.Resources.Childs do
                    FResTypes.Add(Resource.DisplayName);
                end;
              finally
                PeResReader.Free;
              end;
            finally
              FileStream.Free;
            end;
          finally
            Gate.Free;
          end;
        end;

        cbTypes.Items := FResTypes;
        {$IFDEF DEBUG}
        if ParamStr(2) = '-resources' then
          cbTypes.ItemIndex := FResTypes.IndexOf(ParamStr(3));
        {$ENDIF}
        FillByFilter;
      finally
        if Settings.SuspendProcess then
          ResumeProcess(ProcessLock);
      end;
    finally
      CloseHandle(FProcess);
      FProcess := 0;
    end;
  finally
    dlgProgress.Release;
  end;
end;

procedure TdlgResources.pbResImagePaint(Sender: TObject);
var
  R: TRect;
begin
  pbResImage.Canvas.Brush.Color := clWhite;
  pbResImage.Canvas.FillRect(pbResImage.ClientRect);
  if FResImage = nil then Exit;
  R := Rect(0, 0, FResImage.Width, FResImage.Height);
  OffsetRect(R, (pbResImage.ClientWidth - R.Width) div 2,
    (pbResImage.ClientHeight - R.Height) div 2);
  case FCurrentImageType of
    brtCursor, brtCursorDib, brtIcon, brtIconDib:
      pbResImage.Canvas.Draw(R.Left, R.Top, FResImage.Icon);
    brtBitmap,
    brtBitmapDib: pbResImage.Canvas.Draw(R.Left, R.Top, FResImage.Bitmap);
    brtMetaFile: pbResImage.Canvas.Draw(R.Left, R.Top, FResImage.Metafile);
    brtTiff: pbResImage.Canvas.Draw(R.Left, R.Top, FResImage.WICImage);
  else
    pbResImage.Canvas.Draw(R.Left, R.Top, FResImage.Graphic);
  end;
end;

procedure TdlgResources.ShowResources;
begin
  Show;
end;

procedure TdlgResources.tvResourcesAddToSelection(Sender: TBaseVirtualTree;
  Node: PVirtualNode);

  procedure InitResImage(M: TMemoryStream; AClass: TGraphicClass);
  var
    AGraphic: TGraphic;
  begin
    if M.Size = 0 then
    begin
      FCurrentImageType := brtUnknown;
      Exit;
    end;
    FResImage := TPicture.Create;
    try
      M.Position := 0;
      AGraphic := AClass.Create;
      try
        AGraphic.LoadFromStream(M);
        FResImage.Assign(AGraphic);
      finally
        FreeAndNil(AGraphic);
      end;
    except
      FreeAndNil(FResImage);
    end;
  end;

  procedure InitStrings(AList: TStringList);
  begin
    memResText.Lines.AddStrings(AList);
    AList.Free;
  end;

var
  M: TMemoryStream;
  Idx, Tmp: Integer;
  Res: TResource;
  AddrVA: UInt64;
begin
  ClearView;
  Idx := PInteger(tvResources.GetNodeData(Node))^;
  Res := FResList[Idx].Data;

  memResInfo.Clear;
  AddrVA := FResList[Idx].AddrVA;
  if AddrVA > 0 then
  begin
    with FResList[Idx].DirData do
    begin
      {$MESSAGE 'Тут какую-то херню выводит'}
      memResInfo.Lines.Add(IntToHex(AddrVA) + ' Characteristics: 0x' + IntToHex(Characteristics, 8));
      Inc(AddrVA, SizeOf(ULONG));
      memResInfo.Lines.Add(IntToHex(AddrVA) + ' TimeDateStamp: ' + IntToHex(TimeDateStamp, 8));
      Inc(AddrVA, SizeOf(ULONG));
      memResInfo.Lines.Add(IntToHex(AddrVA) + ' MajorVersion: ' + IntToStr(MajorVersion));
      Inc(AddrVA, SizeOf(USHORT));
      memResInfo.Lines.Add(IntToHex(AddrVA) + ' MinorVersion: ' + IntToStr(MinorVersion));
      Inc(AddrVA, SizeOf(USHORT));
      memResInfo.Lines.Add(IntToHex(AddrVA) + ' NumberOfNamedEntries: ' + IntToStr(NumberOfNamedEntries));
      Inc(AddrVA, SizeOf(USHORT));
      memResInfo.Lines.Add(IntToHex(AddrVA) + ' NumberOfIdEntries: ' + IntToStr(NumberOfIdEntries));
      SendMessage(memResInfo.Handle, EM_LINESCROLL, 0, -memResInfo.Lines.Count);
    end;
  end;

  M := Res.Data;
  if M = nil then Exit;
  AddrVA := FResList[Idx].DataAddrVA;
  if AddrVA = 0 then
    AddrVA := FResList[Idx].AddrVA;
  memResRaw.Text := ByteToHexStr(AddrVA, M.Memory, M.Size);
  FCurrentImageType := GetBinaryResType(Res);
  case FCurrentImageType of

    brtIconDib:
    begin
      M := GetCursorIconStreamFromDib(Res, rc3_Icon);
      try
        InitResImage(M, TIcon);
      finally
        M.Free;
      end;
    end;
    brtIcon, brtIconGroup:
    begin
      {$message 'brtIcon, brtIconGroup не реализовано'}
      M := GetIconGroupStream(Res);
      M.SaveToFile('d:\tmp\test.ico');
      M.Free;
    end;
    brtCursorDib:
    begin
      M := GetCursorIconStreamFromDib(Res, rc3_Cursor);
      try
        M.Position := 2;
        Tmp := rc3_Icon;
        M.WriteBuffer(Tmp, 2);
        M.Position := 0;
        InitResImage(M, TIcon);
      finally
        M.Free;
      end;
    end;
    brtCursor, brtCursorGroup:
    begin
      {$message 'brtCursor, brtCursorGroup не реализовано'}
      M := GetCursorGroupStream(Res);
      M.SaveToFile('d:\tmp\test.cur');
      M.Free;
    end;
    brtBitmap: InitResImage(M, TBitmap);
    brtBitmapDib:
    begin
      M := GetBitmapStreamFromDib(Res);
      try
        InitResImage(M, TBitmap);
      finally
        M.Free;
      end;
    end;
    brtPng: InitResImage(M, TPngImage);
    brtJpg: InitResImage(M, TJPEGImage);
    brtGif: InitResImage(M, TGIFImage);
    brtMetaFile: InitResImage(M, TMetafile);
    brtTiff: InitResImage(M, TWICImage);
    brtStrUtf8: memResText.Lines.LoadFromStream(M, TEncoding.UTF8);
    brtStrUtf16: memResText.Lines.LoadFromStream(M, TEncoding.Unicode);
    brtStrUtf16Be: memResText.Lines.LoadFromStream(M, TEncoding.BigEndianUnicode);
    brtStrAnsi: memResText.Lines.LoadFromStream(M, TEncoding.ANSI);
    brtVersion: InitStrings(VersionToRC(Res));
    brtStringTable: InitStrings(StringsToRC(Res));
    brtMessageTable: InitStrings(MessageTableToString(Res));
    brtAccelerator: InitStrings(AcceleratorsToRC(Res));
    brtMenu: InitStrings(MenuToRC(Res));
    brtDialog: InitStrings(DialogToRC(Res));
    brtDVCLAL: InitStrings(DVCLALToRC(Res));
    brtDFM: InitStrings(DFMToRC(Res));
  end;

  if FCurrentImageType in [brtVersion..brtMessageTable, brtStrUtf8..brtDFM] then
  begin
    pcResViewers.TabIndex := 1;
    Exit;
  end;

  if Assigned(FResImage) and (FResImage.Width > 0) and (FResImage.Height > 0) then
    pcResViewers.TabIndex := 2
  else
    pcResViewers.TabIndex := 0;
end;

procedure TdlgResources.tvResourcesGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; TextType: TVstTextType;
  var CellText: string);
begin
  CellText := FResList[PInteger(tvResources.GetNodeData(Node))^].Caption;
end;

end.
