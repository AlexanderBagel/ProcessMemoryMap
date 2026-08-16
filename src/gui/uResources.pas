////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uResources.pas
//  * Purpose   : Форма для отображения ресурсов процесса
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.7.53
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
  VirtualTrees.AncestorVCL, VirtualTrees, Vcl.ExtCtrls, Vcl.StdCtrls, Vcl.ComCtrls,
  VirtualTrees.Types, Vcl.Menus, System.ImageList, Vcl.ImgList, UITypes, uBaseForm,

  Generics.Collections,

  jpeg, pngimage, GIFImg, Math, Img32, Img32.SVG.Reader,

  FWAniPaintBox,
  FWHexView,
  FWHexView.Common,

  MemoryMap.Core,
  MemoryMap.RegionData,
  MemoryMap.Utils,

  RawScanner.Core,
  RawScanner.Image.Pe,
  RawScanner.Resources,
  RawScanner.Resources.Helpers,
  RawScanner.Utils,

  uDumpResources, FWHexView.Actions, Vcl.ActnList, System.Actions;

type
  TResourceData = record
    Caption: string;
    AddrVA, DataAddrVA: UInt64;
    DirData: TImageResourceDirectory;
    Data: TResource;
    BinaryResType: TBinaryResType;
  end;

  TIconFrame = record
    Width, Height, BitDepth: Integer;
    Handle: HICON;
  end;

  TImagePaintParam = record
    Margin,
    Padding,
    DblPadding,
    Gap,
    CheckerSize,
    MinBoxSize,
    MaxBoxSize: Integer;
  end;

  TWheelPaintBox = class(TPaintBox)
  published
    property OnMouseWheel;
  end;

  TdlgResources = class(TBaseAppForm)
    tvResources: TVirtualStringTree;
    pcResViewers: TPageControl;
    tsRaw: TTabSheet;
    tsText: TTabSheet;
    memResText: TMemo;
    tsImage: TTabSheet;
    pbResImage: TPaintBox;
    spLeftSplitter: TSplitter;
    pnTop: TPanel;
    lblFilter: TLabel;
    cbTypes: TComboBox;
    sbVert: TScrollBar;
    pnRight: TPanel;
    memResInfo: TMemo;
    spBottomSplitter: TSplitter;
    pmTree: TPopupMenu;
    mnuSave: TMenuItem;
    SaveDialog: TSaveDialog;
    pmImage: TPopupMenu;
    pmText: TPopupMenu;
    SelectAll1: TMenuItem;
    Copy1: TMenuItem;
    N1: TMenuItem;
    SaveAs1: TMenuItem;
    SaveAs2: TMenuItem;
    ilTree: TImageList;
    HexView: TFWHexView;
    pmHex: TPopupMenu;
    CopyAddress1: TMenuItem;
    CopyAsText1: TMenuItem;
    N2: TMenuItem;
    SelectAll2: TMenuItem;
    SelectAll3: TMenuItem;
    SaveAs3: TMenuItem;
    N3: TMenuItem;
    OpenInExplorer1: TMenuItem;
    ActionList: TActionList;
    HexViewCopyAction1: THexViewCopyAction;
    HexViewCopyAction2: THexViewCopyAction;
    acSaveSingleRes: TAction;
    acSaveMultipleRes: TAction;
    acOpenInExplorer: TAction;
    acSelectAll: TAction;
    acCopy: TAction;
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
    procedure tsImageResize(Sender: TObject);
    procedure sbVertChange(Sender: TObject);
    procedure InternalSaveCurrent(Sender: TObject);
    procedure tvResourcesGetImageIndex(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: TImageIndex);
    procedure FormAfterMonitorDpiChanged(Sender: TObject; OldDPI,
      NewDPI: Integer);
    procedure acSaveSingleResUpdate(Sender: TObject);
    procedure acSaveSingleResExecute(Sender: TObject);
    procedure acSaveMultipleResExecute(Sender: TObject);
    procedure acOpenInExplorerExecute(Sender: TObject);
    procedure acSelectAllExecute(Sender: TObject);
    procedure acCopyExecute(Sender: TObject);
    procedure acOpenInExplorerUpdate(Sender: TObject);
  private
    FResTrees, FResTypes: TStringList;
    FResList: TList<TResourceData>;
    FResImage: TBitmap;
    FCurrentImageType: TBinaryResType;
    FCurrentImageIdx: Integer;
    FRootIdx, FUnfilteredCount: Integer;
    FProcess: THandle;
    FSavedResTree: TResourceTree;
    FAnimation: TFWAniPaintBox;
    function BuildIconOrCursorSheet(AStream: TMemoryStream;
      pIds: PWord; AIsIcon: Boolean): TBitmap;
    function BuildSingleImageSheet(AStream: TMemoryStream;
      AClass: TGraphicClass; AResType: TBinaryResType): TBitmap;
    function BuildSVGSheet(AStream: TMemoryStream): TBitmap;
    procedure ClearView;
    procedure DrawCheckerBoard(ACanvas: TCanvas; CheckerSize: Integer;
      const ARect: TRect);
    function GetImagePaintParam(ABitmap: TBitmap): TImagePaintParam;
    procedure FillTree(ANode: PVirtualNode; AResource: TResource);
    procedure FillByFilter;
    procedure ResourceInitSave;
    procedure ResourceAdd(AResource: TResource);
    procedure ResourceSave(const FilePath: string);
    function LoadIconFrames(AStream: TMemoryStream; pIds: PWord): TArray<TIconFrame>;
    procedure UpdateScroll(AReset: Boolean);
    procedure OnPainBoxWheel(Sender: TObject; Shift: TShiftState;
      WheelDelta: Integer; MousePos: TPoint; var Handled: Boolean);
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

procedure TdlgResources.acCopyExecute(Sender: TObject);
begin
  memResText.CopyToClipboard;
end;

procedure TdlgResources.acOpenInExplorerExecute(Sender: TObject);
var
  Node: PVirtualNode;
  ARes: TResourceData;
begin
  if tvResources.SelectedCount = 0 then Exit;
  Node := tvResources.GetFirstSelected;
  ARes := FResList[PInteger(tvResources.GetNodeData(Node))^];
  OpenExplorerAndSelectFile(TRawPEImage(GetResRoot(ARes.Data).Tag).ImagePath);
end;

procedure TdlgResources.acOpenInExplorerUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := tvResources.SelectedCount > 0;
end;

procedure TdlgResources.acSaveMultipleResExecute(Sender: TObject);
var
  Node: PVirtualNode;
  Res: TResourceData;
begin
  if tvResources.SelectedCount = 0 then Exit;
  Node := tvResources.GetFirstSelected;
  case tvResources.SelectedCount of
    0: Exit;
    1:
    begin
      Res := FResList[PInteger(tvResources.GetNodeData(Node))^];
      if Res.Data.ResType = rtLanguageId then
      begin
        InternalSaveCurrent(nil);
        Exit;
      end;
    end;
  end;
  SaveDialog.Filter := 'Resource File (*.res)|*.res';
  SaveDialog.FilterIndex := 0;
  SaveDialog.DefaultExt := '.res';
  Res := FResList[PInteger(tvResources.GetNodeData(Node))^];
  SaveDialog.FileName := ChangeFileExt(TRawPEImage(GetResRoot(Res.Data).Tag).ImageName, '.res');
  if not SaveDialog.Execute(Handle) then Exit;
  ResourceInitSave;
  try
    while Node <> nil do
    begin
      Res := FResList[PInteger(tvResources.GetNodeData(Node))^];
      ResourceAdd(Res.Data);
      Node := tvResources.GetNextSelected(Node);
    end;
  finally
    ResourceSave(SaveDialog.FileName);
  end;
end;

procedure TdlgResources.acSaveSingleResExecute(Sender: TObject);
begin
  InternalSaveCurrent(nil);
end;

procedure TdlgResources.acSaveSingleResUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := FCurrentImageIdx >= 0;
end;

procedure TdlgResources.acSelectAllExecute(Sender: TObject);
begin
  if pcResViewers.ActivePageIndex = 0 then
    HexView.SelectAll
  else
    memResText.SelectAll;
end;

function TdlgResources.BuildIconOrCursorSheet(AStream: TMemoryStream;
  pIds: PWord; AIsIcon: Boolean): TBitmap;
var
  Frames: TArray<TIconFrame>;
  Texts: TArray<string>;
  I, RowHeight, TextHeight, MaxTextWidth, MaxIconWidth,
  IconColumnX, TotalHeight, Y, IndexDigits: Integer;
  Param: TImagePaintParam;
  R, CellRect: TRect;
  IndexFmt: string;
  GroupText: string;
  GroupTextW: Integer;
begin
  Frames := LoadIconFrames(AStream, pIds);
  if Frames = nil then Exit(nil);
  Result := TBitmap.Create;
  try
    try
      Param := GetImagePaintParam(Result);
      IndexDigits := Length(IntToStr(Max(Length(Frames) - 1, 0)));
      IndexFmt := '%.' + IntToStr(IndexDigits) + 'd: %dx%d %dbpp';
      SetLength(Texts, Length(Frames));
      TextHeight := Result.Canvas.TextHeight('Wg');
      MaxTextWidth := 0;
      MaxIconWidth := 0;
      TotalHeight := Param.Margin;
      for I := 0 to Length(Frames) - 1 do
      begin
        if Frames[I].Handle = 0 then Continue;
        Texts[I] := Format(IndexFmt, [I, Frames[I].Width, Frames[I].Height, Frames[I].BitDepth]);
        MaxTextWidth := Max(MaxTextWidth, Result.Canvas.TextWidth(Texts[I]));
        MaxIconWidth := Max(MaxIconWidth, Frames[I].Width);
        RowHeight := Max(Frames[I].Height + Param.DblPadding, TextHeight);
        Inc(TotalHeight, RowHeight + Param.Gap);
      end;
      if Length(Frames) > 0 then
        Dec(TotalHeight, Param.Gap);

      if AIsIcon then
        GroupText := 'Group Icon'
      else
        GroupText := 'Group Cursor';
      GroupTextW := Result.Canvas.TextWidth(GroupText);

      Inc(TotalHeight, Param.Gap + TextHeight);
      Inc(TotalHeight, Param.Margin);

      IconColumnX := Param.Margin + MaxTextWidth + Param.Gap;
      Result.Width := Max(IconColumnX + MaxIconWidth + Param.DblPadding, GroupTextW) + Param.Margin;
      Result.Height := Max(TotalHeight, 1);

      Result.Canvas.Brush.Style := bsSolid;
      Result.Canvas.Brush.Color := clWhite;
      R := Rect(0, 0, Result.Width, Result.Height);
      Result.Canvas.FillRect(R);
      Result.Canvas.Pen.Color := $A4A4A4;
      Dec(R.Bottom, TextHeight + Param.Margin);
      Result.Canvas.Rectangle(R);
      Result.Canvas.Font.Color := clBlack;

      Y := Param.Margin;
      for I := 0 to Length(Frames) - 1 do
      begin
        if Frames[I].Handle = 0 then Continue;
        RowHeight := Max(Frames[I].Height + Param.DblPadding, TextHeight);

        // зебра для длинных списков
        if Odd(I) then
        begin
          Result.Canvas.Brush.Style := bsSolid;
          Result.Canvas.Brush.Color := $DEDEDE;
          Result.Canvas.FillRect(Bounds(Param.Padding, Y - Param.Padding,
            Result.Width - Param.DblPadding, RowHeight + Param.DblPadding));
          Result.Canvas.Brush.Style := bsClear;
        end;

        Result.Canvas.TextOut(Param.Margin, Y + (RowHeight - TextHeight) div 2, Texts[I]);

        // ячейка под иконку + шахматный фон для более явного отображения альфа-канала
        CellRect := Bounds(IconColumnX, Y + (RowHeight - (Frames[I].Height + Param.DblPadding)) div 2,
          Frames[I].Width + Param.DblPadding, Frames[I].Height + Param.DblPadding);
        DrawCheckerBoard(Result.Canvas, Param.CheckerSize, CellRect);

        R := Bounds(CellRect.Left + Param.Padding, CellRect.Top + Param.Padding,
          Frames[I].Width, Frames[I].Height);
        DrawIconEx(Result.Canvas.Handle,
          R.Left, R.Top, Frames[I].Handle, R.Width, R.Height, 0, 0, DI_NORMAL);

        Inc(Y, RowHeight + Param.Gap);
      end;

      Result.Canvas.TextOut((Result.Width - GroupTextW) div 2, Y + Param.Gap, GroupText);
    except
      FreeAndNil(Result);
    end;
  finally
    for I := 0 to Length(Frames) - 1 do
      if Frames[I].Handle <> 0 then
        DestroyIcon(Frames[I].Handle);
  end;
end;

function TdlgResources.BuildSingleImageSheet(AStream: TMemoryStream;
  AClass: TGraphicClass; AResType: TBinaryResType): TBitmap;

  function GetBitDepthFromGraphic(AGraphic: TGraphic): Integer;
  var
    TmpBmp: TBitmap;
  begin
    Result := 24;
    TmpBmp := TBitmap.Create;
    try
      TmpBmp.Assign(AGraphic);
      case TmpBmp.PixelFormat of
        pf1bit:  Result := 1;
        pf4bit:  Result := 4;
        pf8bit:  Result := 8;
        pf15bit: Result := 15;
        pf16bit: Result := 16;
        pf24bit: Result := 24;
        pf32bit: Result := 32;
      end;
    finally
      TmpBmp.Free;
    end;
  end;

var
  AGraphic: TGraphic;
  TypeName, TextStr: string;
  BitDepth, ImgW, ImgH, BoxW, BoxH, TextW, TextH: Integer;
  Param: TImagePaintParam;
  BoxRect, DrawRect: TRect;
begin
  Result := nil;
  AGraphic := AClass.Create;
  try
    try
      AStream.Position := 0;
      AGraphic.LoadFromStream(AStream);

      ImgW := AGraphic.Width;
      ImgH := AGraphic.Height;
      if (ImgW <= 0) or (ImgH <= 0) then Exit;

      case AResType of
        brtCursor,
        brtCursorDib,
        brtAniCursor: TypeName := 'CUR';
        brtIcon,
        brtIconDib,
        brtAniIcon: TypeName := 'ICO';
        brtBitmap,
        brtBitmapDib: TypeName := 'BMP';
        brtPng: TypeName := 'PNG';
        brtJpg: TypeName := 'JPG';
        brtGif: TypeName := 'GIF';
        brtMetaFile: TypeName := 'WMF';
        brtTiff: TypeName := 'TIFF';
      else
        Exit;
      end;
      case AResType of
        brtCursor,
        brtCursorDib,
        brtIcon,
        brtIconDib:
        begin
          BitDepth := PIconFileDirEntry(PByte(AStream.Memory) + SizeOf(TCursorOrIcon))^.ImageOffset;
          BitDepth := PBitmapInfoHeader(PByte(AStream.Memory) + BitDepth)^.biBitCount;
        end;
      else
        BitDepth := GetBitDepthFromGraphic(AGraphic);
      end;

      Result := TBitmap.Create;
      Param := GetImagePaintParam(Result);

      TextStr := Format('%s %dx%d %dbpp', [TypeName, ImgW, ImgH, BitDepth]);
      TextW := Result.Canvas.TextWidth(TextStr);
      TextH := Result.Canvas.TextHeight(TextStr);

      BoxW := Max(ImgW + Param.DblPadding, Param.MinBoxSize);
      BoxH := Max(ImgH + Param.DblPadding, Param.MinBoxSize);

      Result.Width := Max(BoxW, TextW) + Param.Margin * 2;
      Result.Height := Param.Margin + BoxH + Param.Gap + TextH + Param.Margin;

      Result.Canvas.Brush.Style := bsSolid;
      Result.Canvas.Brush.Color := clWhite;
      Result.Canvas.FillRect(Rect(0, 0, Result.Width, Result.Height));
      Result.Canvas.Brush.Style := bsClear;
      Result.Canvas.Font.Color := clBlack;

      BoxRect := Bounds((Result.Width - BoxW) div 2, Param.Margin, BoxW, BoxH);
      DrawCheckerBoard(Result.Canvas, Param.CheckerSize, BoxRect);

      DrawRect := Bounds(BoxRect.Left + (BoxW - ImgW) div 2,
        BoxRect.Top + (BoxH - ImgH) div 2, ImgW, ImgH);
      Result.Canvas.Draw(DrawRect.Left, DrawRect.Top, AGraphic);
      Result.Canvas.TextOut((Result.Width - TextW) div 2, BoxRect.Bottom + Param.Gap, TextStr);
    except
      FreeAndNil(Result);
    end;
  finally
    AGraphic.Free;
  end;
end;

function TdlgResources.BuildSVGSheet(AStream: TMemoryStream): TBitmap;
var
  Param: TImagePaintParam;
  LSvgReader: TSvgReader;
  LImg: TImage32;
  SvgSize: TSize;
  ImgW, ImgH, BoxW, BoxH, TextW, TextH, MaxSide, DrawW, DrawH: Integer;
  Scale: Double;
  TextStr: string;
  BoxRect, DrawRect: TRect;
begin
  Result := nil;
  LSvgReader := TSvgReader.Create;
  try
    try
      AStream.Position := 0;
      LSvgReader.LoadFromStream(AStream);

      SvgSize := LSvgReader.GetImageSize;
      ImgW := SvgSize.cx;
      ImgH := SvgSize.cy;
      if (ImgW <= 0) or (ImgH <= 0) then Exit;

      Result := TBitmap.Create;
      Param := GetImagePaintParam(Result);

      TextStr := Format('SVG %dx%d 32bpp', [ImgW, ImgH]);
      TextW := Result.Canvas.TextWidth(TextStr);
      TextH := Result.Canvas.TextHeight(TextStr);

      MaxSide := Param.MaxBoxSize - Param.Margin;
      if MaxSide < 1 then
        MaxSide := Param.MaxBoxSize;

      if Max(ImgW, ImgH) > Param.MaxBoxSize then
      begin
        DrawW := ImgW;
        DrawH := ImgH;
      end
      else
      begin
        Scale := MaxSide / Max(ImgW, ImgH);
        DrawW := Max(Round(ImgW * Scale), 1);
        DrawH := Max(Round(ImgH * Scale), 1);
      end;

      BoxW := Max(DrawW + Param.DblPadding, Param.MinBoxSize);
      BoxH := Max(DrawH + Param.DblPadding, Param.MinBoxSize);

      Result.Width := Max(BoxW, TextW) + Param.Margin * 2;
      Result.Height := Param.Margin + BoxH + Param.Gap + TextH + Param.Margin;

      Result.Canvas.Brush.Style := bsSolid;
      Result.Canvas.Brush.Color := clWhite;
      Result.Canvas.FillRect(Rect(0, 0, Result.Width, Result.Height));
      Result.Canvas.Brush.Style := bsClear;
      Result.Canvas.Font.Color := clBlack;

      BoxRect := Bounds((Result.Width - BoxW) div 2, Param.Margin, BoxW, BoxH);
      DrawCheckerBoard(Result.Canvas, Param.CheckerSize, BoxRect);

      DrawRect := Bounds(
        BoxRect.Left + (BoxW - DrawW) div 2,
        BoxRect.Top + (BoxH - DrawH) div 2,
        DrawW, DrawH);

      LImg := TImage32.Create(DrawW, DrawH);
      try
        LSvgReader.DrawImage(LImg, True);
        LImg.CopyToDc(Rect(0, 0, LImg.Width, LImg.Height), DrawRect,
          Result.Canvas.Handle, True);
      finally
        LImg.Free;
      end;

      Result.Canvas.TextOut((Result.Width - TextW) div 2, BoxRect.Bottom + Param.Gap, TextStr);
    except
      FreeAndNil(Result);
    end;
  finally
    LSvgReader.Free;
  end;
end;

procedure TdlgResources.cbTypesChange(Sender: TObject);
begin
  FillByFilter;
end;

procedure TdlgResources.ClearView();
begin
  memResText.Clear;
  HexView.SetDataStream(nil, 0);
  memResInfo.Clear;
  FreeAndNil(FResImage);
  FAnimation.Visible := False;
  pbResImage.Visible := True;
  FCurrentImageIdx := -1;
  InvalidateRect(tsImage.Handle, pbResImage.BoundsRect, False);
end;

procedure TdlgResources.DrawCheckerBoard(ACanvas: TCanvas;
  CheckerSize: Integer; const ARect: TRect);
var
  X, Y: Integer;
  GraySquare: Boolean;
begin
  ACanvas.Brush.Style := bsSolid;
  Y := ARect.Top;
  while Y < ARect.Bottom do
  begin
    X := ARect.Left;
    GraySquare := ((Y - ARect.Top) div CheckerSize) mod 2 = 0;
    while X < ARect.Right do
    begin
      if GraySquare then
        ACanvas.Brush.Color := $F0F0F0
      else
        ACanvas.Brush.Color := clWhite;
      ACanvas.FillRect(Rect(X, Y, Min(X + CheckerSize, ARect.Right),
        Min(Y + CheckerSize, ARect.Bottom)));
      GraySquare := not GraySquare;
      Inc(X, CheckerSize);
    end;
    Inc(Y, CheckerSize);
  end;
  ACanvas.Pen.Color := $00FCA000;
  ACanvas.Brush.Style := bsClear;
  ACanvas.Rectangle(ARect);
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
    FResList.Count := FUnfilteredCount;
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
  Idx, I: Integer;
  DirData: TImageResourceDirectory;
begin
  NodeData := tvResources.GetNodeData(ANode);
  Idx := NodeData^;

  ResRoot := GetResRoot(AResource);
  Size := SizeOf(DirData);
  AddrVA := TRawPEImage(ResRoot.Tag).RawToVa(AResource.RawAddr);
  if FProcess <> 0 then
  begin
    if AResource.ResType <> rtLanguageId then
    begin
      ReadProcessData(FProcess, Pointer(AddrVA), @DirData, Size, RegionSize, rcReadAllwais);
      FResList.List[Idx].AddrVA := AddrVA;
      FResList.List[Idx].DirData := DirData;
      if (AResource.ResType = rtNameDirectory) and (AResource.Childs.Count = 1) then
        FResList.List[Idx].DataAddrVA := TRawPEImage(ResRoot.Tag).RawToVa(AResource.Childs[0].RawAddr);
    end;
  end
  else
  begin
    for I := 0 to Idx - 1 do
      if FResList.List[I].AddrVA = AddrVA then
      begin 
        FResList.List[Idx].AddrVA := AddrVA;
        FResList.List[Idx].DirData := FResList.List[I].DirData;  
        FResList.List[Idx].DataAddrVA := FResList.List[I].DataAddrVA;  
        Break;  
      end;
  end;

  case AResource.ResType of
    rtNameDirectory:
    begin
      if AResource.Childs.Count = 1 then
      begin
        FResList.List[Idx].Data := AResource.Childs[0];
        FResList.List[Idx].BinaryResType := GetBinaryResType(AResource.Childs[0]);
        Exit;
      end;
    end;
    rtLanguageId:
    begin
      FResList.List[Idx].Data := AResource;
      ResourceData.BinaryResType := GetBinaryResType(AResource);
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
    ResourceData.BinaryResType := brtUnknown;
    NewNode := tvResources.AddChild(ANode);
    NodeData := tvResources.GetNodeData(NewNode);
    NodeData^ := FResList.Add(ResourceData);
    FillTree(NewNode, ResChild);
  end;
end;

procedure TdlgResources.FormAfterMonitorDpiChanged(Sender: TObject; OldDPI,
  NewDPI: Integer);
begin
  FixVirtualStringTreeDpiBug(tvResources);
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
  tsImage.DoubleBuffered := True;
  TWheelPaintBox(pbResImage).OnMouseWheel := OnPainBoxWheel;
  FAnimation := TFWAniPaintBox.Create(Self);
  FAnimation.Parent := tsImage;
  FAnimation.Align := alClient;
  FAnimation.Color := clWhite;
  FAnimation.PopupMenu := pmImage;
  FAnimation.Visible := False;
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
        FUnfilteredCount := FResList.Count;
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

function TdlgResources.GetImagePaintParam(ABitmap: TBitmap): TImagePaintParam;
begin
  Result.Margin := MulDiv(12, FCurrentPPI, USER_DEFAULT_SCREEN_DPI);
  Result.Padding := MulDiv(4, FCurrentPPI, USER_DEFAULT_SCREEN_DPI);
  Result.DblPadding := Result.Padding + Result.Padding;
  Result.Gap := MulDiv(8, FCurrentPPI, USER_DEFAULT_SCREEN_DPI);
  Result.CheckerSize := MulDiv(6, FCurrentPPI, USER_DEFAULT_SCREEN_DPI);
  Result.MinBoxSize := MulDiv(32, FCurrentPPI, USER_DEFAULT_SCREEN_DPI);
  Result.MaxBoxSize := MulDiv(256, FCurrentPPI, USER_DEFAULT_SCREEN_DPI);
  ABitmap.PixelFormat := pf32bit;
  ABitmap.Canvas.Font.Name := 'Segoe UI';
  ABitmap.Canvas.Font.Size := MulDiv(10, FCurrentPPI, USER_DEFAULT_SCREEN_DPI);
  ABitmap.Canvas.Brush.Style := bsClear;
end;

procedure TdlgResources.InternalSaveCurrent(Sender: TObject);
var
  Filter: string;
  M: TMemoryStream;
  IdList: TIdList;
  Ext: TArray<string>;
  FilterCount: Integer;
begin
  Filter := '';
  if FCurrentImageIdx < 0 then Exit;
  FilterCount := 3;
  case FCurrentImageType of
    brtVersion, brtStringTable, brtAccelerator,
    brtMenu, brtDialog{, brtFont, brtFontDir}: Filter := '|Resource Script File (*.rc)|*.rc';
    brtMessageTable, brtStrUtf8, brtStrUtf16, brtStrUtf16Be,
    brtStrAnsi, brtDVCLAL, brtPackageInfo: Filter := '|Text File (*.txt)|*.txt';
    brtCursorGroup, brtCursor, brtCursorDib: Filter := '|Cursor File (*.cur)|*.cur';
    brtIconGroup, brtIcon, brtIconDib: Filter := '|Icon File (*.ico)|*.ico';
    brtAniCursor, brtAniIcon: Filter := '|Animation (*.ani)|*.ani';
    brtBitmap, brtBitmapDib: Filter := '|Bitmap (*.bmp)|*.bmp';
    brtPng: Filter := '|PNG (*.png)|*.png';
    brtJpg: Filter := '|JPG (*.jpg)|*.jpg';
    brtGif: Filter := '|GIF (*.gif)|*.gif';
    brtMetaFile: Filter := '|Window Meta File (*.wmf)|*.wmf';
    brtTiff: Filter := '|TIFF (*.tiff)|*.tiff';
    brtSvgUtf8: Filter := '|SVG (*.svg)|*.svg';
    brtDFM: Filter := '|Delphi Form (*.dfm)|*.dfm';
  else
    FilterCount := 2;
  end;
  SaveDialog.Filter := 'Binary Stream (*.bin)|*.bin|Resource File (*.res)|*.res' + Filter;
  SaveDialog.FilterIndex := FilterCount;
  Ext := SaveDialog.Filter.Split(['|']);
  SaveDialog.DefaultExt := ExtractFileExt(Ext[Length(Ext) - 1]);
  SaveDialog.FileName :=
    ChangeFileExt(TRawPEImage(GetResRoot(FResList[FCurrentImageIdx].Data).Tag).ImageName, '') + '_' +
    GetResType(FResList[FCurrentImageIdx].Data).DisplayName + '_' +
    FResList[FCurrentImageIdx].Caption + SaveDialog.DefaultExt;
  if not SaveDialog.Execute(Handle) then Exit;
  case SaveDialog.FilterIndex of
    1:
    begin
      FResList[FCurrentImageIdx].Data.Data.SaveToFile(SaveDialog.FileName);
      Exit;
    end;
    2:
    begin
      ResourceInitSave;
      ResourceAdd(FResList[FCurrentImageIdx].Data);
      ResourceSave(SaveDialog.FileName);
      Exit;
    end;
  end;
  case FCurrentImageType of
    brtVersion, brtStringTable, brtAccelerator, brtMenu, brtDialog,
    brtMessageTable, brtDFM:
      memResText.Lines.SaveToFile(SaveDialog.FileName);
    brtStrUtf8, brtStrUtf16, brtStrUtf16Be, brtStrAnsi,
    brtCursor, brtIcon, brtAniCursor, brtAniIcon, brtSvgUtf8,
    brtBitmap, brtPng, brtJpg, brtGif, brtMetaFile, brtTiff:
      FResList[FCurrentImageIdx].Data.Data.SaveToFile(SaveDialog.FileName);
    brtBitmapDib:
    begin
      M := GetBitmapStreamFromDib(FResList[FCurrentImageIdx].Data);
      try
        M.SaveToFile(SaveDialog.FileName);
      finally
        M.Free;
      end;
    end;
    brtCursorDib:
    begin
      M := GetCursorIconStreamFromDib(FResList[FCurrentImageIdx].Data, rc3_Cursor);
      try
        M.SaveToFile(SaveDialog.FileName);
      finally
        M.Free;
      end;
    end;
    brtCursorGroup:
    begin
      M := GetCursorGroupStream(FResList[FCurrentImageIdx].Data, IdList);
      try
        M.SaveToFile(SaveDialog.FileName);
      finally
        M.Free;
      end;
    end;
    brtIconDib:
    begin
      M := GetCursorIconStreamFromDib(FResList[FCurrentImageIdx].Data, rc3_Icon);
      try
        M.SaveToFile(SaveDialog.FileName);
      finally
        M.Free;
      end;
    end;
    brtIconGroup:
    begin
      M := GetIconGroupStream(FResList[FCurrentImageIdx].Data, IdList);
      try
        M.SaveToFile(SaveDialog.FileName);
      finally
        M.Free;
      end;
    end;
  end;
end;

function TdlgResources.LoadIconFrames(AStream: TMemoryStream; pIds: PWord): TArray<TIconFrame>;
const
  PNGSig: array[0..7] of Byte = ($89, $50, $4E, $47, $0D, $0A, $1A, $0A);
var
  Dir: TCursorOrIcon;
  Entries: array of TIconFileDirEntry;
  I: Integer;
  BitDepth, ColorType: Byte;
  pBuff: PByteArray;
  TextInfo: string;
begin
  Result := nil;
  AStream.Position := 0;
  AStream.ReadBuffer(Dir, SizeOf(Dir));

  if (Dir.Reserved <> 0) or not (Dir.wType in [RC3_ICON, RC3_CURSOR]) then
    Exit;

  SetLength(Entries, Dir.Count);
  if Dir.Count > 0 then
    AStream.ReadBuffer(Entries[0], Dir.Count * SizeOf(TIconFileDirEntry));

  SetLength(Result, Dir.Count);
  for I := 0 to Dir.Count - 1 do
  begin
        
    pBuff := PByteArray(PByte(AStream.Memory) + Entries[I].ImageOffset);

    if CompareMem(@PNGSig[0], pBuff, SizeOf(PNGSig)) then
    begin
      Result[I].Width := (UInt32(pBuff[16]) shl 24) or
        (UInt32(pBuff[17]) shl 16) or (UInt32(pBuff[18]) shl 8) or UInt32(pBuff[19]);
      Result[I].Height := (UInt32(pBuff[20]) shl 24) or
        (UInt32(pBuff[21]) shl 16) or (UInt32(pBuff[22]) shl 8) or UInt32(pBuff[23]);
      BitDepth := pBuff[24];
      ColorType := pBuff[25];
      case ColorType of
        2: Result[I].BitDepth := BitDepth * 3;  // truecolor (RGB)
        4: Result[I].BitDepth := BitDepth * 2;  // grayscale + alpha
        6: Result[I].BitDepth := BitDepth * 4;  // truecolor + alpha (RGBA)
      else
        Result[I].BitDepth := BitDepth;
      end;
      TextInfo := 'Vista ';
    end
    else
    begin
      Result[I].Width := PBitmapInfoHeader(pBuff)^.biWidth;
      Result[I].Height := PBitmapInfoHeader(pBuff)^.biHeight div 2;
      Result[I].BitDepth := PBitmapInfoHeader(pBuff)^.biBitCount;
      TextInfo := '';
    end;

    if Result[I].Width = 0 then
      Result[I].Width := 256;
    if Result[I].Height = 0 then
      Result[I].Height := 256;

    if Dir.wType = RC3_ICON then
      Result[I].Handle := CreateIconFromResourceEx(PByte(pBuff),
        Entries[I].BytesInRes, True, $00030000,
        Result[I].Width, Result[I].Height, LR_DEFAULTCOLOR)
    else
    begin
      pBuff := PByteArray(PByte(AStream.Memory) + Entries[I].ImageOffset - 4);
      PInteger(pBuff)^ := 0; // хотспоты курсора (два ворда), просто скидываю в ноль
      Result[I].Handle := CreateIconFromResourceEx(PByte(pBuff),
        Entries[I].BytesInRes + 4, False, $00030000,
        Result[I].Width, Result[I].Height, LR_DEFAULTCOLOR)
    end;
    if pIds <> nil then
    begin
      TextInfo := Format('%dx%d %d-bit %s%s Entry Ord: %d', [
        Result[I].Width, Result[I].Height, Result[I].BitDepth, TextInfo, 
        IfThen(Dir.wType = RC3_ICON, 'Icon', 'Cursor'), pIds^
      ]);
      Inc(pIds);
      memResText.Lines.Add(TextInfo);
    end;
  end;
end;

procedure TdlgResources.OnPainBoxWheel(Sender: TObject; Shift: TShiftState;
  WheelDelta: Integer; MousePos: TPoint; var Handled: Boolean);
begin
  if sbVert.Visible then
    sbVert.Position := Min(sbVert.Position - WheelDelta, sbVert.Max - sbVert.PageSize);
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
  if R.Top < 0 then
    OffsetRect(R, 0, -sbVert.Position - R.Top);
  pbResImage.Canvas.Draw(R.Left, R.Top, FResImage);
end;

procedure TdlgResources.ResourceAdd(AResource: TResource);
begin
  AddResToResTree(AResource, FSavedResTree);
end;

procedure TdlgResources.ResourceInitSave;
begin
  FSavedResTree := TResourceTree.Create;
end;

procedure TdlgResources.ResourceSave(const FilePath: string);
var
  Writer: TBinaryResourceWriter;
begin
  Writer := TBinaryResourceWriter.Create;
  try
    try
      Writer.SaveToFile(FSavedResTree, FilePath);
    finally
      FreeAndNil(FSavedResTree);
    end;
  finally
    Writer.Free;
  end;
end;

procedure TdlgResources.sbVertChange(Sender: TObject);
begin
  // Отключение флика
  InvalidateRect(tsImage.Handle, pbResImage.BoundsRect, False);
end;

procedure TdlgResources.ShowResources;
begin
  Show;
end;

procedure TdlgResources.tsImageResize(Sender: TObject);
begin
  UpdateScroll(False);
end;

procedure TdlgResources.tvResourcesAddToSelection(Sender: TBaseVirtualTree;
  Node: PVirtualNode);

  procedure InitResImage(M: TMemoryStream; AClass: TGraphicClass);
  begin
    if M.Size = 0 then
    begin
      FCurrentImageType := brtUnknown;
      FCurrentImageIdx := -1;
    end
    else
      FResImage := BuildSingleImageSheet(M, AClass, FCurrentImageType);
  end;

  procedure InitStrings(AList: TStringList);
  begin
    memResText.Lines.AddStrings(AList);
    AList.Free;
  end;

  procedure InitAnimation(M: TMemoryStream);
  begin
    FAnimation.LoadFromStream(M);
    FAnimation.Visible := True;
    pbResImage.Visible := False;
    FAnimation.Play;
  end;

var
  M: TMemoryStream;
  Idx, Tmp: Integer;
  Res: TResource;
  AddrVA: UInt64;
  IdList: TIdList;
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
  HexView.SetDataStream(M, AddrVA);
  if AddrVA < DWORD(-1) then
    HexView.AddressMode := am32bit
  else
    HexView.AddressMode := am64bit;
  HexView.FitColumnsToBestSize;

  FCurrentImageIdx := Idx;
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
    brtIcon, brtCursor, brtIconGroup, brtCursorGroup:
    begin
      case FCurrentImageType of
        brtIcon, brtCursor:
          FResImage := BuildIconOrCursorSheet(M, nil, FCurrentImageType = brtIcon);
      else
        if FCurrentImageType = brtIconGroup then
          M := GetIconGroupStream(Res, IdList)
        else
          M := GetCursorGroupStream(Res, IdList);
        try
          FResImage := BuildIconOrCursorSheet(M, @IdList[0], FCurrentImageType = brtIconGroup);
        finally
          M.Free;
        end;
      end;
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
    brtSvgUtf8:
    begin
      memResText.Lines.LoadFromStream(M, TEncoding.UTF8);
      FResImage := BuildSVGSheet(M);
    end;
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
    brtDVCLAL: InitStrings(DVCLALToString(Res));
    brtPackageInfo: InitStrings(PackageInfoToString(Res));
    brtDFM: InitStrings(DFMToString(Res));
    brtAvi, brtAniCursor, brtAniIcon: InitAnimation(M);
  end;

  UpdateScroll(True);

  if FCurrentImageType in [brtVersion..brtMessageTable, brtStrUtf8..brtDFM] then
  begin
    pcResViewers.TabIndex := 1;
    Exit;
  end;

  if FAnimation.Visible or (Assigned(FResImage) and (FResImage.Width > 0) and (FResImage.Height > 0)) then
    pcResViewers.TabIndex := 2
  else
    pcResViewers.TabIndex := 0;
end;

procedure TdlgResources.tvResourcesGetImageIndex(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: Boolean; var ImageIndex: TImageIndex);
var
  Res: TResourceData;
begin
  ImageIndex := -1;
  if Node = nil then Exit;
  if Kind <> ikState then Exit;
  Res := FResList[PInteger(tvResources.GetNodeData(Node))^];
  case Res.Data.ResType of
    rtRoot,
    rtTypeDirectory,
    rtNameDirectory: ImageIndex := 0;
    rtLanguageId:
    begin
      case Res.BinaryResType of
        brtUnknown: ImageIndex := 1;
        brtVersion: ImageIndex := 2;
        brtStringTable: ImageIndex := 3;
        brtAccelerator: ImageIndex := 4;
        brtMenu: ImageIndex := 5;
        brtDialog: ImageIndex := 6;
        brtFont,
        brtFontDir: ImageIndex := 7;
        brtMessageTable: ImageIndex := 8;
        brtCursorGroup, brtCursor, brtCursorDib, brtAniCursor: ImageIndex := 9;
        brtIconGroup, brtIcon, brtIconDib, brtAniIcon: ImageIndex := 10;
        brtBitmap, brtBitmapDib: ImageIndex := 11;
        brtPng: ImageIndex := 12;
        brtJpg: ImageIndex := 13;
        brtGif: ImageIndex := 14;
        brtMetaFile: ImageIndex := 15;
        brtTiff: ImageIndex := 16;
        brtSvgUtf8: ImageIndex := 17;
        brtStrUtf8: ImageIndex := 18;
        brtStrUtf16, brtStrUtf16Be: ImageIndex := 19;
        brtStrAnsi: ImageIndex := 20;
        brtDVCLAL: ImageIndex := 21;
        brtDFM: ImageIndex := 22;
        brtPackageInfo: ImageIndex := 23;
        brtAvi: ImageIndex := 24;
      end;
    end;
  end;
end;

procedure TdlgResources.tvResourcesGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; TextType: TVstTextType;
  var CellText: string);
begin
  CellText := FResList[PInteger(tvResources.GetNodeData(Node))^].Caption;
end;

procedure TdlgResources.UpdateScroll(AReset: Boolean);
var
  OverHeight, PageSize: Integer;
begin
  if (FResImage = nil) or (FResImage.Height <= pbResImage.Height) then
    sbVert.Visible := False
  else
  begin
    if AReset then
      sbVert.Position := 0;
    OverHeight := FResImage.Height - pbResImage.Height;
    if OverHeight < 3 then Exit;
    PageSize := MulDiv(OverHeight, 100 - MulDiv(OverHeight, 100, FResImage.Height), 100);
    Inc(OverHeight, PageSize);
    sbVert.PageSize := PageSize;
    sbVert.Max := OverHeight;
    sbVert.PageSize := PageSize;
    sbVert.Visible := True;
  end;
end;

end.
