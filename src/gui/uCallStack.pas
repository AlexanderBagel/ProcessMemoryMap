////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uCallStack.pas
//  * Purpose   : Утилита демангла CallStack от ProcessExpplorer
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.5.35
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uCallStack;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.ComCtrls, Vcl.ExtCtrls, Vcl.StdCtrls, Vcl.Menus,
  System.Actions, Vcl.ActnList, Generics.Collections,
  System.ImageList, Vcl.ImgList,

  VirtualTrees.BaseAncestorVCL,
  VirtualTrees.BaseTree,
  VirtualTrees.AncestorVCL,
  VirtualTrees,
  VirtualTrees.Types,

  uBaseForm,
  uDumpDisplayUtils,
  uRegionProperties,
  uSettings,

  MemoryMap.DebugMapData,
  MemoryMap.Core,
  MemoryMap.Symbols,
  MemoryMap.Threads,
  MemoryMap.Utils,

  RawScanner.Core,
  RawScanner.ModulesData,
  RawScanner.CoffDwarf,
  RawScanner.SymbolStorage,
  RawScanner.Utils;

type
  TThreadNodeType = (ntNone, nt32Stack, nt64Stack, nt32Seh, nt64Seh, ntCustom32, ntCustom64);
  PThreadNodeData = ^TThreadNodeData;
  TThreadNodeData = record
    AType: TThreadNodeType;
    ThreadID, Level: Integer;
  end;

  TdlgCallStack = class(TBaseAppForm)
    Splitter: TSplitter;
    lvStack: TListView;
    ActionList: TActionList;
    acRefresh: TAction;
    acCopyAddr: TAction;
    acCopyLine: TAction;
    acCopyAll: TAction;
    pmStack: TPopupMenu;
    acCopyAddr1: TMenuItem;
    acCopyLine1: TMenuItem;
    N1: TMenuItem;
    acCopyAll1: TMenuItem;
    pmThreads: TPopupMenu;
    Refresf1: TMenuItem;
    acImportProcessExplorer: TAction;
    ImportProcessExplorerCallStack1: TMenuItem;
    tvThread: TVirtualStringTree;
    acViewRaw: TAction;
    mnuRSeparator: TMenuItem;
    DisplayRawData1: TMenuItem;
    memRaw: TMemo;
    pmRaw: TPopupMenu;
    CopyAll1: TMenuItem;
    mnuDSeparator: TMenuItem;
    DisplayRawData2: TMenuItem;
    acRawCopy: TAction;
    acRawSelectAll: TAction;
    acViewDemangled: TAction;
    SelectAll1: TMenuItem;
    DisplayDemangledData1: TMenuItem;
    DisplayRawData3: TMenuItem;
    acSwitch64: TAction;
    acSwitch32: TAction;
    mnuSwitchSeparator: TMenuItem;
    Switchtox321: TMenuItem;
    Switchtox641: TMenuItem;
    il16: TImageList;
    procedure acRefreshExecute(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure acCopyAddrExecute(Sender: TObject);
    procedure acCopyAddrUpdate(Sender: TObject);
    procedure acCopyAllExecute(Sender: TObject);
    procedure acCopyAllUpdate(Sender: TObject);
    procedure acCopyLineExecute(Sender: TObject);
    procedure acCopyLineUpdate(Sender: TObject);
    procedure lvStackCustomDrawItem(Sender: TCustomListView; Item: TListItem;
      State: TCustomDrawState; var DefaultDraw: Boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormKeyPress(Sender: TObject; var Key: Char);
    procedure tvThreadGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
    procedure tvThreadAddToSelection(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure acViewRawExecute(Sender: TObject);
    procedure acRawCopyExecute(Sender: TObject);
    procedure acRawSelectAllExecute(Sender: TObject);
    procedure acViewRawUpdate(Sender: TObject);
    procedure acViewDemangledUpdate(Sender: TObject);
    procedure lvStackDblClick(Sender: TObject);
    procedure acImportProcessExplorerUpdate(Sender: TObject);
    procedure acImportProcessExplorerExecute(Sender: TObject);
    procedure lvStackInfoTip(Sender: TObject; Item: TListItem;
      var InfoTip: string);
    procedure acSwitch32Update(Sender: TObject);
    procedure acSwitch64Execute(Sender: TObject);
    procedure tvThreadGetImageIndex(Sender: TBaseVirtualTree;
      Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
      var Ghosted: Boolean; var ImageIndex: TImageIndex);
    procedure tvThreadMeasureItem(Sender: TBaseVirtualTree;
      TargetCanvas: TCanvas; Node: PVirtualNode; var NodeHeight: Integer);
  private
    FThreads: TThreads;
    FCurrentStackData: TStringList;
    FCustomStacks: TObjectList<TStringList>;
    FCurrentMode: TThreadNodeType;
    procedure DoConvert(Image64: Boolean);
    function GetLineText(AItem:TListItem): string;
    procedure FillThreads;
    procedure Reinit;
    procedure UpdateColumnMaxLen;
    procedure UpdateTreeHeaderHeight;
  protected
    procedure ChangeScale(M, D: Integer; isDpiChange: Boolean); override;
  end;

var
  dlgCallStack: TdlgCallStack;

implementation

uses
  Clipbrd,
  Math,
  PsAPI,
  CommCtrl;

const
  Overlay32 = 0;
  Overlay64 = 1;

{$R *.dfm}

procedure TdlgCallStack.acCopyAddrExecute(Sender: TObject);
begin
  Clipboard.AsText := lvStack.Selected.Caption;
end;

procedure TdlgCallStack.acCopyAddrUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled :=
    (lvStack.Selected <> nil) and
    (lvStack.Selected.Caption <> '');
end;

procedure TdlgCallStack.acCopyAllExecute(Sender: TObject);
var
  Buff: string;
  AItem: TListItem;
begin
  Buff := '';
  for AItem in lvStack.Items do
    Buff := Buff + GetLineText(AItem) + sLineBreak;
  Clipboard.AsText := TrimRight(Buff);
end;

procedure TdlgCallStack.acCopyAllUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := lvStack.Items.Count > 0;
end;

procedure TdlgCallStack.acCopyLineExecute(Sender: TObject);
begin
  Clipboard.AsText := GetLineText(lvStack.Selected);
end;

procedure TdlgCallStack.acCopyLineUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := lvStack.Selected <> nil;
end;

procedure TdlgCallStack.acImportProcessExplorerExecute(Sender: TObject);
var
  NewStack: TStringList;
  Root: PVirtualNode;
  Data: PThreadNodeData;
begin
  NewStack := TStringList.Create;
  NewStack.Text := Clipboard.AsText;
  Root := tvThread.AddChild(nil);
  Data := Root.GetData;
  if MemoryMapCore.Process64 then
    Data.AType := ntCustom64
  else
    Data.AType := ntCustom32;
  Data.ThreadID := FCustomStacks.Add(NewStack);
  tvThread.Selected[Root] := True;
end;

procedure TdlgCallStack.acImportProcessExplorerUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := Clipboard.HasFormat(CF_TEXT);
end;

procedure TdlgCallStack.acRawCopyExecute(Sender: TObject);
begin
  memRaw.CopyToClipboard;
end;

procedure TdlgCallStack.acRawSelectAllExecute(Sender: TObject);
begin
  memRaw.SelectAll;
end;

procedure TdlgCallStack.acRefreshExecute(Sender: TObject);
begin
  Reinit;
end;

procedure TdlgCallStack.acSwitch32Update(Sender: TObject);
begin
  mnuSwitchSeparator.Visible := not MemoryMapCore.Process64 and
    (FCurrentMode in [ntCustom32, ntCustom64]);
  TAction(Sender).Visible := mnuSwitchSeparator.Visible and
    (TThreadNodeType(TAction(Sender).Tag) <> FCurrentMode);
end;

procedure TdlgCallStack.acSwitch64Execute(Sender: TObject);
var
  SelNode: PVirtualNode;
  Data: PThreadNodeData;
begin
  SelNode := tvThread.GetFirstSelected;
  if SelNode = nil then Exit;
  Data := SelNode.GetData;
  Data.AType := TThreadNodeType(TAction(Sender).Tag);
  FCurrentMode := Data.AType;
  tvThread.InvalidateNode(SelNode);
  DoConvert(FCurrentMode = ntCustom64);
end;

procedure TdlgCallStack.acViewDemangledUpdate(Sender: TObject);
begin
  acViewDemangled.Visible := acViewRaw.Checked;
  acViewDemangled.Enabled := acViewDemangled.Visible;
  mnuDSeparator.Visible := acViewDemangled.Visible;
end;

procedure TdlgCallStack.acViewRawExecute(Sender: TObject);
begin
  DisableAlign;
  if acViewRaw.Checked then
  begin
    memRaw.Align := alClient;
    lvStack.Align := alNone;
    memRaw.Visible := True;
    memRaw.BringToFront;
    memRaw.SetFocus;
  end
  else
  begin
    memRaw.Align := alNone;
    lvStack.Align := alClient;
    memRaw.Visible := False;
    lvStack.SetFocus;
  end;
  EnableAlign;
end;

procedure TdlgCallStack.acViewRawUpdate(Sender: TObject);
begin
  acViewRaw.Visible := not acViewRaw.Checked;
  acViewRaw.Enabled := acViewRaw.Visible;
  mnuRSeparator.Visible := acViewRaw.Visible;
end;

procedure TdlgCallStack.ChangeScale(M, D: Integer; isDpiChange: Boolean);
begin
  inherited;
  if isDpiChange then
    UpdateTreeHeaderHeight;
end;

procedure TdlgCallStack.DoConvert(Image64: Boolean);

  function GetFunction(const Value: string): string;
  var
    Index: Integer;
  begin
    Index := Pos('+', Value);
    if Index > 0 then
      Result := Trim(Copy(Value, 1, Index - 1))
    else
      Result := Value;
  end;

  function Module(const Value: string): string;
  var
    Index: Integer;
  begin
    Index := Pos('!', Value);
    if Index > 0 then
      Result := Copy(Value, 1, Index - 1)
    else
      Result := GetFunction(Value);
  end;

  function GetFunctionAddr(const ModuleName, FuncName: string;
    out PEImage: TRawPEImage): ULONG_PTR;
  var
    Index: Integer;
    ProcData: TExportChunk;
  begin
    Result := 0;
    PEImage := nil;
    Index := RawScannerCore.Modules.GetModuleByName(ModuleName, Image64);
    if Index < 0 then Exit;
    PEImage := RawScannerCore.Modules.Items[Index];
    if FuncName = '' then
      Exit(PEImage.ImageBase);
    if RawScannerCore.Modules.GetProcData(
      ModuleName, FuncName, Image64, ProcData, PEImage.ImageBase) then
      Result := ProcData.FuncAddrVA;
  end;

  function RemoveUNameFromFName(const AUnitName, AFuncName: string): string;
  var
    ModuleNameWithoutExt: string;
  begin
    ModuleNameWithoutExt := ChangeFileExt(AUnitName, '.');
    if AFuncName.StartsWith(ModuleNameWithoutExt) then
      Result := Copy(AFuncName, Length(ModuleNameWithoutExt) + 1, Length(AFuncName))
    else
      Result := AFuncName;
  end;

  function GetDwarf(PEImage: TRawPEImage; AddrVa: ULONG_PTR;
    var AUnitName: string; var ALineNumber: Integer): string;
  var
    I, Count: Integer;
    ExpData: TSymbolData;
    Dwarf, Coff: string;
    DwarfData: TDebugInformationEntry;
    DwarfInfoUnit: TDwarfInfoUnit;

    function CheckAddrEqual: string;
    begin
      if AddrVa <> ExpData.AddrVA then
        Result := '+0x' + IntToHex(AddrVA - ExpData.AddrVA, 1)
      else
        Result := '';
    end;

  begin
    Result := '';
    Count := SymbolStorage.GetDataCountAtAddr(AddrVa);

    // если адрес в середине функции и нам нужно вытащить её название
    // тогда принудительно запускаем один запрос данных,
    // GetExportAtAddr вернет данные по которым можно вытянуть оффсет
    if Count = 0 then
      Count := 1;

    for I := 0 to Count - 1 do
    begin
      if SymbolStorage.GetExportAtAddr(AddrVa, stExport, ExpData, I) then
      begin
        case ExpData.DataType of
          sdtCoffFunction:
          begin
            Coff := GetSymbolDescription(ExpData, False);
            if Settings.DemangleNames then
              Coff := DemangleName(Coff, ExpData.DataType = sdtCoffFunction);
            Coff := Coff + CheckAddrEqual;
          end;
          sdtDwarfProc:
          begin
            DwarfInfoUnit := PEImage.DwarfDebugInfo.UnitInfos[ExpData.Binary.ListIndex];
            DwarfData := DwarfInfoUnit.Data[ExpData.Binary.Param];
            Result := DwarfData.AName + CheckAddrEqual;
            AUnitName := DwarfInfoUnit.UnitName;
            Break;
          end
        else
          Result := GetSymbolDescription(ExpData, False) + CheckAddrEqual;
        end;
      end;
    end;

    if Dwarf <> '' then
      Exit(Dwarf);

    if Result = '' then
      Result := Coff;
  end;

  function DumpDebug(PEImage: TRawPEImage; AddrVA: UInt64;
    var FuncName: string; out AUnitName: string; out ALineNumber: Integer): Boolean;
  const
    LineSearchLimit = 42; // 3 * MaxOpcodeLen
  var
    FunctionUnitName: string;
    ExpData: TSymbolData;
    LineData: TLineData;
    DwarfLinesUnit: TDwarfLinesUnit;
  begin
    AUnitName := '';
    ALineNumber := -1;
    Result := False;
    if MemoryMapCore.DebugMapData.ModuleLoaded(PEImage.ImageName) then
    begin
      ALineNumber := MemoryMapCore.DebugMapData.GetLineNumberAtAddrForced(AddrVA, LineSearchLimit, AUnitName);
      FuncName := MemoryMapCore.DebugMapData.GetDescriptionAtAddrWithOffset(AddrVA, PEImage.ImageName, False);
      FuncName := RemoveUNameFromFName(AUnitName, FuncName);
      Result := True;
      Exit;
    end;

    if ditDwarfDie in PEImage.DebugData then
    begin
      FuncName := GetDwarf(PEImage, AddrVA, FunctionUnitName, ALineNumber);
      Result := True;
    end;

    if ditDwarfLines in PEImage.DebugData then
    begin
      if SymbolStorage.GetDwarfLineAtAddr(AddrVA, LineSearchLimit, ExpData) then
      begin
        DwarfLinesUnit := PEImage.DwarfDebugInfo.UnitLines[ExpData.Binary.ListIndex];
        LineData := DwarfLinesUnit.Lines[ExpData.Binary.Param];
        AUnitName := Trim(DwarfLinesUnit.GetFilePath(LineData.FileId));
        ALineNumber := LineData.Line;
      end;
      Result := True;
    end;

    if AUnitName = '' then
      AUnitName := FunctionUnitName;
  end;

var
  I, LineNumber: Integer;
  FuncAddr, BaseAddr: UINT_PTR;
  FuncOffset: Cardinal;
  Line, ModuleName, FuncName, AUnitName: string;
  Item: TListItem;
  Failed, DebugPresent: Boolean;
  PEImage: TRawPEImage;
begin
  lvStack.Items.BeginUpdate;
  try
    lvStack.Items.Clear;

    for I := 0 to FCurrentStackData.Count - 1 do
    begin
      Item := lvStack.Items.Add;
      Line := Trim(FCurrentStackData[I]);
      Line := StringReplace(Line, ' ', '', [rfReplaceAll]);
      ModuleName := Module(Line);
      if ModuleName = '' then
      begin
        Item.Caption := Line;
        Continue;
      end;

      Delete(Line, 1, Length(ModuleName));
      if (Line <> '') and (Line[1] = '!') then
        Delete(Line, 1, 1);
      FuncName := GetFunction(Line);

      // контроль деманглинга имени функции экспортируемой по ординалу
      // SymGetSymFromAddr возвращает такие функции с префиксом Ordinal
      // MemoryMap.Symbols экранирует их символом # и для этого режима
      // данный контроль будет избыточен
      if (FCurrentMode in [ntCustom32, ntCustom64]) and FuncName.StartsWith('Ordinal') then
        BaseAddr := GetFunctionAddr(ModuleName, '#' + Copy(FuncName, 8, Length(FuncName)), PEImage)
      else
        BaseAddr := GetFunctionAddr(ModuleName, FuncName, PEImage);

      Delete(Line, 1, Length(FuncName));
      Failed := not TryStrToUInt(Line, FuncOffset);
      Item.SubItems.Add(ModuleName);

      // проверка на наличие смещения от начала функции
      // и наличия адреса функции
      if Failed or (BaseAddr = 0) then
      begin
        Item.SubItems.Add(EmptyStr);
        Item.SubItems.Add(FuncName + Line);
        Item.Data := Pointer(1);
        Continue;
      end;

      FuncAddr := BaseAddr + FuncOffset;
      Item.Caption := '0x' + IntToHex(FuncAddr);

      DebugPresent := DumpDebug(PEImage, FuncAddr, FuncName, AUnitName, LineNumber);
      if not DebugPresent then
      begin
        LineNumber := -1;
        if FuncName = '' then
          FuncName := '<ImageBage>';
        FuncName := FuncName + Line;
      end;

      if LineNumber <= 0 then
      begin
        Item.SubItems.Add(AUnitName);
        Item.SubItems.Add(FuncName);
        if DebugPresent then
        begin
          if FuncName = '' then
            Item.Data := Pointer(1)
          else
            Item.Data := Pointer(2);
        end;
      end
      else
      begin
        FuncName := GetFunction(FuncName);
        Item.SubItems.Add(AUnitName);
        Item.SubItems.Add(FuncName);
        Item.SubItems.Add(IntToStr(LineNumber));
        Item.Data := Pointer(3);
      end;

    end;

  finally
    lvStack.Items.EndUpdate;
  end;
  UpdateColumnMaxLen;
end;

procedure TdlgCallStack.FillThreads;
var
  Root, FirstRoot: PVirtualNode;
  Data: PThreadNodeData;
  Child: PVirtualNode;
  SehIdx: Integer;

  function GetNodeType(const Entry: TThreadStackEntry): TThreadNodeType;
  begin
    if Entry.Wow64 then
      Result := nt32Stack
    else
      Result := nt64Stack;
  end;

  procedure FillSEH(CurrentID: Integer);
  var
    FirstFound: Boolean;
  begin
    FirstFound := True;
    while SehIdx < FThreads.SEHEntries.Count - 1 do
    begin
      if FThreads.SEHEntries[SehIdx].ThreadID <> CurrentID then Exit;
      if FirstFound then
      begin
        Child := tvThread.AddChild(Root);
        Data := Child.GetData;
        Data.AType := nt32Seh;
        Data.ThreadID := CurrentID;
        Data.Level := 1;
        FirstFound := False;
      end;
      Inc(SehIdx);
    end;
  end;

var
  I, CurrentID: Integer;
  CurrentType, NextType: TThreadNodeType;
  PaintOptions: TVTPaintOptions;
begin
  SehIdx := 0;
  tvThread.BeginUpdate;
  try
    tvThread.Clear;
    tvThread.NodeDataSize := SizeOf(TThreadNodeData);
    CurrentID := 0;
    CurrentType := ntCustom32;
    FirstRoot := nil;
    for I := 0 to FThreads.ThreadStackEntries.Count - 1 do
    begin
      // заполняем рута
      if CurrentID <> FThreads.ThreadStackEntries[I].ThreadID then
      begin
        // если новый рут, то к предыдущему докидываем SEH если есть
        if CurrentID <> 0 then
          FillSEH(CurrentID);
        CurrentID := FThreads.ThreadStackEntries[I].ThreadID;
        CurrentType := GetNodeType(FThreads.ThreadStackEntries[I]);
        Root := tvThread.AddChild(nil);
        if FirstRoot = nil then
          FirstRoot := Root;
        Data := Root.GetData;
        Data.AType := CurrentType;
        Data.ThreadID := CurrentID;
        Data.Level := 0;
        Continue;
      end;
      // если появился новый тип потока, переключаемся на него
      NextType := GetNodeType(FThreads.ThreadStackEntries[I]);
      if NextType <> CurrentType then
      begin
        // если присутствует 32 битный стек нити
        // переключаем рута на него
        Data := Root.GetData;
        Data.AType := NextType;
        Child := tvThread.AddChild(Root);
        Data := Child.GetData;
        Data.AType := CurrentType;
        Data.ThreadID := CurrentID;
        Data.Level := 1;
        CurrentType := NextType;
      end;
    end;
    if CurrentID <> 0 then
      FillSEH(CurrentID);

    PaintOptions := DefaultPaintOptions;
    Include(PaintOptions, toUseExplorerTheme);
    if FirstRoot = Root then
      Exclude(PaintOptions, toShowTreeLines);

    tvThread.TreeOptions.PaintOptions := PaintOptions;
  finally
    tvThread.EndUpdate;
  end;
  tvThread.Selected[FirstRoot] := True;
end;

procedure TdlgCallStack.FormClose(Sender: TObject;
  var Action: TCloseAction);
begin
   Action := caFree;
   dlgCallStack := nil;
end;

procedure TdlgCallStack.FormCreate(Sender: TObject);
begin
  FThreads := TThreads.Create;
  FCurrentStackData := TStringList.Create;
  FCustomStacks := TObjectList<TStringList>.Create;
  UpdateTreeHeaderHeight;
  il16.Overlay(3, Overlay32);
  il16.Overlay(4, Overlay64);
  Reinit;
end;

procedure TdlgCallStack.FormDestroy(Sender: TObject);
begin
  FThreads.Free;
  FCurrentStackData.Free;
  FCustomStacks.Free;
end;

procedure TdlgCallStack.FormKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #27 then Close;
end;

function TdlgCallStack.GetLineText(AItem: TListItem): string;
var
  I: Integer;
begin
  Result :=
    Format('%' + IntToStr(lvStack.Columns[0].Tag) + 's |', [AItem.Caption]);
  for I := 0 to AItem.SubItems.Count - 1 do
    Result := Result +
      Format('%' + IntToStr(lvStack.Columns[I + 1].Tag) + 's |', [AItem.SubItems[I]]);
end;

procedure TdlgCallStack.lvStackCustomDrawItem(Sender: TCustomListView;
  Item: TListItem; State: TCustomDrawState; var DefaultDraw: Boolean);
begin
  case Integer(Item.Data) of
    1: Sender.Canvas.Brush.Color := $00C7C7FE;
    2: Sender.Canvas.Brush.Color := $00B4F5FF;
    3: Sender.Canvas.Brush.Color := $00C1E5C4;
  end;
end;

procedure TdlgCallStack.lvStackDblClick(Sender: TObject);
var
  AddrVA: UInt64;
begin
  if lvStack.Selected = nil then Exit;
  if not TryStrToUInt64(lvStack.Selected.Caption, AddrVA) then Exit;
  dlgRegionProps := TdlgRegionProps.Create(Application);
  dlgRegionProps.ShowPropertyAtAddr(Pointer(AddrVA));
end;

procedure TdlgCallStack.lvStackInfoTip(Sender: TObject; Item: TListItem;
  var InfoTip: string);
begin
  if Item.Data = nil then
  begin
    InfoTip := '';
    Application.CancelHint;
  end
  else
    InfoTip := FCurrentStackData[Item.Index];
end;

procedure TdlgCallStack.Reinit;
var
  Process: THandle;
  Symbols: TSymbols;
  ProcessLock: TProcessLockHandleList;
  ThreadStackEntry: TThreadStackEntry;
  SEHEntry: TSEHEntry;
  MBI: TMemoryBasicInformation;
  dwLength: NativeUInt;
  I: Integer;
  OwnerName: array [0..MAX_PATH - 1] of Char;
begin
  FCustomStacks.Clear;
  Process := OpenProcess(
    PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
    False, MemoryMapCore.PID);
  if Process = 0 then
    RaiseLastOSError;
  try
    Symbols := TSymbols.Create(Process);
    try
      Symbols.Undecorate := False;
      ProcessLock := nil;
      if MemoryMapCore.SuspendProcessBeforeScan then
        ProcessLock := SuspendProcess(MemoryMapCore.PID);
      try
        FThreads.Update(MemoryMapCore.PID, Process);

        dwLength := SizeOf(TMemoryBasicInformation);
        for I := 0 to FThreads.ThreadStackEntries.Count - 1 do
        begin
          ThreadStackEntry := FThreads.ThreadStackEntries[I];
          if not CheckAddr(ThreadStackEntry.Data.AddrFrame.Offset) then
            Continue;
          VirtualQueryEx(Process, Pointer(ThreadStackEntry.Data.AddrPC.Offset), MBI, dwLength);
          if GetMappedFileName(Process, MBI.AllocationBase, @OwnerName[0], MAX_PATH) > 0 then
          begin
            ThreadStackEntry.SetFuncName(
              Symbols.GetDescriptionAtAddr(
                ULONG_PTR(ThreadStackEntry.Data.AddrPC.Offset),
                ULONG_PTR(MBI.AllocationBase),
              NormalizePath(string(OwnerName))));
            FThreads.ThreadStackEntries[I] := ThreadStackEntry;
          end;
        end;

        for I := 0 to FThreads.SEHEntries.Count - 1 do
        begin
          SEHEntry := FThreads.SEHEntries[I];
          if not CheckAddr(SEHEntry.Handler) then
            Continue;
          VirtualQueryEx(Process, SEHEntry.Handler, MBI, dwLength);
          if GetMappedFileName(Process, MBI.AllocationBase, @OwnerName[0], MAX_PATH) > 0 then
          begin
            SEHEntry.SetHandlerName(
              Symbols.GetDescriptionAtAddr(
                ULONG_PTR(SEHEntry.Handler),
                ULONG_PTR(MBI.AllocationBase),
              NormalizePath(string(OwnerName))));
            FThreads.SEHEntries[I] := SEHEntry;
          end;
        end;

      finally
        if MemoryMapCore.SuspendProcessBeforeScan then
          ResumeProcess(ProcessLock);
      end;
    finally
      Symbols.Free;
    end;
  finally
    CloseHandle(Process);
  end;
  FillThreads;
end;

procedure TdlgCallStack.tvThreadAddToSelection(Sender: TBaseVirtualTree;
  Node: PVirtualNode);

  procedure Add(const Value: ShortString);
  begin
    if Value <> '' then
      FCurrentStackData.Add(string(Value));
  end;

var
  I, CurrentID: Integer;
  Data: PThreadNodeData;
begin
  if Assigned(Node) then
  begin
    Data := Node.GetData;
    CurrentID := Data.ThreadID;
    FCurrentMode := Data.AType;
    FCurrentStackData.Clear;
    case FCurrentMode of
      nt32Stack, nt64Stack:
      begin
        for I := 0 to FThreads.ThreadStackEntries.Count - 1 do
          if FThreads.ThreadStackEntries[I].ThreadID = CurrentID then
            if FThreads.ThreadStackEntries[I].Wow64 = (Data.AType = nt32Stack) then
              Add(FThreads.ThreadStackEntries[I].FuncName);
      end;
      nt32Seh, nt64Seh:
      begin
        for I := 0 to FThreads.SEHEntries.Count - 1 do
          if FThreads.SEHEntries[I].ThreadID = CurrentID then
            Add(FThreads.SEHEntries[I].HandlerName);
      end;
      ntCustom32, ntCustom64:
        FCurrentStackData.Assign(FCustomStacks[CurrentID]);
    end;

    memRaw.Lines.Assign(FCurrentStackData);
    DoConvert(FCurrentMode in [nt64Stack, nt64Seh, ntCustom64]);
  end;
end;

procedure TdlgCallStack.tvThreadGetImageIndex(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Kind: TVTImageKind; Column: TColumnIndex;
  var Ghosted: Boolean; var ImageIndex: TImageIndex);
var
  Data: PThreadNodeData;
begin
  Data := Node.GetData;
  if Kind = ikOverlay then
  begin
    if Data.AType in [nt32Stack, nt32Seh, ntCustom32] then
    begin
      if MemoryMapCore.Process64 then
        ImageIndex := Overlay32;
    end
    else
      if not MemoryMapCore.Process64 then
        ImageIndex := Overlay64;
  end
  else
    if Kind in [ikNormal, ikSelected] then
      case Data.AType of
        nt32Stack, nt64Stack: ImageIndex := 0;
        nt32Seh, nt64Seh: ImageIndex := 1;
        ntCustom32, ntCustom64: ImageIndex := 2;
      end;
end;

procedure TdlgCallStack.tvThreadGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; TextType: TVSTTextType;
  var CellText: string);
var
  NodeData: PThreadNodeData;
begin
  NodeData := Node.GetData;
  if NodeData.Level = 0 then
  begin
    case NodeData.AType of
      ntCustom32: CellText := Format('Custom №%d (x32)', [NodeData.ThreadID]);
      ntCustom64: CellText := Format('Custom №%d (x64)', [NodeData.ThreadID]);
    else
      CellText := Format('%d (x%d)', [NodeData.ThreadID, 16 shl Byte(NodeData.AType)]);
    end;
  end
  else
    case NodeData.AType of
      nt32Stack: CellText := 'x32 stack';
      nt64Stack: CellText := 'x64 stack';
      nt32Seh: CellText := 'x32 SEH';
      nt64Seh: CellText := 'x64 SEH';
    end;
end;

procedure TdlgCallStack.tvThreadMeasureItem(Sender: TBaseVirtualTree;
  TargetCanvas: TCanvas; Node: PVirtualNode; var NodeHeight: Integer);
begin
  NodeHeight := MulDiv(18, FCurrentPPI, USER_DEFAULT_SCREEN_DPI);
end;

procedure TdlgCallStack.UpdateColumnMaxLen;
var
  I, A: Integer;
  Item: TListItem;
begin
  for I := 0 to lvStack.Columns.Count - 1 do
    lvStack.Columns[I].Tag := 0;
  for I := 0 to lvStack.Items.Count - 1 do
  begin
    Item := lvStack.Items[I];
    with lvStack.Columns[0] do
      Tag := Max(Tag, Length(Item.Caption) + 1);
    for A := 0 to Item.SubItems.Count - 1 do
      with lvStack.Columns[A + 1] do
        Tag := Max(Tag, Length(Item.SubItems[A]) + 1);
  end;
end;

procedure TdlgCallStack.UpdateTreeHeaderHeight;
var
  R: TRect;
begin
  GetWindowRect(SendMessage(lvStack.Handle, LVM_GETHEADER, 0, 0), R);
  tvThread.Header.Height := R.Height;
  tvThread.ReinitNode(nil, True);
end;

end.
