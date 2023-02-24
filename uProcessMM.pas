////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uProcessMM.pas
//  * Purpose   : Главная форма проекта
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2016, 2023.
//  * Version   : 1.4.26
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uProcessMM;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.Menus, VirtualTrees, Vcl.ComCtrls, Vcl.StdCtrls, Vcl.ExtCtrls,
  Vcl.ImgList, Winapi.TlHelp32, Winapi.ShellAPI, Winapi.CommCtrl,
  Vcl.Clipbrd, System.Actions, Vcl.ActnList, Vcl.PlatformDefaultStyleActnCtrls,
  Vcl.ActnMan, System.ImageList,

  MemoryMap.Core,
  MemoryMap.RegionData,
  MemoryMap.Utils,
  MemoryMap.Threads,
  MemoryMap.Heaps,

  RawScanner.Core,
  RawScanner.ApiSet,
  RawScanner.Types,
  RawScanner.Wow64,

  uDisplayUtils,
  uIPC,
  uProgress;

type
  TdlgProcessMM = class(TForm)
    MainMenu: TMainMenu;
    mnuFile: TMenuItem;
    mnuSelectProcess: TMenuItem;
    N1: TMenuItem;
    mnuOpen: TMenuItem;
    mnuSave: TMenuItem;
    N2: TMenuItem;
    mnuRunAsAdmin: TMenuItem;
    N3: TMenuItem;
    mnuExit: TMenuItem;
    gbSummary: TGroupBox;
    imgProcess: TImage;
    lblProcessName: TLabel;
    lblProcessNameData: TLabel;
    lblProcessPID: TLabel;
    lblProcessPIDData: TLabel;
    stMemoryMap: TVirtualStringTree;
    mnuEdit: TMenuItem;
    mnuCopyAddress: TMenuItem;
    mnuCopySelected: TMenuItem;
    mnuShowExport: TMenuItem;
    mnuOptions: TMenuItem;
    mnuExpand: TMenuItem;
    mnuCollapse: TMenuItem;
    N5: TMenuItem;
    mnuSettings: TMenuItem;
    mnuHelp: TMenuItem;
    mnuAbout: TMenuItem;
    MainMenuImageList: TImageList;
    SavePMMDialog: TSaveDialog;
    mnuRefresh: TMenuItem;
    N7: TMenuItem;
    OpenPMMDialog: TOpenDialog;
    lvSummary: TVirtualStringTree;
    PopupMenu: TPopupMenu;
    CopyAddress1: TMenuItem;
    CopySelected1: TMenuItem;
    N8: TMenuItem;
    Find1: TMenuItem;
    N9: TMenuItem;
    ExpandAll1: TMenuItem;
    CollapseAll1: TMenuItem;
    mnuSearch: TMenuItem;
    mnuCompare: TMenuItem;
    mnuQuery: TMenuItem;
    mnuFind: TMenuItem;
    N4: TMenuItem;
    mnuProprety: TMenuItem;
    Queryaddress2: TMenuItem;
    N6: TMenuItem;
    Regionproperties1: TMenuItem;
    mnuShowAddr: TMenuItem;
    ActionManager: TActionManager;
    acSelectProcess: TAction;
    acOpen: TAction;
    acCompare: TAction;
    acSave: TAction;
    acRunAsAdmin: TAction;
    acExit: TAction;
    acRefresh: TAction;
    acCopyAddress: TAction;
    acCopySelected: TAction;
    acRegionProps: TAction;
    acSearchAddress: TAction;
    acQueryAddr: TAction;
    acSearchData: TAction;
    acShowExports: TAction;
    acDumpAddr: TAction;
    acDumpRegion: TAction;
    acExpandAll: TAction;
    acCollapseAll: TAction;
    acSettings: TAction;
    acAbout: TAction;
    DumpRegion1: TMenuItem;
    N10: TMenuItem;
    mnuUtils: TMenuItem;
    DumpAddress1: TMenuItem;
    DumpRegion2: TMenuItem;
    SaveDMPDialog: TSaveDialog;
    acFillMMList: TAction;
    N12: TMenuItem;
    FillAddrListInfo1: TMenuItem;
    FindPatchedData1: TMenuItem;
    acFindPachedData: TAction;
    N13: TMenuItem;
    N14: TMenuItem;
    mnuShowKnonData: TMenuItem;
    acShowKnown: TAction;
    FillAddrListInfo2: TMenuItem;
    acGenerateMML: TAction;
    GenerateMMLfromMAP1: TMenuItem;
    Debugdata1: TMenuItem;
    acDebugInfo: TAction;
    // Actions
    procedure acAboutExecute(Sender: TObject);
    procedure acCollapseAllExecute(Sender: TObject);
    procedure acCompareExecute(Sender: TObject);
    procedure acCompareUpdate(Sender: TObject);
    procedure acCopyAddressExecute(Sender: TObject);
    procedure acCopySelectedExecute(Sender: TObject);
    procedure acDumpAddrExecute(Sender: TObject);
    procedure acExitExecute(Sender: TObject);
    procedure acExpandAllExecute(Sender: TObject);
    procedure acOpenExecute(Sender: TObject);
    procedure acQueryAddrExecute(Sender: TObject);
    procedure acRefreshExecute(Sender: TObject);
    procedure acRegionPropsExecute(Sender: TObject);
    procedure acRunAsAdminExecute(Sender: TObject);
    procedure acSaveExecute(Sender: TObject);
    procedure acSearchAddressExecute(Sender: TObject);
    procedure acSearchDataExecute(Sender: TObject);
    procedure acSelectProcessExecute(Sender: TObject);
    procedure acSettingsExecute(Sender: TObject);
    procedure acShowExportsExecute(Sender: TObject);
    // Other...
    procedure FormCreate(Sender: TObject);
    procedure stMemoryMapGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
    procedure stMemoryMapBeforeItemErase(Sender: TBaseVirtualTree;
      TargetCanvas: TCanvas; Node: PVirtualNode; ItemRect: TRect;
      var ItemColor: TColor; var EraseAction: TItemEraseAction);
    procedure lvSummaryCustomDrawItem(Sender: TCustomListView; Item: TListItem;
      State: TCustomDrawState; var DefaultDraw: Boolean);
    procedure lvSummaryGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
    procedure lvSummaryBeforeItemErase(Sender: TBaseVirtualTree;
      TargetCanvas: TCanvas; Node: PVirtualNode; ItemRect: TRect;
      var ItemColor: TColor; var EraseAction: TItemEraseAction);
    procedure lvSummaryNodeClick(Sender: TBaseVirtualTree;
      const HitInfo: THitInfo);
    procedure FormKeyPress(Sender: TObject; var Key: Char);
    procedure acSaveUpdate(Sender: TObject);
    procedure acDumpRegionExecute(Sender: TObject);
    procedure acDumpRegionUpdate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure stMemoryMapNodeDblClick(Sender: TBaseVirtualTree;
      const HitInfo: THitInfo);
    procedure acFillMMListExecute(Sender: TObject);
    procedure acShowKnownExecute(Sender: TObject);
    procedure acGenerateMMLUpdate(Sender: TObject);
    procedure acGenerateMMLExecute(Sender: TObject);
    procedure acFindPachedDataUpdate(Sender: TObject);
    procedure acFindPachedDataExecute(Sender: TObject);
    procedure imgProcessClick(Sender: TObject);
    procedure acDebugInfoExecute(Sender: TObject);
  private
    FirstRun, ProcessOpen, MapPresent, FirstSelectProcess: Boolean;
    NodeDataArrayLength: Integer;
    NodeDataArray: array of TNodeData;
    SearchString: string;
    SearchPosition: Integer;
    IPCServerMMFName: string;
    {$IFDEF WIN32}
    IPCServer: TIPCServer;
    {$ENDIF}
    procedure AddShieldIconToMenu;
    procedure CalcNodeDataArraySize;
    procedure InternalOpenProcess(AMap: TMemoryMap;
      PID: DWORD; const ProcessName: string);
    procedure FillTreeView;
    function Search(const Value: string): Boolean;
    function GetSelectedNodeData: PNodeData;
    procedure OnGetWow64Heaps(Value: THeap);
    procedure OnInitProgress(const Step: string; APecent: Integer);
  public
    function Reconnect: Boolean;
  end;

var
  dlgProcessMM: TdlgProcessMM;

implementation

uses
  uSelectAddress,
  uRegionProperties,
  uSelectProcess,
  uExportList,
  uComparator,
  uFindData,
  uSettings,
  uUtils,
  uDump,
  uAbout,
  uMemoryMapListInfo,
  uProcessReconnect,
  uKnownData,
  uPatchDetect,
  uPluginManager,
  uDebugInfoDlg,
  Shell.TaskBarListProgress;

const
  RootCaption = 'Process Memory Map';
  DumpFailed = 'Dump filed';
  DumpSuccess = 'Dumped %d bytes';

{$R *.dfm}

procedure TdlgProcessMM.acAboutExecute(Sender: TObject);
begin
  dlgAbout := TdlgAbout.Create(Self);
  try
    dlgAbout.ShowModal;
  finally
    dlgAbout.Release;
  end;
end;

procedure TdlgProcessMM.acCollapseAllExecute(Sender: TObject);
begin
  stMemoryMap.FullCollapse;
end;

procedure TdlgProcessMM.acCompareExecute(Sender: TObject);
var
  M: TMemoryMap;
begin
  if OpenPMMDialog.Execute then
  begin
    M := TMemoryMap.Create;
    try
      M.LoadFromFile(OpenPMMDialog.FileName);
      dlgComparator := TdlgComparator.Create(nil);
      try
        if dlgComparator.CompareMemoryMaps(M, MemoryMapCore) then
          Application.MessageBox('No changes found.',
            PChar(Application.Title), MB_ICONINFORMATION);
      finally
        dlgComparator.Release;
      end;
    finally
      M.Free;
    end;
  end;
end;

procedure TdlgProcessMM.acCompareUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled := MapPresent;
end;

procedure TdlgProcessMM.acCopyAddressExecute(Sender: TObject);
var
  Data: PNodeData;
begin
  Data := GetSelectedNodeData;
  if Data <> nil then
    Clipboard.AsText := UInt64ToStr(Data^.Address);
end;

procedure TdlgProcessMM.acCopySelectedExecute(Sender: TObject);
var
  Data: PNodeData;
begin
  Data := GetSelectedNodeData;
  if Data = nil then
    Clipboard.AsText :=
      UInt64ToStr(Data^.Address) + #9 +
      Data^.RegionType  + #9 +
      SizeToStr(Data^.Size) + #9 +
      Data^.Section + #9 +
      Data^.Contains + #9 +
      Data^.Access + #9 +
      Data^.InitialAccess + #9 +
      Data^.Details;
end;

procedure TdlgProcessMM.acDebugInfoExecute(Sender: TObject);
begin
  dlgDbgInfo := TdlgDbgInfo.Create(nil);
  try
    dlgDbgInfo.ShowDebugInfo;
  finally
    dlgDbgInfo.Free;
  end;
end;

procedure TdlgProcessMM.acDumpAddrExecute(Sender: TObject);
var
  Data: PNodeData;
  DumpAddress: Pointer;
  DumpSize, DumpedSize: NativeUInt;
begin
  DumpAddress := nil;
  DumpSize := 0;
  dlgSelectAddress := TdlgSelectAddress.Create(nil);
  try
    Data := GetSelectedNodeData;
    if Data <> nil then
    begin
      dlgSelectAddress.edInt.Text := IntToStr(Data^.Address);
      dlgSelectAddress.edSize.Text := IntToStr(Data^.Size);
    end;
    if dlgSelectAddress.ShowDlg(ctDump) = mrOk then
    begin
      DumpAddress := Pointer(StrToInt64(dlgSelectAddress.edInt.Text));
      DumpSize := StrToInt64(dlgSelectAddress.edSize.Text)
    end;
  finally
    dlgSelectAddress.Release;
  end;
  if DumpAddress = nil then Exit;
  if SaveDMPDialog.Execute then
  begin
    DumpedSize := DumpAddr(SaveDMPDialog.FileName, DumpAddress, DumpSize);
    if DumpedSize = 0 then
      Application.MessageBox(DumpFailed,
        PChar(Application.Title), MB_ICONERROR)
    else
      Application.MessageBox(PChar(Format(DumpSuccess, [DumpedSize])),
        PChar(Application.Title), MB_ICONERROR);
  end;
end;

procedure TdlgProcessMM.acDumpRegionExecute(Sender: TObject);
var
  Data: PNodeData;
  DumpedSize: NativeUInt;
begin
  Data := GetSelectedNodeData;
  if Data <> nil then
    if SaveDMPDialog.Execute then
    begin
      DumpedSize := DumpRegion(SaveDMPDialog.FileName, Data^.Region);
      if DumpedSize = 0 then
        Application.MessageBox(DumpFailed,
          PChar(Application.Title), MB_ICONERROR)
      else
        Application.MessageBox(PChar(Format(DumpSuccess, [DumpedSize])),
          PChar(Application.Title), MB_ICONERROR);
    end;
end;

procedure TdlgProcessMM.acDumpRegionUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled := ProcessOpen and (GetSelectedNodeData <> nil);
end;

procedure TdlgProcessMM.acExitExecute(Sender: TObject);
begin
  Close;
end;

procedure TdlgProcessMM.acExpandAllExecute(Sender: TObject);
begin
  stMemoryMap.FullExpand;
end;

procedure TdlgProcessMM.acFillMMListExecute(Sender: TObject);
begin
  dlgMemoryMapListInfo := TdlgMemoryMapListInfo.Create(Application);
  dlgMemoryMapListInfo.ShowMemoryMapInfo;
end;

procedure TdlgProcessMM.acFindPachedDataExecute(Sender: TObject);
begin
  if dlgPatches <> nil then
  begin
    dlgPatches.BringToFront;
    Exit;
  end;
  dlgPatches := TdlgPatches.Create(Application);
  dlgPatches.FindPatches;
end;

procedure TdlgProcessMM.acFindPachedDataUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled := ProcessOpen and RawScannerCore.Active;
end;

procedure TdlgProcessMM.acGenerateMMLExecute(Sender: TObject);
begin
  dlgMemoryMapListInfo := TdlgMemoryMapListInfo.Create(Application);
  dlgMemoryMapListInfo.GenerateMemoryMapInfo;
end;

procedure TdlgProcessMM.acGenerateMMLUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := ProcessOpen and
    (MemoryMapCore.DebugMapData.Items.Count > 0);
end;

procedure TdlgProcessMM.acOpenExecute(Sender: TObject);
begin
  if OpenPMMDialog.Execute then
  begin
    MemoryMapCore.LoadFromFile(OpenPMMDialog.FileName);
    lblProcessNameData.Caption := MemoryMapCore.ProcessName;
    lblProcessPIDData.Caption := IntToStr(MemoryMapCore.PID);
    MapPresent := True;
    FillTreeView;
  end;
end;

procedure TdlgProcessMM.acQueryAddrExecute(Sender: TObject);
var
  QueryAddr: Pointer;
begin
  QueryAddr := nil;
  dlgSelectAddress := TdlgSelectAddress.Create(nil);
  try
    if dlgSelectAddress.ShowDlg(ctQuery) = mrOk then
      QueryAddr := Pointer(StrToInt64(dlgSelectAddress.edInt.Text));
  finally
    dlgSelectAddress.Release;
  end;
  if QueryAddr = nil then Exit;
  dlgRegionProps := TdlgRegionProps.Create(Application);
  dlgRegionProps.ShowPropertyAtAddr(QueryAddr, False);
end;

procedure TdlgProcessMM.acRefreshExecute(Sender: TObject);
var
  M: TMemoryMap;
  NewPID: Cardinal;
begin
  try
    NewPID := ProcessReconnect.GetNewPID(MemoryMapCore.PID);
    if NewPID = 0 then Abort;
    if Settings.SearchDifferences then
    begin
      M := TMemoryMap.Create;
      try
        M.OnGetWow64Heaps := OnGetWow64Heaps;
        InternalOpenProcess(M, NewPID, MemoryMapCore.ProcessName);
        dlgComparator := TdlgComparator.Create(nil);
        try
          if dlgComparator.CompareMemoryMaps(MemoryMapCore, M) then
            Application.MessageBox('No changes found.',
              PChar(Application.Title), MB_ICONINFORMATION);
        finally
          dlgComparator.Release;
        end;
      finally
        ReplaceMemoryMap(M);
      end;
    end
    else
      InternalOpenProcess(MemoryMapCore, NewPID, MemoryMapCore.ProcessName);
  except
    acSelectProcess.Execute;
    Exit;
  end;
end;

procedure TdlgProcessMM.acRegionPropsExecute(Sender: TObject);
var
  Data: PNodeData;
begin
  Data := GetSelectedNodeData;
  if Data <> nil then
  begin
    dlgRegionProps := TdlgRegionProps.Create(Application);
    dlgRegionProps.ShowPropertyAtAddr(Pointer(Data^.Address), False);
  end;
end;

procedure TdlgProcessMM.acRunAsAdminExecute(Sender: TObject);
begin
  if RestartAsAdmin then
    Close
  else
    RaiseLastOSError;
end;

procedure TdlgProcessMM.acSaveExecute(Sender: TObject);
var
  ProcessName: string;
begin
  ProcessName := MemoryMapCore.ProcessName;
  if Copy(ProcessName, Length(ProcessName) - 3, 4) = ' *32' then
    Delete(ProcessName, Length(ProcessName) - 3, 4);
  SavePMMDialog.FileName := ChangeFileExt(ProcessName, '.pmm');
  if SavePMMDialog.Execute then
    MemoryMapCore.SaveToFile(SavePMMDialog.FileName);
end;

procedure TdlgProcessMM.acSaveUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled := ProcessOpen;
end;

procedure TdlgProcessMM.acSearchAddressExecute(Sender: TObject);
var
  QueryAddr: Int64;
  I, Index: Integer;
begin
  QueryAddr := 0;
  dlgSelectAddress := TdlgSelectAddress.Create(nil);
  try
    if dlgSelectAddress.ShowDlg(ctHighLight) = mrOk then
      QueryAddr := StrToInt64(dlgSelectAddress.edInt.Text);
  finally
    dlgSelectAddress.Release;
  end;
  if QueryAddr = 0 then Exit;
  Index := -1;
  for I := 0 to NodeDataArrayLength - 1 do
    if QueryAddr >= NodeDataArray[I].Address then
      if QueryAddr <= NodeDataArray[I].Address + NodeDataArray[I].Size then
        Index := I;
  if Index >= 0 then
  begin
    stMemoryMap.Selected[NodeDataArray[Index].Node] := True;
    stMemoryMap.ScrollIntoView(NodeDataArray[Index].Node, True);
  end;
end;

procedure TdlgProcessMM.acSearchDataExecute(Sender: TObject);
var
  Data: PNodeData;
begin
  dlgFindData := TdlgFindData.Create(Application);
  Data := GetSelectedNodeData;
  if Data <> nil then
    dlgFindData.edStartAddr.Text := UInt64ToStr(Data^.Address);
  dlgFindData.Show;
end;

procedure TdlgProcessMM.acSelectProcessExecute(Sender: TObject);

  procedure OpenProcessAndInitGUI(PID: DWORD; const ProcessName: string);
  var
    Ico: TIcon;
  begin
    InternalOpenProcess(MemoryMapCore, PID, ProcessName);
    Ico := TIcon.Create;
    try
      Ico.Handle := GetProcessIco(PID);
      imgProcess.Picture.Assign(Ico);
      lblProcessNameData.Caption := MemoryMapCore.ProcessName +
        ' (' + MemoryMapCore.ProcessPath + ')';
      lblProcessPIDData.Caption := IntToStr(MemoryMapCore.PID);
      ProcessOpen := True;
      MapPresent := True;
    finally
      Ico.Free;
    end;
  end;

var
  dlgSelectProcess: TdlgSelectProcess;
  CmdLinePID: DWORD;
  AddrVA: ULONG64;
  ProcHandle: THandle;
  DebugParamIndex: Integer;
  TaskBarBtn: TTaskBarListProgress;
  Pid: Cardinal;
  ProcessName: string;
begin
  if FirstSelectProcess and (ParamCount > 0) then
  begin
    DebugParamIndex := 1;
    {$IFDEF WIN32}
    if ParamStr(1).StartsWith('x32') then
    {$ELSE}
    if ParamStr(1).StartsWith('Process') then
    {$ENDIF}
      Inc(DebugParamIndex);
    if TryStrToUInt(ParamStr(DebugParamIndex), CmdLinePID) then
    begin
      FirstSelectProcess := False;
      ProcHandle := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
        False, CmdLinePID);
      if ProcHandle <> 0 then
      begin
        CloseHandle(ProcHandle);
        OpenProcessAndInitGUI(CmdLinePID, 'opened from cmd ' + IntToStr(CmdLinePID));
        Inc(DebugParamIndex);
        if TryStrToUInt64(ParamStr(DebugParamIndex), AddrVA) then
        begin
          dlgRegionProps := TdlgRegionProps.Create(Application);
          dlgRegionProps.Position := poScreenCenter;
          dlgRegionProps.ShowPropertyAtAddr(Pointer(AddrVA),
            FindCmdLineSwitch('d', SwitchChars, True));
        end;
        Exit;
      end;
    end;
  end;
  dlgSelectProcess := TdlgSelectProcess.Create(Application);
  try
    Pid := 0;
    TaskBarBtn := TTaskBarListProgress.Create;
    try
      if FirstSelectProcess then
      begin
        TaskBarBtn.ShowExternalButton(dlgSelectProcess.Handle, Caption, EmptyStr);
        FirstSelectProcess := False;
        dlgSelectProcess.Position := poScreenCenter;
      end
      else
        dlgSelectProcess.Position := poMainFormCenter;
      case dlgSelectProcess.ShowModal of
        mrOk:
        begin
          Pid := dlgSelectProcess.Pid;
          ProcessName := dlgSelectProcess.ProcessName;
        end;
        mrClose: Close;
      end;
    finally
      TaskBarBtn.Free;
    end;
  finally
    dlgSelectProcess.Free;
  end;
  if Pid <> 0 then
    OpenProcessAndInitGUI(Pid, ProcessName);
end;

procedure TdlgProcessMM.acSettingsExecute(Sender: TObject);
begin
  dlgSettings := TdlgSettings.Create(nil);
  try
    if dlgSettings.ShowModal = mrOk then
      FillTreeView;
  finally
    dlgSettings.Release;
  end;
end;

procedure TdlgProcessMM.acShowExportsExecute(Sender: TObject);
begin
  if dlgExportList <> nil then
  begin
    dlgExportList.BringToFront;
    Exit;
  end;
  dlgExportList := TdlgExportList.Create(Application);
  dlgExportList.ShowExport;
end;

procedure TdlgProcessMM.acShowKnownExecute(Sender: TObject);
begin
  if dlgKnownData <> nil then
  begin
    dlgKnownData.BringToFront;
    Exit;
  end;
  dlgKnownData := TdlgKnownData.Create(Application);
  dlgKnownData.ShowKnownData;
end;

procedure TdlgProcessMM.AddShieldIconToMenu;
var
  IconInfo: TSHStockIconInfo;
begin
  ZeroMemory(@IconInfo, SizeOf(TSHStockIconInfo));
  IconInfo.cbSize := SizeOf(TSHStockIconInfo);
  if Succeeded(SHGetStockIconInfo(
    SIID_SHIELD, SHGSI_ICON or SHGFI_SMALLICON, IconInfo)) then
  begin
    mnuRunAsAdmin.ImageIndex :=
      ImageList_AddIcon(MainMenuImageList.Handle, IconInfo.hIcon);
    DestroyIcon(IconInfo.hIcon);
  end;
end;

//
//   Процедура рассчитывает количество всех отображаемых узлов
// =============================================================================
procedure TdlgProcessMM.CalcNodeDataArraySize;
var
  Region: TRegionData;
  I, A: Integer;
begin
  SetLength(NodeDataArray, 0);
  NodeDataArrayLength := MemoryMapCore.Count;
  for I := 0 to MemoryMapCore.Count - 1 do
  begin
    Region := MemoryMapCore[I];
    Inc(NodeDataArrayLength, Region.Directory.Count);
    if Region.HiddenRegionCount > 0 then
    begin
      Inc(NodeDataArrayLength, Region.HiddenRegionCount + 1);
      for A := 0 to Region.HiddenRegionCount do
      begin
        Region := MemoryMapCore.GetHiddenRegion(I, A);
        Inc(NodeDataArrayLength, Region.Directory.Count);
        if Region.Contains.Count > 0 then
        begin
          if Region.RegionType = rtHeap then
            if Region.Contains.Count = 1 then Continue;
          Inc(NodeDataArrayLength, Region.Contains.Count);
        end;
      end;
    end
    else
      Inc(NodeDataArrayLength, Region.Contains.Count);
  end;
  SetLength(NodeDataArray, NodeDataArrayLength);
end;

//
//   Процедура инициализирует дерево
// =============================================================================
procedure TdlgProcessMM.FillTreeView;
var
  Lvl1, Lvl2, Counter: Integer;
  Region: TRegionData;
  Lvl1Root, Lvl2Root: PVirtualNode;
  NodesColor: TColorRef;

  procedure AddContainsNodes(Root: PVirtualNode);
  var
    I: Integer;
    NeedAdd: Boolean;
  begin
    // в случае если регион содержит в себе один единственный элемент кучи
    // данные не выводим (ибо не имеет смысла)
    if Region.RegionType = rtHeap then
      if Region.Contains.Count = 1 then Exit;

    for I := 0 to Region.Contains.Count - 1 do
    begin
      // фильтруем регион
      NeedAdd := False;
      case MemoryMapCore.Filter of
        fiNone: NeedAdd := True;
        fiHeap: NeedAdd := Region.Contains[I].ItemType = itHeapBlock;
        fiThread: NeedAdd := Region.Contains[I].ItemType in [itThreadData, itStackFrame, itSEHFrame];
        fiSystem: NeedAdd := Region.Contains[I].ItemType = itSystem;
      end;
      if not NeedAdd then Continue;
      // если фильтр пройден - добавляем
      AddDataToContainsNode(Region, @NodeDataArray[Counter],
        Region.Contains[I]);
      NodeDataArray[Counter].Node :=
        stMemoryMap.AddChild(Root, @NodeDataArray[Counter]);
      Inc(Counter);
    end;
  end;

  procedure AddDirectoryNodes(Root: PVirtualNode);
  var
    I: Integer;
  begin
    // директории и секции выводятся только в случае отсутвия фильтра
    // или когда выставлен фильтр на образы файлов
    if not (MemoryMapCore.Filter in [fiNone, fiImage]) then Exit;
    for I := 0 to Region.Directory.Count - 1 do
    begin
      if not CheckAddr(Region.Directory[I].Address) then Continue;
      AddDataToDirectoryesNode(Region, @NodeDataArray[Counter],
        Region.Directory[I]);
      NodeDataArray[Counter].Node :=
        stMemoryMap.AddChild(Root, @NodeDataArray[Counter]);
      Inc(Counter);
    end;
  end;

const
  ProgressHint = 'Preparing to view...';
  ProgressHint2 = 'Preparing to view...  (%d%%)';

var
  PEImage: Boolean;
  LastPercent, CurrentPercent: Integer;
begin
  stMemoryMap.BeginUpdate;
  try
    stMemoryMap.NodeDataSize := SizeOf(TNodeData);
    stMemoryMap.RootNodeCount := 0;
    MemoryMapCore.ShowEmpty := Settings.ShowFreeRegions;
    MemoryMapCore.DebugMapData.LoadLines := Settings.LoadLines;
    MemoryMapCore.DetailedHeapData := Settings.ShowDetailedHeap;
    // Рассчитываем общее количество узлов
    CalcNodeDataArraySize;
    Counter := 0;
    LastPercent := 0;
    OnInitProgress(ProgressHint, 0);
    for Lvl1 := 0 to MemoryMapCore.Count - 1 do
    begin

      CurrentPercent := Round(Lvl1 / (MemoryMapCore.Count / 100));
      if CurrentPercent <> LastPercent then
      begin
        LastPercent := CurrentPercent;
        OnInitProgress(Format(ProgressHint2, [CurrentPercent]), CurrentPercent);
      end;

      // Заполяем данные по узлам первого уровня
      Region := MemoryMapCore[Lvl1];
      if Region.RegionVisible then
        NodesColor := AddDataToLevel1Node(Region, @NodeDataArray[Counter])
      else
      begin
        NodesColor := GetRegionColor(Region, True);
        AddDataToLevel2Node(Region, @NodeDataArray[Counter], NodesColor,
          Region.RegionType in [rtExecutableImage, rtExecutableImage64]);
      end;
      Lvl1Root :=
        stMemoryMap.AddChild(stMemoryMap.RootNode, @NodeDataArray[Counter]);
      NodeDataArray[Counter].Node := Lvl1Root;
      Inc(Counter);

      // Рассчитываем доппараметры, для более красивого отображения узлов
      // второго уровня. NodesColor отвечает за цвет подэлементов,
      // PEImage за вывод допинформации по региону
      if Region.RegionType in [rtDefault, rtSystem] then
        NodesColor := 0;
      PEImage := Region.RegionType in [rtExecutableImage, rtExecutableImage64];
      if PEImage then
        NodesColor := Settings.ImagePartColor;

      // Проверка, присутствуют ли скрытые узлы?
      if Region.HiddenRegionCount > 0 then
      begin
        // если присутствуют, добавляем их...
        for Lvl2 := 0 to Region.HiddenRegionCount do
        begin
          Region := MemoryMapCore.GetHiddenRegion(Lvl1, Lvl2);
          AddDataToLevel2Node(Region, @NodeDataArray[Counter], NodesColor, PEImage);
          Lvl2Root :=
            stMemoryMap.AddChild(Lvl1Root, @NodeDataArray[Counter]);
          NodeDataArray[Counter].Node := Lvl2Root;
          Inc(Counter);

          // у узлов второго уровня всегда выводится список директорий
          AddDirectoryNodes(Lvl2Root);
          // и дополнительной информации
          if Region.Contains.Count > 0 then
            AddContainsNodes(Lvl2Root);
        end;
      end
      else
      begin

        // а у узлов первого уровня директории и доп информация выводятся только
        // в тех случаях, если отсутствую скрытые узлы
        AddDirectoryNodes(Lvl1Root);
        if Region.Contains.Count > 0 then
          AddContainsNodes(Lvl1Root);
      end;
    end;
  finally
    stMemoryMap.EndUpdate;
  end;
  lvSummary.RootNodeCount := 0;
  lvSummary.RootNodeCount := 9;
end;

procedure TdlgProcessMM.FormCreate(Sender: TObject);
begin
  {$IFDEF DEBUG}
  ReportMemoryLeaksOnShutdown := True;
  Caption := Caption + ' [DEBUG]';
  {$ENDIF}
  if CheckIsAdmin then
  begin
    Caption := 'Administrator: ' + Caption;
    SetDebugPriv;
    acRunAsAdmin.Visible := False;
  end
  else
    AddShieldIconToMenu;
  {$IFDEF WIN64}
  IPCServerMMFName := ParamStr(1);
  {$ELSE}
  IPCServer := TIPCServer.Create;
  {$ENDIF}

  // Инициализация синглтонов и их событий
  RawScannerCore.OnProgress := OnInitProgress;
  PluginManager.OnProgress := OnInitProgress;
  MemoryMapCore.DetailedHeapData := Settings.ShowDetailedHeap;
  MemoryMapCore.OnProgress := OnInitProgress;
  MemoryMapCore.OnGetWow64Heaps := OnGetWow64Heaps;

  Application.Title := Caption;
  FirstRun := True;
  FirstSelectProcess := True;
end;

procedure TdlgProcessMM.FormDestroy(Sender: TObject);
begin
  {$IFDEF WIN32}
  IPCServer.Free;
  {$ENDIF}
end;

procedure TdlgProcessMM.FormKeyPress(Sender: TObject; var Key: Char);
var
  TmpString, ClipboardString: string;
begin
  // реализуем быстрый поиск при нажатии клавиш
  if Key = #8 then
  begin
    Delete(SearchString, Length(SearchString), 1);
    SearchPosition := 0;
    if SearchString = '' then
      Caption := RootCaption
    else
      Search(SearchString);
    Exit;
  end;
  if Key = #22 then
  begin
    ClipboardString := AnsiUpperCase(Trim(Clipboard.AsText));
    if ClipboardString = '' then Exit;
    TmpString := '';
    while TmpString <> ClipboardString do
    begin
      TmpString := TmpString + ClipboardString[Length(TmpString) + 1];
      if Search(TmpString) then
        SearchString := TmpString
      else
        Break;
    end;
  end;
  if Key = #27 then
  begin
    SearchString := '';
    Caption := RootCaption;
    SearchPosition := 0;
    Exit;
  end;
  if Key = #13 then
  begin
    if SearchString <> '' then
    begin
      Inc(SearchPosition);
      Search(SearchString);
    end;
    Exit;
  end;
  if Key <= #32 then Exit;
  TmpString := SearchString + AnsiUpperCase(Key);
  if Search(TmpString) then
    SearchString := TmpString;
end;

procedure TdlgProcessMM.FormShow(Sender: TObject);
begin
  if FirstRun then
    acSelectProcess.Execute;
  FirstRun := False;
end;

function TdlgProcessMM.GetSelectedNodeData: PNodeData;
var
  E: TVTVirtualNodeEnumerator;
begin
  Result := nil;
  E := stMemoryMap.SelectedNodes.GetEnumerator;
  if E.MoveNext then
    Result := PNodeData(stMemoryMap.GetNodeData(E.Current)^);
end;

procedure TdlgProcessMM.imgProcessClick(Sender: TObject);
begin
  acSelectProcessExecute(nil);
end;

procedure TdlgProcessMM.InternalOpenProcess(AMap: TMemoryMap; PID: DWORD;
  const ProcessName: string);
begin
  dlgProgress := TdlgProgress.Create(nil);
  try
    if not ProcessOpen then
      dlgProgress.Position := poScreenCenter;
    AMap.OnProgress := OnInitProgress;
    dlgProgress.ShowWithCallback(procedure()
    begin
      Wow64Support.DisableRedirection;
      try
        // Сначала должно отработать ядро MemoryMap для получения данных по процессу
        AMap.InitFromProcess(PID, ProcessName);
        // Редиректору нужно знать по какому адресу расположен ApiSet
        // для пересчета адресов из локального адресного пространства в удаленное
        ApiSetRedirector.RemoteApiSetVA := ULONG_PTR64(AMap.PEB.ApiSetMap);
        // И только после этого можно запускать на выполнение RawScannerCore
        RawScannerCore.InitFromProcess(PID);
        // Последним идет подсистема плагинов
        PluginManager.OpenProcess(PID);
      finally
        Wow64Support.EnableRedirection;
      end;
    end);
    lblProcessPIDData.Caption := IntToStr(MemoryMapCore.PID);
    FillTreeView;
  finally
    FreeAndNil(dlgProgress);
  end;
end;

procedure TdlgProcessMM.lvSummaryBeforeItemErase(Sender: TBaseVirtualTree;
  TargetCanvas: TCanvas; Node: PVirtualNode; ItemRect: TRect;
  var ItemColor: TColor; var EraseAction: TItemEraseAction);
begin
  case Node^.Index of
    1: ItemColor := Settings.GetColor(Node^.Index - 1);
    2..7: ItemColor := Settings.GetColor(Node^.Index);
  else
    ItemColor := clWhite;
  end;
end;

procedure TdlgProcessMM.lvSummaryCustomDrawItem(Sender: TCustomListView;
  Item: TListItem; State: TCustomDrawState; var DefaultDraw: Boolean);
begin
  case Item.Index of
    1: lvSummary.Canvas.Brush.Color := Settings.ImageColor;
    2: lvSummary.Canvas.Brush.Color := Settings.PrivateColor;
    3: lvSummary.Canvas.Brush.Color := Settings.SharedColor;
    4: lvSummary.Canvas.Brush.Color := Settings.MappedColor;
    5: lvSummary.Canvas.Brush.Color := Settings.HeapColor;
    6: lvSummary.Canvas.Brush.Color := Settings.ThreadColor;
    7: lvSummary.Canvas.Brush.Color := Settings.SystemColor;
  end;
end;

procedure TdlgProcessMM.lvSummaryGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; TextType: TVSTTextType;
  var CellText: string);
const
  TypeString: array [0..8] of string = (
    'Total', 'Image', 'Private', 'Shareable',
    'Mapped', 'Heap', 'Thread', 'System', 'Free');
var
  T: TTotalItem;
begin
  case Node^.Index of
    0: T := MemoryMapCore.TotalData.Total;
    1: T := MemoryMapCore.TotalData.Image;
    2: T := MemoryMapCore.TotalData._Private;
    3: T := MemoryMapCore.TotalData.Shareable;
    4: T := MemoryMapCore.TotalData.Mapped;
    5: T := MemoryMapCore.TotalData.Heap;
    6: T := MemoryMapCore.TotalData.Thread;
    7: T := MemoryMapCore.TotalData.System;
    8: T := MemoryMapCore.TotalData.Free;
  end;
  case Column of
    0: CellText := TypeString[Node^.Index];
    1: CellText := SizeToStr(T.Size);
    2: CellText := SizeToStr(T.Commited);
    3:
      if T.Blocks = 0 then
        CellText := ''
      else
        CellText := IntToStr(T.Blocks);
  end;
end;

procedure TdlgProcessMM.lvSummaryNodeClick(Sender: TBaseVirtualTree;
  const HitInfo: THitInfo);
begin
  MemoryMapCore.Filter := TFilters(HitInfo.HitNode^.Index);
  FillTreeView;
end;

procedure TdlgProcessMM.OnGetWow64Heaps(Value: THeap);
var
  M: TMemoryStream;
begin
  M := GetWin32MemoryMap(MemoryMapCore.PID, IPCServerMMFName);
  try
    if M.Size > 0 then
      LoadHeaps(Value, M);
  finally
    M.Free;
  end;
end;

procedure TdlgProcessMM.OnInitProgress(const Step: string; APecent: Integer);
begin
  if dlgProgress = nil then Exit;
  dlgProgress.lblProgress.Caption := Step;
  dlgProgress.ProgressBar.Position := APecent;
  Application.ProcessMessages;
end;

function TdlgProcessMM.Reconnect: Boolean;
var
  NewPID: DWORD;
begin
  Result := Settings.AutoReconnect;
  if not Result then Exit;
  try
    NewPID := ProcessReconnect.GetNewPID(MemoryMapCore.PID);
    if NewPID = 0 then Exit(False);
    InternalOpenProcess(MemoryMapCore, NewPID, MemoryMapCore.ProcessName);
  except
    Result := False;
  end;
end;

function TdlgProcessMM.Search(const Value: string): Boolean;
var
  I: Integer;
  AddrStr: string;
  Address: Int64;
  Found: Boolean;
begin
  Result := False;
  if Value[1] = '$' then
    AddrStr := Value
  else
    AddrStr := '$' + Value;
  if TryStrToInt64(AddrStr, Address) then
    AddrStr := IntToHex(Address, 1)
  else
    AddrStr := '';
  for I := SearchPosition to NodeDataArrayLength - 1 do
  begin
    Found := Pos(Value, NodeDataArray[I].SearchDetails) > 0;
    if not Found then
      Found := Pos(AddrStr, NodeDataArray[I].SearchAddress) > 0;
    if Found then
    begin
      SearchPosition := I;
      Result := True;
      stMemoryMap.Selected[NodeDataArray[SearchPosition].Node] := True;
      stMemoryMap.ScrollIntoView(NodeDataArray[SearchPosition].Node, True);
      Caption := RootCaption + ' [' + Value + ']';
      Break;
    end;
  end;
end;

procedure TdlgProcessMM.stMemoryMapBeforeItemErase(Sender: TBaseVirtualTree;
  TargetCanvas: TCanvas; Node: PVirtualNode; ItemRect: TRect;
  var ItemColor: TColor; var EraseAction: TItemEraseAction);
var
  Data: PNodeData;
begin
  Data := PNodeData(stMemoryMap.GetNodeData(Node)^);
  ItemColor := Data^.Color;
end;

procedure TdlgProcessMM.stMemoryMapGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; TextType: TVSTTextType;
  var CellText: string);
var
  Data: PNodeData;
begin
  Data := PNodeData(stMemoryMap.GetNodeData(Node)^);
  CellText := '';
  case Column of
    0: CellText := UInt64ToStr(Data^.Address);
    1: CellText := Data^.RegionType;
    2: CellText := SizeToStr(Data^.Size);
    3: CellText := Data^.Section;
    4: CellText := Data^.Contains;
    5: CellText := Data^.Access;
    6: CellText := Data^.InitialAccess;
    7:
      if Node.ChildCount > 0 then
        CellText := IntToStr(Node.ChildCount);
    8: CellText := Data^.Details;
  end;
end;

procedure TdlgProcessMM.stMemoryMapNodeDblClick(Sender: TBaseVirtualTree;
  const HitInfo: THitInfo);
begin
  if not (vsHasChildren in HitInfo.HitNode^.States) then
    acRegionPropsExecute(nil);
end;

end.
