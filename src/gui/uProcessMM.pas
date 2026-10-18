////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : uProcessMM.pas
//  * Purpose   : Main form of the project
//  * Author    : Alexander (Rouse_) Bagel
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.7.54
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : https://github.com/AlexanderBagel/ProcessMemoryMap/releases/latest
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

unit uProcessMM;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.Menus, Vcl.ComCtrls, Vcl.StdCtrls, Vcl.ExtCtrls, System.UITypes,
  Vcl.ImgList, Winapi.TlHelp32, Winapi.ShellAPI, Winapi.CommCtrl,
  Vcl.Clipbrd, System.Actions, Vcl.ActnList, Vcl.PlatformDefaultStyleActnCtrls,
  Vcl.ActnMan, System.ImageList, System.Diagnostics, Generics.Collections,

  VirtualTrees,
  VirtualTrees.BaseTree,
  VirtualTrees.BaseAncestorVCL,
  VirtualTrees.AncestorVCL,
  VirtualTrees.Types,

  MemoryMap.Core,
  MemoryMap.RegionData,
  MemoryMap.Utils,
  MemoryMap.Threads,
  MemoryMap.Heaps,
  MemoryMap.DebugMapData,

  RawScanner.Core,
  RawScanner.ApiSet,
  RawScanner.Types,
  RawScanner.Wow64,
  RawScanner.Image.Pe,
  RawScanner.Logger,
  RawScanner.Pdb,
  RawScanner.CoffDwarf,
  RawScanner.SymbolStorage,
  RawScanner.Utils,

  uDisplayUtils,
  uIPC,
  uProgress,
  uUtils,
  uBaseForm;

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
    acStrings: TAction;
    mnuStrings: TMenuItem;
    pmGui: TPopupMenu;
    acCopyPID: TAction;
    CopyPID1: TMenuItem;
    acCopyProcessPath: TAction;
    CopyProcessPath1: TMenuItem;
    acOpenInExplorer: TAction;
    OpenInExplorer1: TMenuItem;
    acCallStackDemangler: TAction;
    CallStackDemangler1: TMenuItem;
    N11: TMenuItem;
    DWARFReader1: TMenuItem;
    acRunDWARFReader: TAction;
    acSearchResult: TAction;
    mnuSearchResults: TMenuItem;
    gbPages: TGroupBox;
    acShowResources: TAction;
    mnuResources: TMenuItem;
    acShowWindows: TAction;
    ShowWindows1: TMenuItem;
    mnuCheckUpdates: TMenuItem;
    N15: TMenuItem;
    acPdbManager: TAction;
    PDBManager1: TMenuItem;
    N16: TMenuItem;
    News1: TMenuItem;
    N17: TMenuItem;
    acNews: TAction;
    acUpdates: TAction;
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
    procedure acCopyPIDUpdate(Sender: TObject);
    procedure acCopyPIDExecute(Sender: TObject);
    procedure acCopyProcessPathExecute(Sender: TObject);
    procedure acStringsExecute(Sender: TObject);
    procedure acOpenInExplorerUpdate(Sender: TObject);
    procedure acOpenInExplorerExecute(Sender: TObject);
    procedure FormActivate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure acCallStackDemanglerExecute(Sender: TObject);
    procedure acRunDWARFReaderUpdate(Sender: TObject);
    procedure acRunDWARFReaderExecute(Sender: TObject);
    procedure acSearchResultUpdate(Sender: TObject);
    procedure acSearchResultExecute(Sender: TObject);
    procedure acShowResourcesExecute(Sender: TObject);
    procedure acShowWindowsExecute(Sender: TObject);
    procedure FormAfterMonitorDpiChanged(Sender: TObject; OldDPI,
      NewDPI: Integer);
    procedure acPdbManagerExecute(Sender: TObject);
    procedure acUpdatesExecute(Sender: TObject);
    procedure acNewsExecute(Sender: TObject);
  private
    FirstRun, ProcessOpen, MapPresent, FirstSelectProcess: Boolean;
    ContinueState: TSymSrvContinueState;
    NodeDataArrayLength: Integer;
    NodeDataArray: array of TNodeData;
    SearchString: string;
    SearchPosition: Integer;
    {$IFDEF WIN32}
    IPCServer: TIPCServer;
    {$ENDIF}
    DebugLog: TStringList;
    LastProgressCaption: string;
    RemoteGitInfo: TReseaseInfo;
    procedure AddShieldIconToMenu;
    procedure CalcNodeDataArraySize;
    procedure InternalOpenProcess(AMap: TMemoryMap;
      PID: DWORD; const ProcessName: string);
    procedure FillTreeView;
    function Search(const Value: string): Boolean;
    procedure TransmitDebugMapToSymbols;
    function GetSelectedNodeData: PNodeData;
    procedure ProcessFirstRun;
    procedure OnGetWow64Heaps(Value: THeap);
    procedure OnInitProgress(const Step: string; APecent: Integer);
    procedure OnLog(ALevel: TLogLevel; AType: TLogType;
      const FuncName, Description: string);
    procedure OnPdbLoad(Sender: TObject; State: TSymSrvProgressState;
      Pdb: TPdb; BytesReceived, TotalBytes: Int64;
      var AContinueState: TSymSrvContinueState);
    procedure OnCancelBtnPress(Sender: TObject);
    procedure DelayedLoad(var Msg: TMessage); message WM_USER;
    procedure CheckUpdates(OnlyCheckNewest: Boolean);
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
  uSettings.Form,
  uDump,
  uAbout,
  uMemoryMapListInfo,
  uProcessReconnect,
  uKnownData,
  uPatchDetect,
  uPluginManager,
  uPdbManager,
  uDebugInfoDlg,
  uStringsViewer,
  uCallStack,
  uSearchResult,
  uResources,
  uWindows,
  ScaledCtrls,
  Shell.TaskBarListProgress;

const
  RootCaption = 'Process Memory Map' {$IFDEF DEBUG} + ' [DEBUG]'{$ENDIF};
  DumpFailed = 'Dump filed';
  DumpSuccess = 'Dumped %d bytes';

{$R *.dfm}

procedure TdlgProcessMM.acAboutExecute(Sender: TObject);
begin
  dlgAbout := TdlgAbout.Create(Self);
  try
    dlgAbout.ShowModal;
  finally
    dlgAbout.Free;
  end;
end;

procedure TdlgProcessMM.acCallStackDemanglerExecute(Sender: TObject);
begin
  if dlgCallStack <> nil then
  begin
    dlgCallStack.BringToFront;
    Exit;
  end;
  dlgCallStack := TdlgCallStack.Create(Application);
  dlgCallStack.Show;
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
        dlgComparator.Free;
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

procedure TdlgProcessMM.acCopyPIDExecute(Sender: TObject);
begin
  Clipboard.AsText := IntToStr(MemoryMapCore.PID);
end;

procedure TdlgProcessMM.acCopyPIDUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := MemoryMapCore.PID <> 0;
end;

procedure TdlgProcessMM.acCopyProcessPathExecute(Sender: TObject);
begin
  Clipboard.AsText := MemoryMapCore.ProcessPath;
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
    dlgDbgInfo.ShowDebugInfo(DebugLog, RemoteGitInfo);
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
    dlgSelectAddress.Free;
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
          PChar(Application.Title), MB_ICONINFORMATION);
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

procedure TdlgProcessMM.acNewsExecute(Sender: TObject);
begin
  ShellExecute(Handle, 'open', 'https://boosty.to/processmemorymap', nil, nil, SW_SHOWNORMAL);
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

procedure TdlgProcessMM.acOpenInExplorerExecute(Sender: TObject);
var
  Data: PNodeData;
begin
  Data := GetSelectedNodeData;
  OpenExplorerAndSelectFile(Data.Details);
end;

procedure TdlgProcessMM.acOpenInExplorerUpdate(Sender: TObject);
var
  Data: PNodeData;
begin
  Data := GetSelectedNodeData;
  (Sender as TAction).Enabled :=
    ProcessOpen and (Data <> nil) and FileExists(Data.Details);
end;

procedure TdlgProcessMM.acPdbManagerExecute(Sender: TObject);
begin
  if dlgPdbManager <> nil then
  begin
    dlgPdbManager.BringToFront;
    Exit;
  end;
  dlgPdbManager := TdlgPdbManager.Create(Application);
  dlgPdbManager.Show;
end;

procedure TdlgProcessMM.acQueryAddrExecute(Sender: TObject);
var
  QueryAddr: Pointer;
  SelectAddress: UInt64;
begin
  QueryAddr := nil;
  if Assigned(ActiveRegionProps) then
    SelectAddress := ActiveRegionProps.GetSelectedAddr
  else
    SelectAddress := 0;
  dlgSelectAddress := TdlgSelectAddress.Create(nil);
  try
    if dlgSelectAddress.ShowDlg(ctQuery, SelectAddress) = mrOk then
      QueryAddr := Pointer(StrToInt64(dlgSelectAddress.edInt.Text));
  finally
    dlgSelectAddress.Free;
  end;
  if QueryAddr = nil then Exit;
  dlgRegionProps := TdlgRegionProps.Create(Application);
  dlgRegionProps.ShowPropertyAtAddr(QueryAddr);
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
          dlgComparator.Free;
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
    dlgRegionProps.ShowPropertyAtAddr(Pointer(Data^.Address));
  end;
end;

procedure TdlgProcessMM.acRunAsAdminExecute(Sender: TObject);
begin
  if RestartAsAdmin then
    Close
  else
    RaiseLastOSError;
end;

procedure TdlgProcessMM.acRunDWARFReaderExecute(Sender: TObject);
begin
  PluginManager.RunDwarfReader;
end;

procedure TdlgProcessMM.acRunDWARFReaderUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled := PluginManager.DwarfReaderFound;
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
    dlgSelectAddress.Free;
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

procedure TdlgProcessMM.acSearchResultExecute(Sender: TObject);
begin
  dlgSearchResult.Show;
end;

procedure TdlgProcessMM.acSearchResultUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := dlgSearchResult <> nil;
end;

procedure TdlgProcessMM.acSelectProcessExecute(Sender: TObject);

  procedure OpenProcessAndInitGUI(PID: DWORD; const ProcessName: string);
  var
    Ico: TScaledIcon;
  begin
    InternalOpenProcess(MemoryMapCore, PID, ProcessName);
    Ico := TScaledIcon.Create;
    try
      Ico.Handle := GetProcessIco(PID);
      imgProcess.Picture.Assign(Ico);
      imgProcess.Center := True;
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

    CmdLinePID := 0;
    if AnsiSameText(ParamStr(1), 'self') then
      CmdLinePID := GetCurrentProcessId;

    if (CmdLinePID <> 0) or TryStrToUInt(ParamStr(DebugParamIndex), CmdLinePID) then
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
          dlgRegionProps.ShowPropertyAtAddr(Pointer(AddrVA));
          Exit;
        end;
        if AnsiSameText(ParamStr(DebugParamIndex), '-stack') then
        begin
          dlgCallStack := TdlgCallStack.Create(Application);
          dlgCallStack.Position := poScreenCenter;
          dlgCallStack.Show;
        end;
        if AnsiSameText(ParamStr(DebugParamIndex), '-resources') then
        begin
          dlgResources := TdlgResources.Create(Application);
          dlgResources.ShowResources;
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
    dlgSettings.Free;
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

procedure TdlgProcessMM.acShowResourcesExecute(Sender: TObject);
begin
  if dlgResources <> nil then
  begin
    dlgResources.BringToFront;
    Exit;
  end;
  dlgResources := TdlgResources.Create(Application);
  dlgResources.ShowResources;
end;

procedure TdlgProcessMM.acShowWindowsExecute(Sender: TObject);
begin
  if dlgWindows <> nil then
  begin
    dlgWindows.BringToFront;
    Exit;
  end;
  dlgWindows := TdlgWindows.Create(Application);
  dlgWindows.ShowProcessWindows;
end;

procedure TdlgProcessMM.acStringsExecute(Sender: TObject);
begin
  if dlgStringsViewer <> nil then
  begin
    dlgStringsViewer.BringToFront;
    Exit;
  end;
  dlgStringsViewer := TdlgStringsViewer.Create(Application);
  dlgStringsViewer.ShowStrings;
end;

procedure TdlgProcessMM.acUpdatesExecute(Sender: TObject);
begin
  CheckUpdates(False);
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
          if (Region.RegionType = rtHeap) and (Region.Contains.Count = 1) then
            Continue;
          Inc(NodeDataArrayLength, Region.Contains.Count);
        end;
      end;
    end
    else
      Inc(NodeDataArrayLength, Region.Contains.Count);
  end;
  SetLength(NodeDataArray, NodeDataArrayLength);
end;

procedure TdlgProcessMM.CheckUpdates(OnlyCheckNewest: Boolean);
var
  Check: TThreadProcedure;
begin
  Check :=
    procedure
    var
      VerInfo: TVersionInfo;
    begin
      if OnlyCheckNewest and (Settings.LastCheckedUpdate = RemoteGitInfo.Version) then
        Exit;
      if not GetVersionInfo(VerInfo) then Exit;
      if RemoteGitInfo.VerInfo > VerInfo then
      begin
        Settings.LastCheckedUpdate := RemoteGitInfo.Version;
        Settings.SaveSettings;
        if Application.MessageBox(PChar(Format('A new version is available: %s' + sLineBreak +
          'Published: %s' + sLineBreak + sLineBreak +
          'Would you like to open the release page?',
          [RemoteGitInfo.Version, RemoteGitInfo.PublishedDate])),
          PChar(Application.Title), MB_ICONQUESTION or MB_YESNO or MB_DEFBUTTON1) = ID_YES then
          ShellExecute(Handle, 'open', 'https://github.com/AlexanderBagel/ProcessMemoryMap/releases/latest', nil, nil, SW_SHOWNORMAL);
      end
      else
        if not OnlyCheckNewest then
          Application.MessageBox(PChar('You are using the latest version.' + sLineBreak +
             sLineBreak + 'No updates are currently available.'), PChar(Application.Title), MB_ICONINFORMATION);
    end;

  if OnlyCheckNewest then
  begin
    TThread.CreateAnonymousThread(
      procedure
      var
        GitInfo: TReseaseInfo;
      begin
        if GetLatestRelease(Settings.Proxy, GitInfo) then
        begin
          RemoteGitInfo := GitInfo;
          TThread.Queue(nil, Check);
        end;
        Finalize(Check);
      end).Start;
  end
  else
    if GetLatestRelease(Settings.Proxy, RemoteGitInfo) then
    begin
      Check;
      Finalize(Check);
    end;
end;

procedure TdlgProcessMM.DelayedLoad(var Msg: TMessage);
begin
  ProcessFirstRun;
end;

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

    // if the region contains only a single element of the heap
    // do not print the data (since it makes no sense)

    // [ru] в случае если регион содержит в себе один единственный элемент кучи
    // данные не выводим (ибо не имеет смысла)

    if Region.RegionType = rtHeap then
      if Region.Contains.Count = 1 then Exit;

    for I := 0 to Region.Contains.Count - 1 do
    begin
      NeedAdd := False;
      case MemoryMapCore.Filter of
        fiNone: NeedAdd := True;
        fiHeap: NeedAdd := Region.Contains[I].ItemType = itHeapBlock;
        fiThread: NeedAdd := Region.Contains[I].ItemType in [itThreadData, itStackFrame, itSEHFrame];
        fiSystem: NeedAdd := Region.Contains[I].ItemType = itSystem;
      end;
      if not NeedAdd then Continue;
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

    // directories and sections are displayed only if no filter is applied
    // or when a filter is set to file images

    // [ru] директории и секции выводятся только в случае отсутвия фильтра
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
    MemoryMapCore.DetailedHeapData := Settings.ShowDetailedHeap;
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

      // Populating data for first-level nodes
      // [ru] Заполняем данные по узлам первого уровня

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

      // Calculate additional parameters for a nicer display of
      // second-level nodes. NodesColor controls the color of child
      // items, PEImage is used to output additional region info

      // [ru] Рассчитываем доппараметры, для более красивого отображения узлов
      // второго уровня. NodesColor отвечает за цвет подэлементов,
      // PEImage за вывод допинформации по региону

      if Region.RegionType in [rtDefault, rtSystem] then
        NodesColor := 0;
      PEImage := Region.RegionType in [rtExecutableImage, rtExecutableImage64];

      // If the sections are simply mapped, they will be classified as Mapped
      // [ru] если секции просто отмаплены, то они пойдут именно как мап

      PEImage := PEImage and not (Region.MBI.Type_9 = MEM_MAPPED);
      if PEImage then
        NodesColor := Settings.ImagePartColor;

      // check whether any nodes are hidden
      // [ru] Проверка, присутствуют ли скрытые узлы?

      if Region.HiddenRegionCount > 0 then
      begin

        // if there are, add them...
        // [ru] если присутствуют, добавляем их...

        for Lvl2 := 0 to Region.HiddenRegionCount do
        begin
          Region := MemoryMapCore.GetHiddenRegion(Lvl1, Lvl2);
          AddDataToLevel2Node(Region, @NodeDataArray[Counter], NodesColor, PEImage);
          Lvl2Root :=
            stMemoryMap.AddChild(Lvl1Root, @NodeDataArray[Counter]);
          NodeDataArray[Counter].Node := Lvl2Root;
          Inc(Counter);

          // second-level nodes always show a list of directories
          // [ru] у узлов второго уровня всегда выводится список директорий

          AddDirectoryNodes(Lvl2Root);

          // and additional information
          // [ru] и дополнительной информации

          if Region.Contains.Count > 0 then
            AddContainsNodes(Lvl2Root);
        end;
      end
      else
      begin

        // while for first-level nodes, directories and additional info
        // are shown only if there are no hidden nodes

        // [ru] а у узлов первого уровня директории и дополнительная информация
        //  выводится только в тех случаях, если отсутствуют скрытые узлы

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

procedure TdlgProcessMM.FormActivate(Sender: TObject);
begin
  {$IFDEF DEBUG}
  PostMessage(Handle, WM_USER, 0, 0);
  {$ENDIF}
end;

procedure TdlgProcessMM.FormAfterMonitorDpiChanged(Sender: TObject; OldDPI,
  NewDPI: Integer);
begin
  FixVirtualStringTreeDpiBug(lvSummary);
  FixVirtualStringTreeDpiBug(stMemoryMap);
end;

procedure TdlgProcessMM.FormCreate(Sender: TObject);
begin
  {$IFDEF DEBUG}
  ReportMemoryLeaksOnShutdown := True;
  Caption := RootCaption;
  {$ENDIF}
  if CheckIsAdmin then
  begin
    Caption := 'Administrator: ' + Caption;
    SetDebugPriv;
    acRunAsAdmin.Visible := False;
  end
  else
    AddShieldIconToMenu;
  {$IFDEF WIN32}
  IPCServer := TIPCServer.Create;
  {$ENDIF}

  RawScannerCore.OnProgress := OnInitProgress;
  PluginManager.OnProgress := OnInitProgress;
  MemoryMapCore.DetailedHeapData := Settings.ShowDetailedHeap;
  MemoryMapCore.OnProgress := OnInitProgress;
  MemoryMapCore.OnGetWow64Heaps := OnGetWow64Heaps;

  FilePathAtImageBase := function (AddrVA: ULONG_PTR64): string
  var
    Idx: Integer;
    RegionData: TRegionData;
  begin
    Result := '';
    if MemoryMapCore.GetRegionIndex(Pointer(AddrVA), Idx) then
    begin
      RegionData := MemoryMapCore.GetRegionAtUnfilteredIndex(Idx);
      if RegionData.RegionType in [rtExecutableImage, rtExecutableImage64] then
        Result := RegionData.Details;
    end;
  end;

  Application.Title := Caption;
  FirstRun := True;
  FirstSelectProcess := True;

  DebugLog := TStringList.Create;

  DebugInitialHeapSize := GetMemAlloc;
  RawScannerCore.PdbStorage.OnProgress := OnPdbLoad;
end;

procedure TdlgProcessMM.FormDestroy(Sender: TObject);
begin
  DebugLog.Free;
  {$IFDEF WIN32}
  IPCServer.Free;
  {$ENDIF}
end;

procedure TdlgProcessMM.FormKeyPress(Sender: TObject; var Key: Char);
var
  TmpString, ClipboardString: string;
begin
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
  {$IFNDEF DEBUG}
  ProcessFirstRun;
  {$ENDIF}
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
var
  Stopwatch: TStopwatch;
begin
  if not TBaseAppForm.CloseAllBaseForm then Exit;
  dlgProgress := TdlgProgress.Create(Self);
  try
    if not ProcessOpen then
      dlgProgress.Position := poScreenCenter;
    AMap.OnProgress := OnInitProgress;
    dlgProgress.ShowWithCallback(procedure()
    begin
      Wow64Support.DisableRedirection;
      try
        AMap.DebugMapData.LoadLines := Settings.LoadLines;
        Stopwatch.Start;
        FirstRun := False;

        // First, the MemoryMap must run to retrieve data about the process
        // [ru] Сначала должно отработать ядро MemoryMap для получения данных по процессу

        AMap.InitFromProcess(PID, ProcessName);

        // The redirector needs to know the address of the ApiSet
        // in order to translate addresses from the local address
        // space to the remote one

        // [ru] Редиректору нужно знать по какому адресу расположен ApiSet
        // для пересчета адресов из локального адресного пространства в удаленное

        ApiSetRedirector.RemoteApiSetVA := ULONG_PTR64(AMap.PEB.ApiSetMap);

        TRawPEImage.DisableLoadStrings := not Settings.LoadStrings;
        TRawPEImage.LoadStringLength := Settings.StringMinLengh;
        RawScannerCore.UsePDB := Settings.UsePDB;
        RawScannerCore.DownloadPDB := Settings.DownloadPDB;
        RawScannerCore.PdbStorage.SymConfig := Settings.SymSrv;
        dlgProgress.ProgressBarAdv.OnCancelClick := OnCancelBtnPress;

        // Loading DWARF is slow, so progress should be shown as well
        // [ru] загрузка DWARF не быстрый процесс, поэтому нужно тоже выводить прогресс

        TDwarfDebugInfo.LoadCallback := procedure(AStep: TLoadCallbackStep; ACurrent, AMax: Int64)
        var
          AHint: string;
        begin
          case AStep of
            lcsLoadInfo: AHint := LastProgressCaption + ' load DWARF.';
            lcsPrepareAddr: AHint := LastProgressCaption + ' prepare DWARF.';
            lcsProcessInfo: AHint := LastProgressCaption + ' process DWARF.';
          else
            AHint := LastProgressCaption + ' load DWARF lines.';
          end;
          dlgProgress.ProgressBarAdv.HintLabel.Visible := False;
          dlgProgress.ProgressBarAdv.ShowCancelButton := False;
          dlgProgress.ProgressBarAdv.Visible := ACurrent <> AMax;
          dlgProgress.ProgressBarAdv.Max := AMax;
          dlgProgress.UpdateCaption(AHint, ACurrent);
        end;
        RawScannerLogger.OnLog := OnLog;

        // RawScannerCore is configured, now it can be started
        // [ru] RawScannerCore настроен, теперь можно его запускать

        ContinueState := scsRun;
        DebugLog.Clear;
        RawScannerCore.InitFromProcess(PID);

        // The plugin subsystem goes last
        // [ru] Последним идет подсистема плагинов

        PluginManager.OpenProcess(PID);

        // Now we need to move the debug info from DebugMap into the debug symbols
        // [ru] Теперь необходимо перенести отладочную информацию из DebugMap в отладочные символы

        TransmitDebugMapToSymbols;

        // Save the elapsed time for the debug information window
        // [ru] Запомним для окна с отладочной информацией сколько времени было потрачено

        Stopwatch.Stop;
        DebugElapsedMilliseconds := Stopwatch.ElapsedMilliseconds;
      finally
        Wow64Support.EnableRedirection;
      end;
    end);
    lblProcessPIDData.Caption := IntToStr(MemoryMapCore.PID);
    FillTreeView;
  finally
    dlgProgress.Free;
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

procedure TdlgProcessMM.OnCancelBtnPress(Sender: TObject);
begin
  if ContinueState <> scsRun then Exit;
  ContinueState := scsPause;
  if MessageBox(Handle, PChar('Cancel the download?' + sLineBreak +
    'The download of the current and all subsequent debug PDB files ' +
    'will be interrupted, until the process is reopened.'),
    PChar(Application.Title), MB_YESNO or MB_ICONQUESTION or MB_DEFBUTTON2) = IDYES then
  begin
    ContinueState := scsCancel;
    RawScannerCore.DownloadPDB := False;
    if Assigned(dlgProgress) then
      dlgProgress.ProgressBarAdv.HintLabel.Text := 'Canceling...';
  end
  else
    ContinueState := scsRun;
end;

procedure TdlgProcessMM.OnGetWow64Heaps(Value: THeap);
var
  M: TMemoryStream;
begin
  M := GetWin32MemoryMap(MemoryMapCore.PID);
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
  LastProgressCaption := Step;
  dlgProgress.UpdateCaption(Step, APecent);
end;

procedure TdlgProcessMM.OnLog(ALevel: TLogLevel; AType: TLogType;
  const FuncName, Description: string);

  function LogStr: string;
  begin
    if FuncName = EmptyStr then
      Result := Description
    else
      Result := FuncName + ': ' + Description;
    case ALevel of
      llCore: Result := 'Core: ' + Result;
      llContext: Result := 'Context: ' + Result;
      llPE: Result := 'PE: ' + Result;
      llLoader: Result := 'Loader: ' + Result;
      llApiSet: Result := 'ApiSet: ' + Result;
      llDisasm: Result := 'Disasm: ' + Result;
      llWow64: Result := 'Wow64: ' + Result;
      llAnalizer: Result := 'Analizer: ' + Result;
    end;
  end;

  procedure Add(const AType, AData: string);
  begin
    DebugLog.Add(AType + AData);
  end;

begin
  case AType of
    ltNotify:   Add('', LogStr);
    ltInfo:     Add('[.]        ', LogStr);
    ltWarning:  Add('[+] WARN:  ', LogStr);
    ltError:    Add('[-] ERR:   ', LogStr);
    ltFatal:    Add('[-] FATAL: ', LogStr);
  end;
end;

procedure TdlgProcessMM.OnPdbLoad(Sender: TObject;
  State: TSymSrvProgressState; Pdb: TPdb; BytesReceived,
  TotalBytes: Int64; var AContinueState: TSymSrvContinueState);
begin
  if State = spsConnecting then
  begin
    dlgProgress.lblProgress.Caption :=
      dlgProgress.lblProgress.Caption + ' -> ' + Pdb.PdbName;
    dlgProgress.ProgressBarAdv.HintLabel.Visible := True;
    dlgProgress.ProgressBarAdv.HintLabel.Width := 130;
    dlgProgress.ProgressBarAdv.ShowCancelButton := True;
  end;
  dlgProgress.ProgressBarAdv.Visible := State = spsDownloading;
  if ContinueState = scsRun then
    dlgProgress.ProgressBarAdv.HintLabel.Text := 'Downloaded: ' + SizeToStr3(BytesReceived);
  dlgProgress.ProgressBarAdv.Max := TotalBytes;
  dlgProgress.ProgressBarAdv.Position := BytesReceived;
  AContinueState := ContinueState;
end;

procedure TdlgProcessMM.ProcessFirstRun;
begin
  if FirstRun then
  begin
    acSelectProcess.Execute;
    {$IFNDEF DEBUG}
    if Settings.CheckUpdates then
      CheckUpdates(True);
    {$ENDIF}
  end;
  FirstRun := False;
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

procedure TdlgProcessMM.TransmitDebugMapToSymbols;
var
  I: Integer;
  Items: TList<TDebugMapItem>;
  SymbolData: TSymbolData;
begin
  Items := MemoryMapCore.DebugMapData.Items;
  if Items.Count = 0 then Exit;
  SymbolData.Binary.ModuleIndex := 0;
  SymbolData.Binary.Param := 0;
  for I := 0 to Items.Count - 1 do
  begin
    SymbolData.AddrVA := Items.List[I].Address;
    if Items.List[I].Executable then
      SymbolData.DataType := sdtDebugMapFunction
    else
      SymbolData.DataType := sdtDebugMapData;
    SymbolData.Binary.ListIndex := I;
    SymbolStorage.Add(SymbolData);
  end;

  // Since the debug symbols have changed, they need to be updated,
  // otherwise the magic won't happen

  // [ru] так как отладочные символы изменились, надо их обновить
  // иначе никакого фокуса не получится

  SymbolStorage.PrepareForWork;
end;

end.
