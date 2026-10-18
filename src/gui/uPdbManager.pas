////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : uPdbManager.pas
//  * Purpose   : PDB Symbol Store Manager
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

unit uPdbManager;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, uBaseForm, System.SyncObjs,
  Generics.Collections, Generics.Defaults, Vcl.ComCtrls, VirtualTrees.BaseAncestorVCL,
  VirtualTrees.BaseTree, VirtualTrees.AncestorVCL, VirtualTrees, VirtualTrees.Types,
  Vcl.Menus, System.Math, System.UITypes, System.DateUtils, System.IOUtils,

  RawScanner.Core,
  RawScanner.Pdb,
  RawScanner.Wow64;

type
  TPdbActualState = (pasUnknown, pasActual, pasOldest, pasBroken, pasProcess, pasAny);
  TPdbFile = record
    ActualState: TPdbActualState;
    PdbPath, BinaryPath, RemotePath: string;
    Key: TPdbKey;
    Locked: Boolean;
    Downloaded, Size: Int64;
    State: TPdbState;
    SymCount: Integer;
    DownloadDate: TDateTime;
    Pdb: TPdb;
  end;

  TPdbFileList = class(TList<TPdbFile>);

  TCandidateFile = record
    Folder, FileName: string;
    Size: Int64;
  end;

  TCandidateFileList = class(TList<TCandidateFile>);

  TdlgPdbManager = class(TBaseAppForm)
    vstPdbData: TVirtualStringTree;
    StatusBar: TStatusBar;
    pmPdb: TPopupMenu;
    mnuFlag: TMenuItem;
    mnuFlagCurrentProcess: TMenuItem;
    mnuFlagOldest: TMenuItem;
    mnuFlagUnknown: TMenuItem;
    mnuFlagAll: TMenuItem;
    All2: TMenuItem;
    mnuDownloadSel: TMenuItem;
    mnuDeleteSel: TMenuItem;
    N1: TMenuItem;
    mnuOpenPDB: TMenuItem;
    mnuOpenBinary: TMenuItem;
    mnuFlagActual: TMenuItem;
    mnuDeleteAll: TMenuItem;
    mnuDownloadAll: TMenuItem;
    mnuPause: TMenuItem;
    mnuResume: TMenuItem;
    mnuLock: TMenuItem;
    mnuUnlock: TMenuItem;
    N2: TMenuItem;
    mnuStop: TMenuItem;
    mnuFlagBroken: TMenuItem;
    procedure FormAfterMonitorDpiChanged(Sender: TObject; OldDPI,
      NewDPI: Integer);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure mnuDeleteAllClick(Sender: TObject);
    procedure mnuDeleteSelClick(Sender: TObject);
    procedure mnuDownloadAllClick(Sender: TObject);
    procedure mnuDownloadSelClick(Sender: TObject);
    procedure mnuFlagCurrentProcessClick(Sender: TObject);
    procedure mnuLockClick(Sender: TObject);
    procedure mnuPauseClick(Sender: TObject);
    procedure mnuResumeClick(Sender: TObject);
    procedure mnuStopClick(Sender: TObject);
    procedure mnuUnlockClick(Sender: TObject);
    procedure mnuOpenBinaryClick(Sender: TObject);
    procedure mnuOpenPDBClick(Sender: TObject);
    procedure pmPdbPopup(Sender: TObject);
    procedure vstPdbDataAddToSelection(Sender: TBaseVirtualTree;
      Node: PVirtualNode);
    procedure vstPdbDataAfterCellPaint(Sender: TBaseVirtualTree;
      TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      CellRect: TRect);
    procedure vstPdbDataBeforeCellPaint(Sender: TBaseVirtualTree;
      TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
      CellPaintMode: TVTCellPaintMode; CellRect: TRect; var ContentRect: TRect);
    procedure vstPdbDataGetHint(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; var LineBreakStyle: TVTTooltipLineBreakStyle;
      var HintText: string);
    procedure vstPdbDataGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; TextType: TVstTextType; var CellText: string);
    procedure vstPdbDataHeaderClick(Sender: TVTHeader;
      HitInfo: TVTHeaderHitInfo);
  private
    FCurrentState: TPdbActualState;
    FFiles: TPdbFileList;
    FRemotePdb: TList<TPdb>;
    FQueue: TSymQueue;
    FBatchQueryMode, FClosePending: Boolean;
    FComparer: IEqualityComparer<TPdbKey>;
    FDict: TDictionary<TPdbKey, Integer>;
    FFilters: array [TPdbActualState] of TList<Integer>;
    FTotalSize, FSelCount, FSelSize: Integer;
    FSymSrvState, FPausedState: string;
    FFirstInitDone, FOnInit: Boolean;
    function CheckIsReadyForDeletePresent: Boolean;
    function CheckIsReadyForDownloadPresent: Boolean;
    function CheckIsSelectedReadyForDelete: Boolean;
    function CheckIsSelectedReadyForDownload: Boolean;
    function CheckPdbLibCandidate(const LibPath: string; Idx: Integer): Boolean;
    procedure CreatePdbLockFile(const PdbFolder: string);
    procedure CreateQueue(JobsCount: Integer);
    procedure DestroyQueue;
    procedure DeletePdb(const PdbFilePath: string);
    function IsDownloadDateShow: Boolean;
    function GetPdbAtNode(ANode: PVirtualNode): TPdbFile;
    function GetPdbStateColor(PdbFile: TPdbFile; ViewMode: TPdbActualState): TColor;
    function GetSelectedIndex: Integer;
    procedure InvalidateNode(PdbKey: TPdbKey);
    procedure Fill(AState: TPdbActualState);
    function GetPdbKeyFromPath(FilePath: string): TPdbKey;
    function GuessBinaryNamesFromPdb(const FilePath: string): TArray<string>;
    procedure ReInit;
    procedure RunQueryThread;
    procedure ScanFolder(const FolderPath: string; APdbList: TCandidateFileList);
    procedure ScanLoadedPdb;
    procedure ScanOldestPdb;
    procedure ScanPresentPdb(APdbList: TCandidateFileList);
    procedure Sort;
    procedure SymQueueBatchDone(Sender: TObject);
    procedure SymQueueJobDone(Sender: TObject; const Job: TSymJob; const Error: string);
    procedure SymQueueJobProgress(Sender: TObject; State: TSymSrvProgressState;
      Pdb: TPdb; BytesReceived, TotalBytes: Int64);
    procedure SymQueueStopped(Sender: TObject);
    procedure UpdateStatusBar;
    procedure UpdateStatusBarState(const Value: string);
  public
    procedure Init;
  end;

var
  dlgPdbManager: TdlgPdbManager;

implementation

uses
  uUtils,
  uProgress;

const
  PdbLockFileName = '.pmm-lock';

{$R *.dfm}

{ TdlgPdbManager }

function TdlgPdbManager.CheckIsReadyForDeletePresent: Boolean;
var
  I: Integer;
begin
  Result := False;
  for I in FFilters[FCurrentState] do
    if FileExists(FFiles.List[I].PdbPath) and not FFiles.List[I].Locked then
      Exit(True);
end;

function TdlgPdbManager.CheckIsReadyForDownloadPresent: Boolean;
var
  Pdb: TPdb;
begin
  Result := False;
  for Pdb in FRemotePdb do
    if Pdb.State = psAvailableForLoading then
      Exit(True);
end;

function TdlgPdbManager.CheckIsSelectedReadyForDelete: Boolean;
var
  E: TVTVirtualNodeEnumerator;
  I: Integer;
begin
  Result := False;
  E := vstPdbData.SelectedNodes.GetEnumerator;
  while E.MoveNext do
  begin
    I := FFilters[FCurrentState][E.Current^.Index];
    if FileExists(FFiles.List[I].PdbPath) and not FFiles.List[I].Locked then
      Exit(True);
  end;
end;

function TdlgPdbManager.CheckIsSelectedReadyForDownload: Boolean;
var
  E: TVTVirtualNodeEnumerator;
begin
  Result := False;
  E := vstPdbData.SelectedNodes.GetEnumerator;
  while E.MoveNext do
    if FFiles.List[FFilters[FCurrentState][E.Current^.Index]].State = psAvailableForLoading then
      Exit(True);
end;

function TdlgPdbManager.CheckPdbLibCandidate(const LibPath: string;
  Idx: Integer): Boolean;
var
  LibKey: TPdbKey;
begin
  Result := False;
  if not FileExists(LibPath) then Exit;
  if not GetImagePdbKey(LibPath, LibKey) then Exit;
  Result := True;
  if IsPdbKeyEqual(LibKey, FFiles.List[Idx].Key) then
    FFiles.List[Idx].ActualState := pasActual
  else
    FFiles.List[Idx].ActualState := pasOldest;
  FFilters[FFiles.List[Idx].ActualState].Add(Idx);
  FFiles.List[Idx].BinaryPath := LibPath;
end;

procedure TdlgPdbManager.CreatePdbLockFile(const PdbFolder: string);
var
  LockFilePath: string;
  Lines: TStringList;
begin
  LockFilePath := PdbFolder + PdbLockFileName;
  if FileExists(LockFilePath) then Exit;
  Lines := TStringList.Create;
  try
    Lines.Add('LockedAt=' + DateTimeToStr(Now));
    Lines.Add('LockedBy=' + DateToISO8601(TTimeZone.Local.ToUniversalTime(Now)));
    Lines.SaveToFile(LockFilePath, TEncoding.UTF8);
  finally
    Lines.Free;
  end;
  {$WARN SYMBOL_PLATFORM OFF}
  FileSetAttr(LockFilePath, faHidden);
  {$WARN SYMBOL_PLATFORM ON}
end;

procedure TdlgPdbManager.CreateQueue(JobsCount: Integer);
begin
  FQueue := TSymQueue.Create(RawScannerCore.PdbStorage, Min(JobsCount, 8));
  FQueue.OnBatchDone := SymQueueBatchDone;
  FQueue.OnJobDone := SymQueueJobDone;
  FQueue.OnProgress := SymQueueJobProgress;
  FQueue.OnStopped := SymQueueStopped;
  FBatchQueryMode := True;
end;

procedure TdlgPdbManager.DeletePdb(const PdbFilePath: string);
var
  Files: TArray<string>;
  S: string;
  Folder, PrevFolder: string;
begin
  DeleteFile(PdbFilePath);
  Files := TDirectory.GetFiles(ExtractFilePath(PdbFilePath), '*.*');
  for S in Files do
  begin
    if ExtractFileName(S) = PdbLockFileName then
    begin
      DeleteFile(S);
      Continue;
    end;
    if ExtractFileName(S) = PdbInfoFile then
    begin
      DeleteFile(S);
      Continue;
    end;
    Exit;
  end;
  Folder := ExtractFileDir(PdbFilePath);
  repeat
    if TDirectory.IsEmpty(Folder) then
    begin
      RemoveDir(Folder);
      PrevFolder := Folder;
      Folder := ExtractFileDir(ExcludeTrailingPathDelimiter(Folder));
    end
    else
      Break;
  until (Folder = PrevFolder) or (Folder = '');
end;

procedure TdlgPdbManager.DestroyQueue;
begin
  if Assigned(FQueue) then
  begin
    FQueue.OnJobDone := nil;
    FQueue.OnBatchDone := nil;
    FQueue.OnProgress := nil;
    UpdateStatusBarState('SYMSRV: Waiting for symbol server tasks to finish...');
    StatusBar.Repaint;
    FQueue.Stop;
  end;
end;

procedure TdlgPdbManager.mnuDeleteAllClick(Sender: TObject);
var
  Idx: Integer;
  List: TList<Integer>;
begin
  List := TList<Integer>.Create;
  try
    for Idx in FFilters[FCurrentState] do
      if FileExists(FFiles[Idx].PdbPath) and not FFiles[Idx].Locked then
        List.Add(Idx);

    if List.Count = 0 then Exit;

    if MessageBox(Handle, PChar(Format('Delete all %d symbol file(s) in this list?',
      [List.Count])), PChar(Application.Title), MB_ICONQUESTION or MB_YESNO or MB_DEFBUTTON2) = ID_NO then
      Exit;

    vstPdbData.RootNodeCount := 0;
    for Idx in List do
    begin
      DeletePdb(FFiles[Idx].PdbPath);
      if Assigned(FFiles[Idx].Pdb) then
        FFiles[Idx].Pdb.Reset;
    end;
    ReInit;
  finally
    List.Free;
  end;
end;

procedure TdlgPdbManager.mnuDeleteSelClick(Sender: TObject);
var
  E: TVTVirtualNodeEnumerator;
  Idx: Integer;
  List: TList<Integer>;
begin
  E := vstPdbData.SelectedNodes.GetEnumerator;
  List := TList<Integer>.Create;
  try
    while E.MoveNext do
    begin
      Idx := FFilters[FCurrentState][E.Current^.Index];
      if FileExists(FFiles[Idx].PdbPath) and not FFiles[Idx].Locked then
        List.Add(Idx)
    end;
    if List.Count = 0 then Exit;

    if MessageBox(Handle, PChar(Format('Delete %d selected symbol file(s)?',
      [List.Count])), PChar(Application.Title), MB_ICONQUESTION or MB_YESNO or MB_DEFBUTTON2) = ID_NO then
      Exit;

    vstPdbData.RootNodeCount := 0;
    for Idx in List do
    begin
      DeletePdb(FFiles[Idx].PdbPath);
      if Assigned(FFiles[Idx].Pdb) then
        FFiles[Idx].Pdb.Reset;
    end;
    ReInit;
  finally
    List.Free;
  end;
end;

procedure TdlgPdbManager.mnuDownloadAllClick(Sender: TObject);
var
  List: TList<TPdb>;
  Pdb: TPdb;
begin
  List := TList<TPdb>.Create;
  try
    for Pdb in FRemotePdb do
      if Pdb.State = psAvailableForLoading then
        List.Add(Pdb);
    if List.Count = 0 then Exit;
    CreateQueue(List.Count);
    UpdateStatusBarState('SYMSRV: Download...');
    for Pdb in List do
      FQueue.DownloadPdb(Pdb);
  finally
    List.Free;
  end;
end;

procedure TdlgPdbManager.mnuDownloadSelClick(Sender: TObject);
var
  E: TVTVirtualNodeEnumerator;
  Idx: Integer;
  List: TList<Integer>;
begin
  E := vstPdbData.SelectedNodes.GetEnumerator;
  List := TList<Integer>.Create;
  try
    while E.MoveNext do
    begin
      Idx := FFilters[FCurrentState][E.Current^.Index];
      if FFiles.List[Idx].State = psAvailableForLoading then
        List.Add(Idx);
    end;
    if List.Count = 0 then Exit;
    CreateQueue(List.Count);
    UpdateStatusBarState('SYMSRV: Download...');
    for Idx in List do
      FQueue.DownloadPdb(RawScannerCore.PdbStorage.QueryPDB(FFiles.List[Idx].Key));
  finally
    List.Free;
  end;
end;

procedure TdlgPdbManager.mnuFlagCurrentProcessClick(Sender: TObject);
begin
  if FCurrentState <> TPdbActualState(TMenuItem(Sender).Tag) then
    Fill(TPdbActualState(TMenuItem(Sender).Tag));
end;

procedure TdlgPdbManager.mnuLockClick(Sender: TObject);
var
  E: TVTVirtualNodeEnumerator;
  Idx: Integer;
begin
  E := vstPdbData.SelectedNodes.GetEnumerator;
  while E.MoveNext do
  begin
    Idx := FFilters[FCurrentState][E.Current^.Index];
    CreatePdbLockFile(ExtractFilePath(FFiles.List[Idx].PdbPath));
    FFiles.List[Idx].Locked := True;
    InvalidateNode(FFiles.List[Idx].Key);
  end;
end;

procedure TdlgPdbManager.mnuPauseClick(Sender: TObject);
begin
  FPausedState := FSymSrvState;
  FQueue.Pause;
  UpdateStatusBarState('SYMSRV: Pause');
end;

procedure TdlgPdbManager.mnuResumeClick(Sender: TObject);
begin
  FQueue.Resume;
  UpdateStatusBarState(FPausedState);
end;

procedure TdlgPdbManager.mnuStopClick(Sender: TObject);
begin
  DestroyQueue;
  FBatchQueryMode := True;
  SymQueueBatchDone(nil);
end;

procedure TdlgPdbManager.mnuUnlockClick(Sender: TObject);
var
  E: TVTVirtualNodeEnumerator;
  LockPath: string;
  Idx: Integer;
begin
  E := vstPdbData.SelectedNodes.GetEnumerator;
  while E.MoveNext do
  begin
    Idx := FFilters[FCurrentState][E.Current^.Index];
    LockPath := ExtractFilePath(FFiles.List[Idx].PdbPath) + PdbLockFileName;
    if DeleteFile(LockPath) then
      FFiles.List[Idx].Locked := False;
    InvalidateNode(FFiles.List[Idx].Key);
  end;
end;

procedure TdlgPdbManager.Fill(AState: TPdbActualState);
var
  I: Integer;
begin
  FCurrentState := AState;
  if IsDownloadDateShow then
    vstPdbData.Header.Columns[4].Text := 'Date'
  else
    vstPdbData.Header.Columns[4].Text := 'SymCount';
  FTotalSize := 0;
  for I := 0 to FFilters[AState].Count - 1 do
    Inc(FTotalSize, FFiles.List[FFilters[AState][I]].Size);
  vstPdbData.BeginUpdate;
  try
    vstPdbData.RootNodeCount := FFilters[AState].Count;
    Sort;
  finally
    vstPdbData.EndUpdate;
  end;
  UpdateStatusBar;
  UpdateStatusBarState(FSymSrvState);
end;

procedure TdlgPdbManager.FormAfterMonitorDpiChanged(Sender: TObject; OldDPI,
  NewDPI: Integer);
begin
  inherited;
  FixVirtualStringTreeDpiBug(vstPdbData);
end;

procedure TdlgPdbManager.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  inherited;
  Action := caFree;
end;

procedure TdlgPdbManager.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  inherited;
  if FClosePending then
  begin
    CanClose := False;
    Exit;
  end;
  if FQueue <> nil then
  begin
    CanClose := False;
    FQueue.Pause;
    try
      if MessageBox(Handle, PChar('Symbol server operation in progress.' + sLineBreak +
        'Stop it and close the window?'), PChar(Application.Title),
        MB_ICONQUESTION or MB_YESNO or MB_DEFBUTTON2) = ID_YES then
      begin
        DestroyQueue;
        FClosePending := True;
      end;
    finally
      if not FClosePending then
        FQueue.Resume;
    end;
  end;
end;

procedure TdlgPdbManager.FormCreate(Sender: TObject);
begin
  inherited;
  FFiles := TPdbFileList.Create;
  FRemotePdb := TList<TPdb>.Create;
  FComparer := TPdbKeyComparer.Create;
  FDict := TDictionary<TPdbKey, Integer>.Create(FComparer);
  FFilters[pasUnknown] := TList<Integer>.Create;
  FFilters[pasActual] := TList<Integer>.Create;
  FFilters[pasOldest] := TList<Integer>.Create;
  FFilters[pasProcess] := TList<Integer>.Create;
  FFilters[pasBroken] := TList<Integer>.Create;
  FFilters[pasAny] := TList<Integer>.Create;
  Init;
  if FRemotePdb.Count > 0 then
  begin
    vstPdbData.Header.SortColumn := 2;
    vstPdbData.Header.SortDirection := sdAscending;
  end;
  Fill(pasProcess);
  RunQueryThread;
end;

procedure TdlgPdbManager.FormDestroy(Sender: TObject);
begin
  inherited;
  FFiles.Free;
  FRemotePdb.Free;
  FDict.Free;
  FFilters[pasUnknown].Free;
  FFilters[pasActual].Free;
  FFilters[pasOldest].Free;
  FFilters[pasProcess].Free;
  FFilters[pasBroken].Free;
  FFilters[pasAny].Free;
  dlgPdbManager := nil;
end;

function TdlgPdbManager.GetPdbAtNode(ANode: PVirtualNode): TPdbFile;
begin
  if FOnInit or (ANode.Index >= FFilters[FCurrentState].Count) then
    Result := Default(TPdbFile)
  else
    Result := FFiles[FFilters[FCurrentState][ANode.Index]];
end;

function TdlgPdbManager.GetPdbKeyFromPath(FilePath: string): TPdbKey;
begin
  Result := Default(TPdbKey);
  Result.Name := ExtractFileName(FilePath);
  FilePath := ExtractFileName(ExcludeTrailingPathDelimiter(ExtractFilePath(FilePath)));
  TryStrToUInt(Copy(FilePath, 33, Length(FilePath)), Result.Age);
  SetLength(FilePath, 32);
  FilePath := '{' +
    Copy(FilePath, 1, 8) + '-' +
    Copy(FilePath, 9, 4) + '-' +
    Copy(FilePath, 13, 4) + '-' +
    Copy(FilePath, 17, 4) + '-' +
    Copy(FilePath, 21, 12) + '}';
  Result.Uid := StringToGUID(FilePath);
end;

function TdlgPdbManager.GetPdbStateColor(PdbFile: TPdbFile;
  ViewMode: TPdbActualState): TColor;
const
  clPdbActual    = TColor($00C7E4B7);
  clPdbAvailable = TColor($00AEDFBF);
  clPdbLoading   = TColor($00FFAB94);
  clPdbBroken    = TColor($00A8A9F4);
  clPdbMissing   = TColor($00D4D9FF);
  clPdbOutdated  = TColor($009FC5F7);
  clPdbLocked    = TColor($00E2B4D8);
begin
  Result := 0;
  case ViewMode of
    pasActual:
      if PdbFile.State = psReady then
        Result := clPdbActual;

    pasProcess:
    begin
      case PdbFile.State of
        psNotFoundLocally,
        psNotFoundAnywhere: Result := clPdbMissing;
        psBroken: Result := clPdbBroken;
        psAvailableForLoading: Result := clPdbAvailable;
        psLoading: Result := clPdbLoading;
      end;
      Exit;
    end;

    pasAny:
    begin
      case PdbFile.ActualState of
        pasUnknown: Result := clPdbMissing;
        pasActual: Result := clPdbActual;
        pasOldest: Result := clPdbOutdated;
      end;
    end;
  end;

  if PdbFile.Locked then
    Result := clPdbLocked;
end;

function TdlgPdbManager.GetSelectedIndex: Integer;
var
  E: TVTVirtualNodeEnumerator;
begin
  E := vstPdbData.SelectedNodes.GetEnumerator;
  if not E.MoveNext then Exit(-1);
  Result := E.Current^.Index;
end;

function TdlgPdbManager.GuessBinaryNamesFromPdb(
  const FilePath: string): TArray<string>;
var
  FileName: string;
begin
  FileName := AnsiLowerCase(ExtractFileName(FilePath));
  if FileName = '' then Exit;
  FileName := ChangeFileExt(FileName, '.dll');
  if FileName[1] = 'w' then
  begin
    SetLength(Result, 2);
    Result[0] := FileName;
    Result[1] := Copy(FileName, 2, Length(FileName) - 1);
  end
  else
  begin
    SetLength(Result, 1);
    Result[0] := FileName;
  end;
end;

procedure TdlgPdbManager.Init;
var
  Cache: string;
  PdbList: TCandidateFileList;
begin
  FOnInit := True;
  try
    FFiles.Clear;
    FRemotePdb.Clear;
    FDict.Clear;
    FFilters[pasUnknown].Clear;
    FFilters[pasActual].Clear;
    FFilters[pasOldest].Clear;
    FFilters[pasBroken].Clear;
    FFilters[pasProcess].Clear;
    FFilters[pasAny].Clear;

    PdbList := TCandidateFileList.Create;
    try
      for Cache in RawScannerCore.PdbStorage.CacheFolders do
        ScanFolder(Cache, PdbList);
      if FFirstInitDone then
        ScanPresentPdb(PdbList)
      else
      begin
        dlgProgress := TdlgProgress.Create(Application);
        try
          dlgProgress.ProgressBar.Max := PdbList.Count;
          dlgProgress.lblProgress.Caption := 'Pdb Storages initialization...';
          dlgProgress.Show;
          ScanPresentPdb(PdbList);
          FFirstInitDone := True;
        finally
          dlgProgress.Free;
        end;
      end;
    finally
      PdbList.Free;
    end;

    ScanLoadedPdb;
    ScanOldestPdb;
  finally
    FOnInit := False;
  end;
end;

procedure TdlgPdbManager.InvalidateNode(PdbKey: TPdbKey);
var
  I: Integer;
  Node: PVirtualNode;
begin
  for I := 0 to FFilters[FCurrentState].Count - 1 do
    if IsPdbKeyEqual(PdbKey, FFiles[FFilters[FCurrentState][I]].Key) then
    begin
      Node := vstPdbData.GetFirst;
      while (Node <> nil) and (Node^.Index < Cardinal(I)) do
        Node := vstPdbData.GetNext(Node);
      if Node = nil then
        vstPdbData.Invalidate
      else
        vstPdbData.InvalidateNode(Node);
    end;
end;

function TdlgPdbManager.IsDownloadDateShow: Boolean;
begin
  Result := FCurrentState in [pasUnknown, pasOldest, pasBroken];
end;

procedure TdlgPdbManager.mnuOpenBinaryClick(Sender: TObject);
begin
  OpenExplorerAndSelectFile(FFiles.List[FFilters[FCurrentState][GetSelectedIndex]].BinaryPath);
end;

procedure TdlgPdbManager.mnuOpenPDBClick(Sender: TObject);
begin
  OpenExplorerAndSelectFile(FFiles.List[FFilters[FCurrentState][GetSelectedIndex]].PdbPath);
end;

procedure TdlgPdbManager.pmPdbPopup(Sender: TObject);
var
  Idx: Integer;
begin
  Idx := GetSelectedIndex;
  if Idx >= 0 then
    Idx := FFilters[FCurrentState][Idx];
  mnuFlagUnknown.Visible := FFilters[pasUnknown].Count > 0;
  mnuFlagBroken.Visible := FFilters[pasBroken].Count > 0;
  mnuDeleteSel.Visible := (FCurrentState <> pasProcess) and CheckIsSelectedReadyForDelete;
  mnuDeleteAll.Visible := (FCurrentState in [pasOldest, pasBroken]) and CheckIsReadyForDeletePresent;
  mnuDownloadAll.Visible := (FCurrentState = pasProcess) and (FQueue = nil) and CheckIsReadyForDownloadPresent;
  mnuDownloadSel.Visible := mnuDownloadAll.Visible and CheckIsSelectedReadyForDownload;
  mnuPause.Visible := Assigned(FQueue) and (FQueue.ContinueState = scsRun);
  mnuResume.Visible := Assigned(FQueue) and (FQueue.ContinueState = scsPause);
  mnuStop.Visible := Assigned(FQueue);
  mnuLock.Visible := (Idx >= 0) and not FFiles.List[Idx].Locked;
  mnuUnlock.Visible := (Idx >= 0) and FFiles.List[Idx].Locked;
  mnuOpenPDB.Visible := (Idx >= 0) and FileExists(FFiles.List[Idx].PdbPath);
  mnuOpenBinary.Visible := (Idx >= 0) and FileExists(FFiles.List[Idx].BinaryPath);
  mnuFlagCurrentProcess.Checked := FCurrentState = pasProcess;
  mnuFlagOldest.Checked := FCurrentState = pasOldest;
  mnuFlagUnknown.Checked := FCurrentState = pasUnknown;
  mnuFlagAll.Checked := FCurrentState = pasAny;
  mnuFlagActual.Checked := FCurrentState = pasActual;
  mnuFlagBroken.Checked := FCurrentState = pasBroken;
end;

procedure TdlgPdbManager.ReInit;
begin
  Init;
  Fill(FCurrentState);
end;

procedure TdlgPdbManager.RunQueryThread;
var
  Pdb: TPdb;
  List: TList<TPdb>;
begin
  if FRemotePdb.Count = 0 then Exit;
  List := TList<TPdb>.Create;
  try
    for Pdb in FRemotePdb do
      if Pdb.State = psNotFoundLocally then
        List.Add(Pdb);
    if List.Count = 0 then Exit;
    CreateQueue(List.Count);
    for Pdb in FRemotePdb do
      FQueue.QueryPdb(Pdb);
  finally
    List.Free;
  end;
  UpdateStatusBarState('SYMSRV: querying...')
end;

procedure TdlgPdbManager.ScanFolder(const FolderPath: string; APdbList: TCandidateFileList);
var
  SR: TSearchRec;
  Candidate: TCandidateFile;
begin
  if FindFirst(FolderPath + '*', faAnyFile, SR) = 0 then
  try
    repeat
      if SR.Name = '.' then Continue;
      if SR.Name = '..' then Continue;
      if DirectoryExists(FolderPath + SR.Name) then
      begin
        ScanFolder(FolderPath + SR.Name + PathDelim, APdbList);
        Continue;
      end;
      if AnsiLowerCase(ExtractFileExt(SR.Name)) = '.pdb' then
      begin
        Candidate.Folder := FolderPath;
        Candidate.FileName := SR.Name;
        Candidate.Size := SR.Size;
        APdbList.Add(Candidate);
      end;
    until FindNext(SR) <> 0;
  finally
    FindClose(SR);
  end;
end;

procedure TdlgPdbManager.ScanLoadedPdb;
var
  Pdb: TPdb;
  PdbFile: TPdbFile;
  Idx: Integer;
begin
  for Pdb in RawScannerCore.PdbStorage.Items do
  begin
    if FDict.TryGetValue(Pdb.Key, Idx) then
    begin
      FFiles.List[Idx].ActualState := pasActual;
      FFiles.List[Idx].State := Pdb.State;
      FFiles.List[Idx].SymCount := Pdb.Count;
      FFiles.List[Idx].BinaryPath := Pdb.BinaryPath;
      FFilters[pasProcess].Add(Idx);
    end
    else
    begin
      PdbFile := Default(TPdbFile);
      PdbFile.Key := Pdb.Key;
      PdbFile.BinaryPath := Pdb.BinaryPath;
      PdbFile.RemotePath := Pdb.GetRemotePath;
      PdbFile.State := Pdb.State;
      Idx := FFiles.Add(PdbFile);
      FDict.Add(PdbFile.Key, Idx);
      FFilters[pasProcess].Add(Idx);
    end;
    FFiles.List[Idx].Pdb := Pdb;
    if Pdb.State in [psNotFoundLocally, psAvailableForLoading] then
      FRemotePdb.Add(Pdb);
    if Pdb.State = psBroken then
    begin
      FFiles.List[Idx].ActualState := pasBroken;
      FFilters[pasBroken].Add(Idx);
    end;
  end;
end;

procedure TdlgPdbManager.ScanOldestPdb;
var
  I: Integer;
  WinDir, System32Path, SysWOW64Path, Candidate: string;
  CandidateNames: TArray<string>;
  PdbFile: TPdbFile;
begin
  WinDir := IncludeTrailingPathDelimiter(GetEnvironmentVariable('windir'));
  System32Path := WinDir + 'System32\';
  SysWOW64Path := WinDir + 'SysWOW64\';
  Wow64Support.DisableRedirection;
  try
    for I := 0 to FFiles.Count - 1 do
    begin
      PdbFile := FFiles[I];
      if not FileExists(PdbFile.PdbPath) then Continue;
      if PdbFile.State = psBroken then Continue;      
      if (PdbFile.BinaryPath <> '') and FileExists(PdbFile.BinaryPath) then
        CheckPdbLibCandidate(PdbFile.BinaryPath, I)
      else
      begin
        CandidateNames := GuessBinaryNamesFromPdb(PdbFile.PdbPath);
        for Candidate in CandidateNames do
        begin
          if CheckPdbLibCandidate(System32Path + Candidate, I) then Break;
          if CheckPdbLibCandidate(SysWOW64Path + Candidate, I) then Break;
        end;
      end;
      if FFiles.List[I].ActualState = pasUnknown then
        FFilters[pasUnknown].Add(I);
    end;
  finally
    Wow64Support.EnableRedirection;
  end;
end;

procedure TdlgPdbManager.ScanPresentPdb(APdbList: TCandidateFileList);
var
  Candidate: TCandidateFile;
  PdbFile: TPdbFile;
  I, Idx: Integer;
  Info: TPdbInfo;
begin
  PdbFile := Default(TPdbFile);
  for I := 0 to APdbList.Count - 1 do
  begin
    Candidate := APdbList[I];
    if dlgProgress <> nil then
      dlgProgress.UpdateCaption(Candidate.FileName, I);
    PdbFile.PdbPath := Candidate.Folder + Candidate.FileName;
    PdbFile.Key := GetPdbKeyFromPath(PdbFile.PdbPath);
    PdbFile.Locked := FileExists(Candidate.Folder + PdbLockFileName);
    PdbFile.Size := Candidate.Size;
    if LoadPdbInfo(Candidate.Folder, Info) then
    begin
      PdbFile.BinaryPath := Info.RequestedForBinaryPath;
      PdbFile.DownloadDate := Info.DownloadedAt;
    end;
    Idx := FFiles.Add(PdbFile);
    FDict.Add(PdbFile.Key, Idx);
    FFilters[pasAny].Add(Idx);
  end;
end;

procedure TdlgPdbManager.Sort;
var
  List: TList<Integer>;
begin
  if vstPdbData.Header.SortColumn < 0 then Exit;
  List := FFilters[FCurrentState];
  List.Sort(TComparer<Integer>.Construct(
    function (const A, B: Integer): Integer
    begin
      Result := 0;
      if A = B then Exit;      
      case vstPdbData.Header.SortColumn of
        0: Result := AnsiCompareText(FFiles.List[A].BinaryPath, FFiles.List[B].BinaryPath);
        1: Result := AnsiCompareText(FFiles.List[A].Key.Name, FFiles.List[B].Key.Name);
        2: 
        begin
          case FCurrentState of
            pasActual, pasAny: 
            begin
              Result := Integer(FFiles.List[A].ActualState) - Integer(FFiles.List[B].ActualState);
              if Result = 0 then
                // Reversed so that Loaded PDBs appear above Actual ones
                Result := Integer(FFiles.List[B].State) - Integer(FFiles.List[A].State);
              if (Result = 0) and (FCurrentState = pasAny) then
                Result := Integer(FFiles.List[A].Locked) - Integer(FFiles.List[B].Locked);
            end;
            pasProcess: Result := Integer(FFiles.List[A].State) - Integer(FFiles.List[B].State);
          else
            Result := Integer(FFiles.List[A].ActualState) - Integer(FFiles.List[B].ActualState);
            if Result = 0 then
              Result := Integer(FFiles.List[A].Locked) - Integer(FFiles.List[B].Locked);
          end;           
        end;
        3: Result := FFiles.List[A].Size - FFiles.List[B].Size;
        4:
        begin
          if IsDownloadDateShow then
            Result := CompareDateTime(FFiles.List[A].DownloadDate, FFiles.List[B].DownloadDate)
          else
            Result := FFiles.List[A].SymCount - FFiles.List[B].SymCount;
        end;
      end;
      if vstPdbData.Header.SortDirection = sdDescending then
        Result := -Result;
    end)); 
end;

procedure TdlgPdbManager.SymQueueBatchDone(Sender: TObject);
const
  StateDone: array [Boolean] of TPdbState = (psReady, psAvailableForLoading);
var
  I, Cnt: Integer;
begin
  Cnt := 0;
  for I := 0 to FRemotePdb.Count - 1 do
    if FRemotePdb[I].State = StateDone[FBatchQueryMode] then
      Inc(Cnt);
  if FBatchQueryMode then
    UpdateStatusBarState(Format('SYMSRV: %d file(s) available for download', [Cnt]))
  else
  begin
    UpdateStatusBarState(Format('SYMSRV: %d file(s) loaded', [Cnt]));
    ReInit;
  end;
  FQueue.Stop;
end;

procedure TdlgPdbManager.SymQueueJobDone(Sender: TObject; const Job: TSymJob;
  const Error: string);
var
  Idx, ModIdx: Integer;
begin
  if FDict.TryGetValue(Job.Pdb.Key, Idx) then
  begin
    FFiles.List[Idx].State := Job.Pdb.State;
    case Job.Pdb.State of
      psAvailableForLoading:
        FFiles.List[Idx].RemotePath := Job.Pdb.GetRemotePath;
      psNoSections, psReady:
      begin
        SavePdbInfo(Job.Pdb, FFiles.List[Idx].BinaryPath);
        FFiles.List[Idx].PdbPath := Job.Pdb.LocalPath;
        FFiles.List[Idx].Size := TFile.GetSize(FFiles.List[Idx].PdbPath);
        ModIdx := RawScannerCore.Modules.GetModule(FFiles.List[Idx].BinaryPath);
        RawScannerCore.LoadPdb(RawScannerCore.Modules.Items[ModIdx], Job.Pdb);
        FFiles.List[Idx].Downloaded := 0;
        FFiles.List[Idx].SymCount := Job.Pdb.Count;
      end;
    end;
    InvalidateNode(Job.Pdb.Key);
  end;
end;

procedure TdlgPdbManager.SymQueueJobProgress(Sender: TObject;
  State: TSymSrvProgressState; Pdb: TPdb; BytesReceived,
  TotalBytes: Int64);
var
  Idx: Integer;
begin
  FBatchQueryMode := False;
  if FDict.TryGetValue(Pdb.Key, Idx) then
  begin
    FFiles.List[Idx].State := psLoading;
    FFiles.List[Idx].Size := TotalBytes;
    FFiles.List[Idx].Downloaded := BytesReceived;
    InvalidateNode(Pdb.Key);
  end;
end;

procedure TdlgPdbManager.SymQueueStopped(Sender: TObject);
begin
  FreeAndNil(FQueue);
  if FClosePending then
    Release
  else
    ReInit;
end;

procedure TdlgPdbManager.UpdateStatusBar;
begin
  StatusBar.Panels[0].Text := Format('Total: %d, size: %s', [vstPdbData.RootNodeCount, SizeToStr3(FTotalSize)]);
  StatusBar.Panels[1].Text := Format('Select: %d, size: %s', [FSelCount, SizeToStr3(FSelSize)]);    
end;

procedure TdlgPdbManager.UpdateStatusBarState(const Value: string);
begin
  if FCurrentState = pasProcess then
  begin
    StatusBar.Panels[2].Text := Value;
    FSymSrvState := Value;
  end
  else
    StatusBar.Panels[2].Text := '';
end;

procedure TdlgPdbManager.vstPdbDataAddToSelection(Sender: TBaseVirtualTree;
  Node: PVirtualNode);
var
  E: TVTVirtualNodeEnumerator;
begin
  E := vstPdbData.SelectedNodes.GetEnumerator;
  FSelSize := 0;
  FSelCount := 0;
  while E.MoveNext do
  begin
    Inc(FSelCount);
    Inc(FSelSize, FFiles.List[FFilters[FCurrentState][E.Current^.Index]].Size);
  end;
  UpdateStatusBar;
end;

procedure TdlgPdbManager.vstPdbDataAfterCellPaint(Sender: TBaseVirtualTree;
  TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
  CellRect: TRect);
const
  ProgressBarHeight = 3;
  ValidProgressColor = $00D77800;
  InvalidProgressColor = $000078D7;
var
  PdbFile: TPdbFile;
  Percent: Double;
  FullRowRect, ProgressRect, VisiblePart: TRect;
begin
  PdbFile := GetPdbAtNode(Node);
  if PdbFile.State <> psLoading then
    Exit;

  if PdbFile.Size = 0 then
    Percent := 1.0
  else
  begin
    Percent := PdbFile.Downloaded / PdbFile.Size;
    if Percent > 1.0 then Percent := 1.0;
    if Percent < 0 then Percent := 0;
  end;

  FullRowRect := Rect(0, CellRect.Top, Sender.ClientWidth, CellRect.Bottom);

  ProgressRect := Rect(
    FullRowRect.Left,
    FullRowRect.Bottom - MulDiv(ProgressBarHeight, FCurrentPPI, USER_DEFAULT_SCREEN_DPI),
    FullRowRect.Left + Round(FullRowRect.Width * Percent),
    FullRowRect.Bottom);

  if IntersectRect(VisiblePart, ProgressRect, CellRect) then
  begin
    if PdbFile.Size = 0 then
      TargetCanvas.Brush.Color := InvalidProgressColor
    else
      TargetCanvas.Brush.Color := ValidProgressColor;
    TargetCanvas.FillRect(VisiblePart);
  end;
end;

procedure TdlgPdbManager.vstPdbDataBeforeCellPaint(Sender: TBaseVirtualTree;
  TargetCanvas: TCanvas; Node: PVirtualNode; Column: TColumnIndex;
  CellPaintMode: TVTCellPaintMode; CellRect: TRect; var ContentRect: TRect);
var
  PdbFile: TPdbFile;
  AColor: TColor;
begin
  if not (Column in [1, 2]) then Exit;
  PdbFile := GetPdbAtNode(Node);
  if (Column = 1) and (PdbFile.State <> psNotFoundAnywhere) then Exit;
  AColor := GetPdbStateColor(PdbFile, FCurrentState);
  if AColor <> 0 then
  begin
    TargetCanvas.Brush.Color := AColor;
    TargetCanvas.FillRect(CellRect);
  end;
end;

procedure TdlgPdbManager.vstPdbDataGetHint(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex;
  var LineBreakStyle: TVTTooltipLineBreakStyle; var HintText: string);
var
  CellText: string;
  CellRect: TRect;
  TextRect: TRect;
begin
  HintText := '';
  if Column < 0 then Exit;
  CellText := vstPdbData.Text[Node, Column];
  if CellText = '' then Exit;
  CellRect := vstPdbData.GetDisplayRect(Node, Column, True);
  InflateRect(CellRect, -1, 0);
  vstPdbData.Canvas.Font := vstPdbData.Font;
  TextRect := CellRect;
  DrawText(vstPdbData.Canvas.Handle, PChar(CellText), Length(CellText), TextRect,
    DT_CALCRECT or DT_SINGLELINE or DT_NOPREFIX);
  if (TextRect.Right - TextRect.Left) > (CellRect.Right - CellRect.Left) then
    HintText := CellText;
end;

procedure TdlgPdbManager.vstPdbDataGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; TextType: TVstTextType;
  var CellText: string);
const
  PdbStateStr: array [TPdbState] of string = (
    'NotFoundLocally',
    'NotFoundAnywhere',
    'AvailableForLoad',
    'Loading',
    'NoSections',
    'Broken',
    'Ready'
  );
  PdbActualStateStr: array [TPdbActualState] of string = (
    'Unknown', 'Actual', 'Oldest', 'Broken', '', '');
var
  PdbFile: TPdbFile;
begin
  PdbFile := GetPdbAtNode(Node);
  case Column of
    0: CellText := PdbFile.BinaryPath;
    1: 
    begin
      if PdbFile.State = psAvailableForLoading then
        CellText := PdbFile.RemotePath
      else      
        CellText := PdbFile.Key.Name;
    end;
    2:
    begin
      if FCurrentState = pasProcess then
      begin
        if (PdbFile.State = psNotFoundLocally) and Assigned(FQueue) then
          CellText := 'Query...'
        else
          CellText := PdbStateStr[PdbFile.State];
      end
      else
      begin
        if PdbFile.State = psReady then
          CellText := 'Loaded'
        else
          CellText := PdbActualStateStr[PdbFile.ActualState];
      end;
      if PdbFile.Locked then
        CellText := CellText + '/Locked';
    end;
    3:
    begin
      if PdbFile.State = psLoading then
      begin
        if PdbFile.Size <> 0 then
          CellText := Format('%s of %s', [SizeToStr3(PdbFile.Downloaded), SizeToStr3(PdbFile.Size)])
        else
          CellText := SizeToStr3(PdbFile.Downloaded);
      end
      else
      begin
        if PdbFile.Size <> 0 then
          CellText := SizeToStr3(PdbFile.Size)
        else
          CellText := '';
      end;
    end;
    4:
    begin
      if IsDownloadDateShow then
      begin
        if PdbFile.DownloadDate = 0 then
          CellText := ''
        else
          CellText := DateTimeToStr(PdbFile.DownloadDate);
      end
      else
      begin
        if PdbFile.State in [psNoSections, psReady] then
          CellText := IntToStr(PdbFile.SymCount)
        else
          CellText := '';
      end;
    end;
  end;
end;

procedure TdlgPdbManager.vstPdbDataHeaderClick(Sender: TVTHeader;
  HitInfo: TVTHeaderHitInfo);
begin
  Sort;
end;

end.
