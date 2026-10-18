////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : uExportList.pas
//  * Purpose   : Dialog box for displaying the list of export functions
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

unit uExportList;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.ComCtrls, Vcl.StdCtrls, Vcl.ExtCtrls,
  Generics.Collections, Generics.Defaults, Vcl.Clipbrd, Vcl.Menus,

  VirtualTrees,
  VirtualTrees.BaseAncestorVCL,
  VirtualTrees.BaseTree,
  VirtualTrees.AncestorVCL,
  VirtualTrees.Types,

  MemoryMap.Core,
  MemoryMap.Symbols,
  MemoryMap.Utils,
  MemoryMap.DebugMapData,

  RawScanner.Image.Pe,
  RawScanner.CoffDwarf,
  RawScanner.Pdb,
  RawScanner.Utils,

  uBaseForm,
  uSettings;

type
  TExportData = record
    dwAddress: NativeUInt;
    Status: TExportStatus;
    AType,
    Address,
    Module,
    FunctionName,
    SearchFunctionName: string;
  end;

  TdlgExportList = class(TBaseAppForm)
    lvExports: TVirtualStringTree;
    pmCopy: TPopupMenu;
    mnuCopyAddress: TMenuItem;
    mnuCopyFunctionName: TMenuItem;
    mnuCopyLine: TMenuItem;
    mnuGotoAddress: TMenuItem;
    mnuSeparator1: TMenuItem;
    mnuSeparator2: TMenuItem;
    mnuNextMatch: TMenuItem;
    N1: TMenuItem;
    Filter1: TMenuItem;
    mnuShowEXPORT: TMenuItem;
    mnuShowFORWARDED: TMenuItem;
    mnuShowREBASED: TMenuItem;
    mnuShowDATA: TMenuItem;
    mnuShowINVALID: TMenuItem;
    mnuShowDEBUGMAPFUNC: TMenuItem;
    mnuShowDEBUGMAPDATA: TMenuItem;
    mnuShowCOFFFUNC: TMenuItem;
    mnuShowCOFFDATA: TMenuItem;
    mnuShowDWARFFUNC: TMenuItem;
    mnuShowDWARFDATA: TMenuItem;
    mnuOpenInExplorer: TMenuItem;
    mnuShowPdbFunc: TMenuItem;
    mnuShowPdbData: TMenuItem;
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure lvExportsGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
    procedure lvExportsHeaderClick(Sender: TVTHeader;
      HitInfo: TVTHeaderHitInfo);
    procedure mnuCopyAddressClick(Sender: TObject);
    procedure mnuCopyFunctionNameClick(Sender: TObject);
    procedure mnuCopyLineClick(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure FormKeyPress(Sender: TObject; var Key: Char);
    procedure FormDestroy(Sender: TObject);
    procedure lvExportsDblClick(Sender: TObject);
    procedure mnuGotoAddressClick(Sender: TObject);
    procedure mnuNextMatchClick(Sender: TObject);
    procedure lvExportsBeforeItemErase(Sender: TBaseVirtualTree;
      TargetCanvas: TCanvas; Node: PVirtualNode; ItemRect: TRect;
      var ItemColor: TColor; var EraseAction: TItemEraseAction);
    procedure mnuOpenInExplorerClick(Sender: TObject);
    procedure pmCopyPopup(Sender: TObject);
    procedure mnuShowDWARFDATAClick(Sender: TObject);
    procedure FormAfterMonitorDpiChanged(Sender: TObject; OldDPI,
      NewDPI: Integer);
  private
    SearchString: string;
    SearchPosition: Integer;
    NoFilterdList, List: TList<TExportData>;
    function Search(const Value: string): Boolean;
    procedure ShowList;
  public
    procedure ShowExport;
  end;

var
  dlgExportList: TdlgExportList;

implementation

uses
  uUtils,
  uProgress,
  uRegionProperties,
  RawScanner.Core,
  RawScanner.SymbolStorage;

const
  RootCaption = 'Process Memory Map - Exports';

{$R *.dfm}

procedure TdlgExportList.FormAfterMonitorDpiChanged(Sender: TObject; OldDPI,
  NewDPI: Integer);
begin
  FixVirtualStringTreeDpiBug(lvExports);
end;

procedure TdlgExportList.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  Action := caFree;
  dlgExportList := nil;
end;

procedure TdlgExportList.FormCreate(Sender: TObject);
begin
  List := TList<TExportData>.Create;
  NoFilterdList := TList<TExportData>.Create;
  lvExports.DoubleBuffered := True;
end;

procedure TdlgExportList.FormDestroy(Sender: TObject);
begin
  List.Free;
  NoFilterdList.Free;
end;

procedure TdlgExportList.FormKeyPress(Sender: TObject; var Key: Char);
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
    if SearchString = '' then
    begin
      Close;
      Exit;
    end;
    SearchString := '';
    Caption := RootCaption;
    SearchPosition := 0;
    Exit;
  end;
  if Key <= #32 then Exit;
  TmpString := SearchString + AnsiUpperCase(Key);
  if Search(TmpString) then
    SearchString := TmpString;
end;

procedure TdlgExportList.FormShow(Sender: TObject);
const
  SymbolExportType: array [TExportStatus] of string =
    ('EXPORT', 'FORWARDED', 'REBASED', 'DATA', 'INVALID',
     'DEBUG_MAP FUNC', 'DEBUG_MAP DATA', 'COFF FUNC', 'COFF DATA',
     'DWARF FUNC', 'DWARF DATA', 'PDB FUNC', 'PDB DATA');
var
  I, A: Integer;
  S: TStringList;
  Symbols: TSymbols;
  Process: THandle;
  Module: TModule;
  ExportData: TExportData;
  ProcessLock: TProcessLockHandleList;
  Image: TRawPEImage;
  Pdb: TPdb;

  function CheckRebased(AddrVA: NativeUInt): TExportStatus;
  var
    Index: Integer;
    ASymbol: TSymbolData;
    SymbolModule: TRawPEImage;
    ExportChunk: TExportChunk;
  begin
    if SymbolStorage.GetDataAtAddr(AddrVA, ASymbol) and
      (ASymbol.DataType in [sdtExport, sdtEntryPoint, sdtPluginDescriptor, sdtInstance]) then
    begin

      // an export with RVA set to zero will point to a module instance
      // [ru] экспорт с убитым RVA выставленым в ноль будет указывать на инстанс модуля

      if ASymbol.DataType = sdtInstance then
      begin
        Result := esInvalid;
        Exit;
      end;
      if ASymbol.DataType = sdtPluginDescriptor then
      begin
        if ASymbol.Plugin.IsFunction then
          Result := esNormal
        else
          Result := esNoExecutable;
        Exit;
      end;
      SymbolModule := RawScannerCore.Modules.Items[ASymbol.Binary.ModuleIndex];
      ExportChunk := SymbolModule.ExportList.List[ASymbol.Binary.ListIndex];
      if ExportChunk.Executable then
        Result := esNormal
      else
        if ExportChunk.ForvardedTo <> '' then
          Result := esForvarded
        else
          Result := esNoExecutable;
      Exit;
    end;

    Index := RawScannerCore.Modules.GetModule(AddrVA, True);
    if Index < 0 then
      Result := esRebased
    else
    begin
      if AnsiSameText(Module.Path, RawScannerCore.Modules.Items[Index].ImagePath) then
        Result := esForvarded
      else
        Result := esRebased;
    end;

  end;

begin
  ProcessLock := nil;
  dlgProgress := TdlgProgress.Create(nil);
  try
    dlgProgress.Show;
    S := TStringList.Create;
    try
      Process := OpenProcessWithReconnect;
      try
        if Settings.SuspendProcess then
          ProcessLock := SuspendProcess(MemoryMapCore.PID);
        try
          Symbols := TSymbols.Create(Process);
          try
            dlgProgress.ProgressBar.Max := MemoryMapCore.Modules.Count;
            for I := 0 to MemoryMapCore.Modules.Count - 1 do
            begin
              Module := MemoryMapCore.Modules[I];
              dlgProgress.UpdateCaption(Module.Path, I);
              ExportData.Module := ExtractFileName(Module.Path);

              // extracting information from COFF
              // [ru] вывод информации из COFF

              S.Clear;
              RawScannerCore.Modules.GetCoffData(Module.Path, S, True);
              for A := 0 to S.Count - 1 do
              begin
                ExportData.dwAddress := NativeUInt(S.Objects[A]);
                ExportData.Address := UInt64ToStr(ExportData.dwAddress);
                ExportData.Status := esCoff;
                ExportData.AType := SymbolExportType[ExportData.Status];
                ExportData.FunctionName := S[A];
                ExportData.SearchFunctionName := AnsiUpperCase(S[A]);
                NoFilterdList.Add(ExportData);
              end;

              S.Clear;
              RawScannerCore.Modules.GetCoffData(Module.Path, S, False);
              for A := 0 to S.Count - 1 do
              begin
                ExportData.dwAddress := NativeUInt(S.Objects[A]);
                ExportData.Address := UInt64ToStr(ExportData.dwAddress);
                ExportData.Status := esCoffData;
                ExportData.AType := SymbolExportType[ExportData.Status];
                ExportData.FunctionName := S[A];
                ExportData.SearchFunctionName := AnsiUpperCase(S[A]);
                NoFilterdList.Add(ExportData);
              end;

              // extracting information from DWARF
              // [ru] вывод информации из DWARF

              S.Clear;
              RawScannerCore.Modules.GetDwarfData(Module.Path, S, True);
              for A := 0 to S.Count - 1 do
              begin
                ExportData.dwAddress := NativeUInt(S.Objects[A]);
                ExportData.Address := UInt64ToStr(ExportData.dwAddress);
                ExportData.Status := esDwarf;
                ExportData.AType := SymbolExportType[ExportData.Status];
                ExportData.FunctionName := S[A];
                ExportData.SearchFunctionName := AnsiUpperCase(S[A]);
                NoFilterdList.Add(ExportData);
              end;

              S.Clear;
              RawScannerCore.Modules.GetDwarfData(Module.Path, S, False);
              for A := 0 to S.Count - 1 do
              begin
                ExportData.dwAddress := NativeUInt(S.Objects[A]);
                ExportData.Address := UInt64ToStr(ExportData.dwAddress);
                ExportData.Status := esDwarfData;
                ExportData.AType := SymbolExportType[ExportData.Status];
                ExportData.FunctionName := S[A];
                ExportData.SearchFunctionName := AnsiUpperCase(S[A]);
                NoFilterdList.Add(ExportData);
              end;

              // extracting information from a debug MAP file
              // [ru] вывод информации из отладочного MAP файла

              S.Clear;
              MemoryMapCore.DebugMapData.GetExportFuncList(ExportData.Module, S, True);
              for A := 0 to S.Count - 1 do
              begin
                ExportData.dwAddress := NativeUInt(S.Objects[A]);
                ExportData.Address := UInt64ToStr(ExportData.dwAddress);
                ExportData.Status := esDebug;
                ExportData.AType := SymbolExportType[ExportData.Status];
                ExportData.FunctionName := S[A];
                ExportData.SearchFunctionName := AnsiUpperCase(S[A]);
                NoFilterdList.Add(ExportData);
              end;

              S.Clear;
              MemoryMapCore.DebugMapData.GetExportFuncList(ExportData.Module, S, False);
              for A := 0 to S.Count - 1 do
              begin
                ExportData.dwAddress := NativeUInt(S.Objects[A]);
                ExportData.Address := UInt64ToStr(ExportData.dwAddress);
                ExportData.Status := esDebugData;
                ExportData.AType := SymbolExportType[ExportData.Status];
                ExportData.FunctionName := S[A];
                ExportData.SearchFunctionName := AnsiUpperCase(S[A]);
                NoFilterdList.Add(ExportData);
              end;

              // extracting exported functions using symbols
              // [ru] вывод экспортируемых функций через символы

              S.Clear;
              Symbols.GetExportFuncList(Module.Path, Module.BaseAddr, S);
              for A := 0 to S.Count - 1 do
              begin
                ExportData.dwAddress := NativeUInt(S.Objects[A]);
                ExportData.Address := UInt64ToStr(ExportData.dwAddress);
                ExportData.Status := CheckRebased(ExportData.dwAddress);
                ExportData.AType := SymbolExportType[ExportData.Status];
                ExportData.FunctionName := S[A];
                ExportData.SearchFunctionName := AnsiUpperCase(ExportData.FunctionName);
                NoFilterdList.Add(ExportData);
              end;

              // extracting information from PDB storage
              // [ru] вывод информации из хранилища PDB симолов

              if not Module.LoadAsImage then Continue;
              S.Clear;
              A := RawScannerCore.Modules.GetModule(Module.BaseAddr);
              if A < 0 then Continue;              
              Image := RawScannerCore.Modules.Items[A];
              if not (ditPdb in Image.DebugData) then Continue;
              with Image.CodeViewInfo do
                Pdb := RawScannerCore.PdbStorage.QueryPDB(UincalId, Age, PdbFileName);
              if Pdb.State = psReady then
              begin
                for A := 0 to Pdb.Count - 1 do
                begin
                  ExportData.dwAddress := Image.RvaToVa(Pdb[A].Rva);
                  ExportData.Address := UInt64ToStr(ExportData.dwAddress);
                  case Pdb[A].SymbolType of
                    pstData: ExportData.Status := esPdbData;
                    pstFunc: ExportData.Status := esPdb;
                  else
                    // ICF-folded stub (e.g. mov ecx,7Fh / jmp RtlSetLastWin32Error):
                    // many unrelated names share this RVA, skipped
                    Continue;
                  end;
                  ExportData.AType := SymbolExportType[ExportData.Status];
                  ExportData.FunctionName := Pdb[A].Name;
                  ExportData.SearchFunctionName := AnsiUpperCase(ExportData.FunctionName);
                  NoFilterdList.Add(ExportData);
                end;
              end;
            end;

            ShowList;

          finally
            Symbols.Free;
          end;
        finally
          if Settings.SuspendProcess then
            ResumeProcess(ProcessLock);
        end;
      finally
        CloseHandle(Process);
      end;
    finally
      S.Free;
    end;
  finally
    dlgProgress.Release;
  end;
end;

procedure TdlgExportList.lvExportsBeforeItemErase(Sender: TBaseVirtualTree;
  TargetCanvas: TCanvas; Node: PVirtualNode; ItemRect: TRect;
  var ItemColor: TColor; var EraseAction: TItemEraseAction);
begin
  case List[Node.Index].Status of
    esForvarded: ItemColor := $A3F4FE;
    esRebased: ItemColor := $D2BDF3;
    esNoExecutable, esCoffData, esDebugData: ItemColor := $E4C4CF;
    esInvalid: ItemColor := $B092EC;
    esDebug, esCoff: ItemColor := $CCEDDF;
    esDwarf: ItemColor := $A1D0A3;
    esDwarfData: ItemColor := $F0DFE5;
    esPdb: ItemColor := $F5D6A3;
    esPdbData: ItemColor := $FCEFD4;
  else
    ItemColor := clWhite;
  end;
end;

procedure TdlgExportList.lvExportsDblClick(Sender: TObject);
var
  E: TVTVirtualNodeEnumerator;
  Address: Int64;
begin
  E := lvExports.SelectedNodes.GetEnumerator;
  if not E.MoveNext then Exit;
  TryStrToInt64('$' + List[E.Current^.Index].Address, Address);
  dlgRegionProps := TdlgRegionProps.Create(Application);
  dlgRegionProps.ShowPropertyAtAddr(Pointer(Address));
end;

procedure TdlgExportList.lvExportsGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; TextType: TVSTTextType;
  var CellText: string);
begin
  case Column of
    0: CellText := List[Node.Index].AType;
    1: CellText := List[Node.Index].Address;
    2: CellText := List[Node.Index].Module;
    3:
    begin
      case List[Node.Index].Status of
        esPdb, esPdbData:
          CellText := UnDecorateSymbolName2(List[Node.Index].FunctionName);
      else
        CellText := List[Node.Index].FunctionName;
      end;
    end;
  end;
end;

procedure TdlgExportList.lvExportsHeaderClick(Sender: TVTHeader;
  HitInfo: TVTHeaderHitInfo);
begin
  SearchPosition := 0;
  if lvExports.Header.SortColumn = HitInfo.Column then
  begin
    if lvExports.Header.SortDirection = sdAscending then
      lvExports.Header.SortDirection := sdDescending
    else
      lvExports.Header.SortDirection := sdAscending;
  end
  else
  begin
    lvExports.Header.SortDirection := sdAscending;
    lvExports.Header.SortColumn := HitInfo.Column;
  end;

  List.Sort(TComparer<TExportData>.Construct(
    function (const A, B: TExportData): Integer
    begin
      Result := 0;
      case lvExports.Header.SortColumn of
        0: Result := AnsiCompareStr(A.AType, B.AType);
        1:
        begin
          if A.dwAddress > B.dwAddress then
            Result := 1
          else
            if A.dwAddress = B.dwAddress then
              Result := 0
            else
              Result := -1;
        end;
        2: Result := AnsiCompareStr(A.Module, B.Module);
        3: Result := AnsiCompareStr(A.FunctionName, B.FunctionName);
      end;
      if lvExports.Header.SortDirection = sdDescending then
        Result := -Result;
    end));
end;

procedure TdlgExportList.mnuCopyAddressClick(Sender: TObject);
var
  E: TVTVirtualNodeEnumerator;
begin
  E := lvExports.SelectedNodes.GetEnumerator;
  if not E.MoveNext then Exit;
  Clipboard.AsText := List[E.Current^.Index].Address;
end;

procedure TdlgExportList.mnuCopyFunctionNameClick(Sender: TObject);
var
  E: TVTVirtualNodeEnumerator;
begin
  E := lvExports.SelectedNodes.GetEnumerator;
  if not E.MoveNext then Exit;
  Clipboard.AsText := List[E.Current^.Index].FunctionName;
end;

procedure TdlgExportList.mnuCopyLineClick(Sender: TObject);
var
  E: TVTVirtualNodeEnumerator;
begin
  E := lvExports.SelectedNodes.GetEnumerator;
  if not E.MoveNext then Exit;
  Clipboard.AsText :=
    List[E.Current^.Index].Address + #9 +
    List[E.Current^.Index].Module + #9 +
    List[E.Current^.Index].FunctionName;
end;

procedure TdlgExportList.mnuGotoAddressClick(Sender: TObject);
begin
  lvExportsDblClick(nil);
end;

procedure TdlgExportList.mnuNextMatchClick(Sender: TObject);
begin
  if SearchString <> '' then
  begin
    Inc(SearchPosition);
    Search(SearchString);
  end;
end;

procedure TdlgExportList.mnuOpenInExplorerClick(Sender: TObject);
var
  E: TVTVirtualNodeEnumerator;
  Index: Integer;
begin
  E := lvExports.SelectedNodes.GetEnumerator;
  if not E.MoveNext then Exit;
  Index := RawScannerCore.Modules.GetModule(List[E.Current^.Index].dwAddress, True);
  OpenExplorerAndSelectFile(RawScannerCore.Modules.Items[Index].ImagePath);
end;

procedure TdlgExportList.mnuShowDWARFDATAClick(Sender: TObject);
begin
  if TMenuItem(Sender).Checked then
    Settings.ExportsShowFilter := Settings.ExportsShowFilter + [TExportStatus(TMenuItem(Sender).Tag)]
  else
    Settings.ExportsShowFilter := Settings.ExportsShowFilter - [TExportStatus(TMenuItem(Sender).Tag)];
  ShowList;
end;

procedure TdlgExportList.pmCopyPopup(Sender: TObject);

  procedure CheckMenuItem(AItem: TExportStatus; AChecked: Boolean);
  begin
    case AItem of
      esNormal: mnuShowEXPORT.Checked := AChecked;
      esForvarded: mnuShowFORWARDED.Checked := AChecked;
      esRebased: mnuShowREBASED.Checked := AChecked;
      esNoExecutable: mnuShowDATA.Checked := AChecked;
      esInvalid: mnuShowINVALID.Checked := AChecked;
      esDebug: mnuShowDEBUGMAPFUNC.Checked := AChecked;
      esDebugData: mnuShowDEBUGMAPDATA.Checked := AChecked;
      esCoff: mnuShowCOFFFUNC.Checked := AChecked;
      esCoffData: mnuShowCOFFDATA.Checked := AChecked;
      esDwarf: mnuShowDWARFFUNC.Checked := AChecked;
      esDwarfData: mnuShowDWARFDATA.Checked := AChecked;
      esPdb: mnuShowPdbFunc.Checked := AChecked;
      esPdbData: mnuShowPdbData.Checked := AChecked;
    end;
  end;

var
  E: TVTVirtualNodeEnumerator;
  Index: TExportStatus;
begin
  for Index := Low(TExportStatus) to High(TExportStatus) do
    CheckMenuItem(Index, Index in Settings.ExportsShowFilter);
  mnuOpenInExplorer.Enabled := False;
  E := lvExports.SelectedNodes.GetEnumerator;
  if not E.MoveNext then Exit;
  mnuOpenInExplorer.Enabled := List[E.Current^.Index].Status <> esRebased;
end;

function TdlgExportList.Search(const Value: string): Boolean;
var
  I: Integer;
  E: TVTVirtualNodeEnumerator;
  AddrStr: string;
  Address: Int64;
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
  for I := SearchPosition to List.Count - 1 do
  begin
    Result := Pos(Value, List[I].SearchFunctionName) > 0;
    if not Result then
      Result := Pos(AddrStr, List[I].Address) > 0;
    if Result then
    begin
      SearchPosition := I;
      Caption := RootCaption + ' [' + Value + ']';
      Result := True;
      Break;
    end;
  end;
  if not Result then
  begin
    if SearchPosition > 0 then
    begin
      SearchPosition := 0;
      Result := Search(Value);
    end;
    Exit;
  end;
  E := lvExports.Nodes.GetEnumerator;
  repeat
    if not E.MoveNext then Break;
  until Integer(E.Current^.Index) = SearchPosition;
  if E.Current = nil then Exit;  
  lvExports.Selected[E.Current] := True;
  lvExports.ScrollIntoView(E.Current, True);
end;

procedure TdlgExportList.ShowExport;
begin
  Show;
end;

procedure TdlgExportList.ShowList;
var
  HitInfo: TVTHeaderHitInfo;
  ExportData: TExportData;
begin
  List.Clear;
  for ExportData in NoFilterdList do
    if ExportData.Status in Settings.ExportsShowFilter then
      List.Add(ExportData);
  lvExports.RootNodeCount := List.Count;
  lvExports.Header.SortDirection := sdAscending;
  lvExports.Header.SortColumn := 0;
  HitInfo.Column := 1;
  lvExportsHeaderClick(nil, HitInfo);
end;

end.

