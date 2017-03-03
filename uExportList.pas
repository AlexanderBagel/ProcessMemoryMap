////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uExportList.pas
//  * Purpose   : Диалог для отображения списка экспорта функций
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2017.
//  * Version   : 1.0.1
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uExportList;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.ComCtrls, Vcl.StdCtrls, Vcl.ExtCtrls, VirtualTrees,
  Generics.Collections, Generics.Defaults, Vcl.Clipbrd, Vcl.Menus,

  MemoryMap.Core,
  MemoryMap.Symbols,
  MemoryMap.Utils,
  MemoryMap.DebugMapData;

type
  TExportData = record
    dwAddress: NativeUInt;
    AType,
    Address,
    Module,
    FunctionName,
    SearchFunctionName: string;
  end;

  TdlgExportList = class(TForm)
    lvExports: TVirtualStringTree;
    pmCopy: TPopupMenu;
    mnuCopyAddress: TMenuItem;
    mnuCopyFunctionName: TMenuItem;
    mnuCopyLine: TMenuItem;
    mnuGotoAddress: TMenuItem;
    mnuSeparator1: TMenuItem;
    mnuSeparator2: TMenuItem;
    mnuNextMatch: TMenuItem;
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
  private
    SearchString: string;
    SearchPosition: Integer;
    List: TList<TExportData>;
    function Search(const Value: string): Boolean;
  public
    procedure ShowExport;
  end;

var
  dlgExportList: TdlgExportList;

implementation

uses
  uUtils,
  uProgress,
  uSettings,
  uRegionProperties;

const
  RootCaption = 'Process Memory Map - Exports';

{$R *.dfm}

procedure TdlgExportList.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  Action := caFree;
  dlgExportList := nil;
end;

procedure TdlgExportList.FormCreate(Sender: TObject);
begin
  List := TList<TExportData>.Create;
end;

procedure TdlgExportList.FormDestroy(Sender: TObject);
begin
  List.Free;
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
var
  I, A: Integer;
  S: TStringList;
  Symbols: TSymbols;
  Process: THandle;
  Module: TModule;
  ExportData: TExportData;
  HitInfo: TVTHeaderHitInfo;
  ProcessLock: TProcessLockHandleList;
begin
  ProcessLock := nil;
  dlgProgress := TdlgProgress.Create(nil);
  try
    dlgProgress.Show;
    S := TStringList.Create;
    try
      Process := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
        False, MemoryMapCore.PID);
      if Process = 0 then
        RaiseLastOSError;
      try
        if Settings.SuspendProcess then
          ProcessLock := SuspendProcess(MemoryMapCore.PID);
        try
          Symbols := TSymbols.Create(Process);
          try
            dlgProgress.ProgressBar.Max := MemoryMapCore.Modules.Count;
            for I := 0 to MemoryMapCore.Modules.Count - 1 do
            begin
              S.Clear;
              Module := MemoryMapCore.Modules[I];
              dlgProgress.lblProgress.Caption := Module.Path;
              dlgProgress.ProgressBar.Position := I;
              Application.ProcessMessages;
              ExportData.Module := ExtractFileName(Module.Path);
              ExportData.AType := 'DEBUG';
              MemoryMapCore.DebugMapData.GetExportFuncList(ExportData.Module, S);
              for A := 0 to S.Count - 1 do
              begin
                ExportData.dwAddress := NativeUInt(S.Objects[A]);
                ExportData.Address := UInt64ToStr(ExportData.dwAddress);
                ExportData.FunctionName := S[A];
                ExportData.SearchFunctionName := AnsiUpperCase(S[A]);
                List.Add(ExportData);
              end;
              S.Clear;
              ExportData.AType := 'EXPORT';
              Symbols.GetExportFuncList(Module.Path, Module.BaseAddr, S);
              for A := 0 to S.Count - 1 do
              begin
                ExportData.dwAddress := NativeUInt(S.Objects[A]);
                ExportData.Address := UInt64ToStr(ExportData.dwAddress);
                ExportData.FunctionName := S[A];
                ExportData.SearchFunctionName := AnsiUpperCase(S[A]);
                List.Add(ExportData);
              end;
            end;
            lvExports.RootNodeCount := dlgExportList.List.Count;
            lvExports.Header.SortDirection := sdAscending;
            lvExports.Header.SortColumn := 0;
            HitInfo.Column := 2;
            lvExportsHeaderClick(nil, HitInfo);
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

procedure TdlgExportList.lvExportsDblClick(Sender: TObject);
var
  E: TVTVirtualNodeEnumerator;
  Address: Int64;
begin
  E := lvExports.SelectedNodes.GetEnumerator;
  if not E.MoveNext then Exit;
  TryStrToInt64('$' + List[E.Current^.Index].Address, Address);
  dlgRegionProps := TdlgRegionProps.Create(Application);
  dlgRegionProps.ShowPropertyAtAddr(Pointer(Address), True);
end;

procedure TdlgExportList.lvExportsGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; TextType: TVSTTextType;
  var CellText: string);
begin
  case Column of
    0: CellText := List[Node.Index].AType;
    1: CellText := List[Node.Index].Address;
    2: CellText := List[Node.Index].Module;
    3: CellText := List[Node.Index].FunctionName;
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
        0:
        begin
          if A.dwAddress > B.dwAddress then
            Result := 1
          else
            if A.dwAddress = B.dwAddress then
              Result := 0
            else
              Result := -1;
        end;
        1: Result := AnsiCompareStr(A.Module, B.Module);
        2: Result := AnsiCompareStr(A.FunctionName, B.FunctionName);
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

end.

