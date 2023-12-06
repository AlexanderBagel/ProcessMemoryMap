////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uStringsViewer.pas
//  * Purpose   : Диалог для отображения списка строк в удаленном процессе
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

unit uStringsViewer;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.Menus,
  Generics.Collections, Generics.Defaults,

  VirtualTrees,
  VirtualTrees.BaseAncestorVCL,
  VirtualTrees.BaseTree,
  VirtualTrees.AncestorVCL,
  VirtualTrees.Types,

  uBaseForm,
  RawScanner.Types;

type
  TdlgStringsViewer = class(TBaseAppForm)
    lvStrings: TVirtualStringTree;
    pmCopy: TPopupMenu;
    mnuGotoAddress: TMenuItem;
    mnuSeparator1: TMenuItem;
    mnuCopyAddress: TMenuItem;
    mnuCopyFunctionName: TMenuItem;
    mnuCopyLine: TMenuItem;
    mnuSeparator2: TMenuItem;
    mnuNextMatch: TMenuItem;
    procedure FormCreate(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure FormShow(Sender: TObject);
    procedure lvStringsGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
    procedure mnuGotoAddressClick(Sender: TObject);
    procedure lvStringsDblClick(Sender: TObject);
    procedure FormKeyPress(Sender: TObject; var Key: Char);
    procedure FormDestroy(Sender: TObject);
    procedure mnuNextMatchClick(Sender: TObject);
    procedure mnuCopyAddressClick(Sender: TObject);
    procedure mnuCopyFunctionNameClick(Sender: TObject);
    procedure mnuCopyLineClick(Sender: TObject);
    procedure lvStringsHeaderClick(Sender: TVTHeader;
      HitInfo: TVTHeaderHitInfo);
  private
    SearchString: string;
    SearchPosition: Integer;
    List: TList<TInt64IntRec>;
    procedure ReloadWithStrings;
    procedure InitStrings;
    function Search(const Value: string): Boolean;
  public
    procedure ShowStrings;
  end;

var
  dlgStringsViewer: TdlgStringsViewer;

implementation

uses
  Clipbrd,
  uProcessMM,
  uSettings,
  uRegionProperties,
  RawScanner.Core,
  RawScanner.ModulesData,
  RawScanner.SymbolStorage;

const
  RootCaption = 'Process Memory Map - Strings';
  TypeString: array [Boolean] of string = ('ANSI', 'UNICODE');

{$R *.dfm}

{ TdlgStringsViewer }

procedure TdlgStringsViewer.FormClose(Sender: TObject;
  var Action: TCloseAction);
begin
  Action := caFree;
  dlgStringsViewer := nil;
end;

procedure TdlgStringsViewer.FormCreate(Sender: TObject);
begin
  lvStrings.DoubleBuffered := True;
  List := TList<TInt64IntRec>.Create;
end;

procedure TdlgStringsViewer.FormDestroy(Sender: TObject);
begin
  List.Free;
end;

procedure TdlgStringsViewer.FormKeyPress(Sender: TObject; var Key: Char);
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

procedure TdlgStringsViewer.FormShow(Sender: TObject);
begin
  if not Settings.LoadStrings then
    ReloadWithStrings;
  InitStrings;
end;

procedure TdlgStringsViewer.InitStrings;
var
  I, A, Z: Integer;
  Index: TInt64IntRec;
  HitInfo: TVTHeaderHitInfo;
begin
  Z := 0;
  List.Count := SymbolStorage.StringsCount;
  for I := 0 to RawScannerCore.Modules.Items.Count - 1 do
    for A := 0 to RawScannerCore.Modules.Items[I].Strings.Count - 1 do
    begin
      Index.Lo := A;
      Index.Hi := I;
      List[Z] := Index;
      Inc(Z);
    end;
  lvStrings.RootNodeCount := List.Count;
  lvStrings.Header.SortDirection := sdDescending;
  lvStrings.Header.SortColumn := 0;
  HitInfo.Column := 0;
  lvStringsHeaderClick(nil, HitInfo);
end;

procedure TdlgStringsViewer.lvStringsDblClick(Sender: TObject);
var
  E: TVTVirtualNodeEnumerator;
  Address: ULONG_PTR64;
  Index: TInt64IntRec;
begin
  E := lvStrings.SelectedNodes.GetEnumerator;
  if not E.MoveNext then Exit;
  Index := List.List[E.Current.Index];
  Address := RawScannerCore.Modules.Items[Index.Hi].Strings[Index.Lo].AddrVA;
  dlgRegionProps := TdlgRegionProps.Create(Application);
  dlgRegionProps.ShowPropertyAtAddr(Pointer(Address));
end;

procedure TdlgStringsViewer.lvStringsGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; TextType: TVSTTextType;
  var CellText: string);
var
  PEImage: TRawPEImage;
  Index: TInt64IntRec;
begin
  Index := List.List[Node.Index];
  PEImage := RawScannerCore.Modules.Items[Index.Hi];
  if Index.Lo >= PEImage.Strings.Count then Exit;
  case Column of
    0: CellText := '0x' + IntToHex(PEImage.Strings.List[Index.Lo].AddrVA, 1);
    1: CellText := PEImage.ImageName;
    2: CellText := TypeString[PEImage.Strings.List[Index.Lo].Unicode];
    3: CellText := PEImage.Strings.List[Index.Lo].Data;
  end;
end;

procedure TdlgStringsViewer.lvStringsHeaderClick(Sender: TVTHeader;
  HitInfo: TVTHeaderHitInfo);
begin
  SearchPosition := 0;
  if lvStrings.Header.SortColumn = HitInfo.Column then
  begin
    if lvStrings.Header.SortDirection = sdAscending then
      lvStrings.Header.SortDirection := sdDescending
    else
      lvStrings.Header.SortDirection := sdAscending;
  end
  else
  begin
    lvStrings.Header.SortDirection := sdAscending;
    lvStrings.Header.SortColumn := HitInfo.Column;
  end;

  List.Sort(TComparer<TInt64IntRec>.Construct(
    function (const A, B: TInt64IntRec): Integer
    var
      AImage, BImage: TRawPEImage;
    begin
      Result := 0;
      AImage := RawScannerCore.Modules.Items[A.Hi];
      BImage := RawScannerCore.Modules.Items[B.Hi];
      case lvStrings.Header.SortColumn of
        0:
        begin
          if AImage.Strings[A.Lo].AddrVA > BImage.Strings[B.Lo].AddrVA then
            Result := 1
          else
            if AImage.Strings[A.Lo].AddrVA = BImage.Strings[B.Lo].AddrVA then
              Result := 0
            else
              Result := -1;
        end;
        1: Result := AnsiCompareStr(AImage.ImageName, BImage.ImageName);
        2:
        begin
          if Byte(AImage.Strings[A.Lo].Unicode) > Byte(BImage.Strings[B.Lo].Unicode) then
            Result := 1
          else
            if Byte(AImage.Strings[A.Lo].Unicode) = Byte(BImage.Strings[B.Lo].Unicode) then
              Result := 0
            else
              Result := -1;
        end;
        3: Result := AnsiCompareStr(AImage.Strings[A.Lo].Data, BImage.Strings[B.Lo].Data);
      end;
      if lvStrings.Header.SortDirection = sdDescending then
        Result := -Result;
    end));
end;

procedure TdlgStringsViewer.mnuCopyAddressClick(Sender: TObject);
var
  E: TVTVirtualNodeEnumerator;
  PEImage: TRawPEImage;
  Index: TInt64IntRec;
begin
  E := lvStrings.SelectedNodes.GetEnumerator;
  if not E.MoveNext then Exit;
  Index := List.List[E.Current^.Index];
  PEImage := RawScannerCore.Modules.Items[Index.Hi];
  Clipboard.AsText := '0x' + IntToHex(PEImage.Strings.List[Index.Lo].AddrVA, 1);
end;

procedure TdlgStringsViewer.mnuCopyFunctionNameClick(Sender: TObject);
var
  E: TVTVirtualNodeEnumerator;
  PEImage: TRawPEImage;
  Index: TInt64IntRec;
begin
  E := lvStrings.SelectedNodes.GetEnumerator;
  if not E.MoveNext then Exit;
  Index := List.List[E.Current^.Index];
  PEImage := RawScannerCore.Modules.Items[Index.Hi];
  Clipboard.AsText := PEImage.Strings.List[Index.Lo].Data;
end;

procedure TdlgStringsViewer.mnuCopyLineClick(Sender: TObject);
var
  E: TVTVirtualNodeEnumerator;
  PEImage: TRawPEImage;
  Index: TInt64IntRec;
begin
  E := lvStrings.SelectedNodes.GetEnumerator;
  if not E.MoveNext then Exit;
  Index := List.List[E.Current^.Index];
  PEImage := RawScannerCore.Modules.Items[Index.Hi];
  with PEImage.Strings.List[Index.Lo] do
    Clipboard.AsText :=
      '0x' + IntToHex(AddrVA, 1) + #9 +
      PEImage.ImageName + #9 +
      TypeString[Unicode] + #9 +
      Data;
end;

procedure TdlgStringsViewer.mnuGotoAddressClick(Sender: TObject);
begin
  lvStringsDblClick(nil);
end;

procedure TdlgStringsViewer.mnuNextMatchClick(Sender: TObject);
begin
  if SearchString <> '' then
  begin
    Inc(SearchPosition);
    Search(SearchString);
  end;
end;

procedure TdlgStringsViewer.ReloadWithStrings;
begin
  Settings.LoadStrings := True;
  try
    dlgProcessMM.acRefresh.Execute;
  finally
    Settings.LoadStrings := False;
  end;
end;

function TdlgStringsViewer.Search(const Value: string): Boolean;
var
  I: Integer;
  E: TVTVirtualNodeEnumerator;
  AddrStr, TmpS: string;
  Address: Int64;
  PEImage: TRawPEImage;
  Index: TInt64IntRec;
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
    Index := List.List[I];
    PEImage := RawScannerCore.Modules.Items[Index.Hi];
    TmpS := AnsiUpperCase(PEImage.Strings.List[Index.Lo].Data);
    Result := Pos(Value, TmpS) > 0;
    if not Result then
    begin
      TmpS := IntToHex(PEImage.Strings.List[Index.Lo].AddrVA, 1);
      Result := Pos(Value, TmpS) > 0;
    end;
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
  E := lvStrings.Nodes.GetEnumerator;
  repeat
    if not E.MoveNext then Break;
  until Integer(E.Current^.Index) = SearchPosition;
  if E.Current = nil then Exit;
  lvStrings.Selected[E.Current] := True;
  lvStrings.ScrollIntoView(E.Current, True);
end;

procedure TdlgStringsViewer.ShowStrings;
begin
  Show;
end;

end.
