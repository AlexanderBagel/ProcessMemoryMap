////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uFindData.pas
//  * Purpose   : Диалог для поиска данных в памяти процесса
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.6.50
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uSearchResult;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.ComCtrls, Vcl.Menus, Generics.Collections, Generics.Defaults,

  VirtualTrees,
  VirtualTrees.BaseTree,
  VirtualTrees.Types,

  MemoryMap.Core,
  MemoryMap.RegionData,

  uBaseForm, System.Actions, Vcl.ActnList;

type
  TSearchItem = record
    AddrVA: ULONG_PTR;
    RegionFilter: TFilters;
    RegionType: TRegionType;
    Contain: TContainItemType;
    MBI: TMemoryBasicInformation;
    Details, Section, DebugHint: string;
  end;
  TSearchResultList = class(TList<TSearchItem>);

  TSearchView = class(TVirtualStringTree)
  private
    FList: TSearchResultList;
  protected
    procedure SaveToFile(const FilePath: string);
    property List: TSearchResultList read FList;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  end;

  TdlgSearchResult = class(TBaseAppForm)
    PageControl: TPageControl;
    pmViewer: TPopupMenu;
    mnuOpen: TMenuItem;
    N1: TMenuItem;
    mnuClose: TMenuItem;
    CloseAllButThis1: TMenuItem;
    ActionList1: TActionList;
    acCopyAddr: TAction;
    acClose: TAction;
    acCloseAll: TAction;
    acCloseLeft: TAction;
    acCloseRight: TAction;
    acCloseAllButThis: TAction;
    acOpen: TAction;
    mnuCopyAddress: TMenuItem;
    CloseAllButThis2: TMenuItem;
    CloseAlltotheLeft1: TMenuItem;
    CloseAlltotheRight1: TMenuItem;
    mnuCloseAll: TMenuItem;
    pmPage: TPopupMenu;
    MenuItem4: TMenuItem;
    MenuItem5: TMenuItem;
    MenuItem6: TMenuItem;
    MenuItem7: TMenuItem;
    MenuItem8: TMenuItem;
    MenuItem9: TMenuItem;
    N2: TMenuItem;
    N3: TMenuItem;
    acOpenInExplorer: TAction;
    N4: TMenuItem;
    OpenInExplorer1: TMenuItem;
    acCopyLine: TAction;
    mnuCopyLine: TMenuItem;
    StatusBar: TStatusBar;
    acSaveToFile: TAction;
    SaveToFile1: TMenuItem;
    SaveDialog: TSaveDialog;
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure FormKeyPress(Sender: TObject; var Key: Char);
    procedure acOpenUpdate(Sender: TObject);
    procedure acOpenExecute(Sender: TObject);
    procedure acCopyAddrExecute(Sender: TObject);
    procedure acCloseExecute(Sender: TObject);
    procedure acCloseAllExecute(Sender: TObject);
    procedure acCloseLeftExecute(Sender: TObject);
    procedure acCloseRightExecute(Sender: TObject);
    procedure acCloseAllButThisExecute(Sender: TObject);
    procedure acCloseAllButThisUpdate(Sender: TObject);
    procedure acCloseRightUpdate(Sender: TObject);
    procedure acCloseLeftUpdate(Sender: TObject);
    procedure acOpenInExplorerUpdate(Sender: TObject);
    procedure acOpenInExplorerExecute(Sender: TObject);
    procedure acCopyLineExecute(Sender: TObject);
    procedure acSaveToFileExecute(Sender: TObject);
    procedure PageControlChange(Sender: TObject);
  protected
    function GetSelectedIndex: Integer;
    function GetActiveView: TSearchView;
    procedure OnBeforeItemErase(Sender: TBaseVirtualTree;
      TargetCanvas: TCanvas; Node: PVirtualNode; ItemRect: TRect;
      var ItemColor: TColor; var EraseAction: TItemEraseAction);
    procedure OnDblClick(Sender: TObject);
    procedure OnGetText(Sender: TBaseVirtualTree; Node: PVirtualNode;
      Column: TColumnIndex; TextType: TVSTTextType; var CellText: string);
    procedure OnHeaderClick(Sender: TVTHeader;
      HitInfo: TVTHeaderHitInfo);
    procedure UpdateStatus;
  public
    function AddNewSearchList(const ACaption: string): TSearchView;
    procedure UpdateSearchList(AView: TSearchView; const Value: TSearchItem);
  end;

var
  dlgSearchResult: TdlgSearchResult;

implementation

uses
  Math,
  Clipbrd,
  uDisplayUtils,
  uSettings,
  uUtils,
  uRegionProperties;

const
  FilterString: array [TFilters] of string = (
    'None',
    'Image',
    'Private',
    'Shareable',
    'Mapped',
    'Heap',
    'Thread',
    'System',
    'Free'
  );

{$R *.dfm}

{ TSearchView }

constructor TSearchView.Create(AOwner: TComponent);
begin
  inherited;
  FList := TSearchResultList.Create;
end;

destructor TSearchView.Destroy;
begin
  FList.Free;
  inherited;
end;

procedure TSearchView.SaveToFile(const FilePath: string);
var
  I: TSearchItem;
  S: TStringList;
  FormatTemplate: string;
begin
  S := TStringList.Create;
  try
    if MemoryMapCore.Process64 then
      FormatTemplate := '%.16X'#9'%s'#9'%s'#9'%s'#9'%s'#9'%s'
    else
      FormatTemplate := '%.8X'#9'%s'#9'%s'#9'%s'#9'%s'#9'%s';
    for I in FList do
    begin
      S.Add(Format(FormatTemplate, [
        I.AddrVA, ExtractRegionTypeString(I.MBI), FilterString[I.RegionFilter],
        ExtractAccessString(I.MBI.Protect), I.Details + I.DebugHint, I.Section]));
    end;
    S.SaveToFile(FilePath);
  finally
    S.Free;
  end;
end;

{ TdlgSearchResult }

procedure TdlgSearchResult.acCloseAllButThisExecute(Sender: TObject);
begin
  for var I := 0 to PageControl.ActivePageIndex - 1 do
    PageControl.Pages[0].Free;
  for var I := PageControl.PageCount - 1 downto 1 do
    PageControl.Pages[I].Free;
end;

procedure TdlgSearchResult.acCloseAllButThisUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := PageControl.PageCount > 1;
end;

procedure TdlgSearchResult.acCloseAllExecute(Sender: TObject);
begin
  for var I := PageControl.PageCount - 1 downto 0 do
    PageControl.Pages[I].Free;
  Close;
end;

procedure TdlgSearchResult.acCloseExecute(Sender: TObject);
begin
  PageControl.ActivePage.Free;
  if PageControl.PageCount = 0 then
    Close;
end;

procedure TdlgSearchResult.acCloseLeftExecute(Sender: TObject);
begin
  for var I := 0 to PageControl.ActivePageIndex - 1 do
    PageControl.Pages[0].Free;
  PageControl.ActivePageIndex := 0;
end;

procedure TdlgSearchResult.acCloseLeftUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := PageControl.ActivePageIndex > 0;
end;

procedure TdlgSearchResult.acCloseRightExecute(Sender: TObject);
var
  Idx: Integer;
begin
  Idx := PageControl.ActivePageIndex;
  for var I := PageControl.PageCount - 1 downto Idx + 1 do
    PageControl.Pages[I].Free;
  PageControl.ActivePageIndex := Idx;
end;

procedure TdlgSearchResult.acCloseRightUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := PageControl.ActivePageIndex < PageControl.PageCount - 1;
end;

procedure TdlgSearchResult.acCopyAddrExecute(Sender: TObject);
var
  Idx: Integer;
begin
  Idx := GetSelectedIndex;
  if Idx < 0 then Exit;
  Clipboard.AsText := IntToHex(GetActiveView.List.List[Idx].AddrVA);
end;

procedure TdlgSearchResult.acCopyLineExecute(Sender: TObject);
var
  Idx: Integer;
begin
  Idx := GetSelectedIndex;
  if Idx < 0 then Exit;
  with GetActiveView.List.List[Idx] do
    Clipboard.AsText :=
      IntToHex(AddrVA) + #9 +
      ExtractRegionTypeString(MBI) + #9 +
      FilterString[RegionFilter] + #9 +
      ExtractAccessString(MBI.Protect) + #9 +
      Details + DebugHint + #9 + Section;
end;

procedure TdlgSearchResult.acOpenExecute(Sender: TObject);
begin
  OnDblClick(GetActiveView);
end;

procedure TdlgSearchResult.acOpenInExplorerExecute(Sender: TObject);
begin
  OpenExplorerAndSelectFile(GetActiveView.List[GetSelectedIndex].Details);
end;

procedure TdlgSearchResult.acOpenInExplorerUpdate(Sender: TObject);
var
  Idx: Integer;
  APath: string;
begin
  Idx := GetSelectedIndex;
  if Idx >= 0 then
  begin
    APath := GetActiveView.List[Idx].Details;
    TAction(Sender).Enabled := FileExists(APath);
  end
  else
    TAction(Sender).Enabled := False;
end;

procedure TdlgSearchResult.acOpenUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := GetSelectedIndex >= 0;
end;

procedure TdlgSearchResult.acSaveToFileExecute(Sender: TObject);
begin
  if SaveDialog.Execute then
    GetActiveView.SaveToFile(SaveDialog.FileName);
end;

function TdlgSearchResult.AddNewSearchList(
  const ACaption: string): TSearchView;

  procedure AddColumn(const AText: string; AWidth: Integer);
  var
    AColumn: TVirtualTreeColumn;
  begin
    AColumn := Result.Header.Columns.Add;
    AColumn.Text := AText;
    AColumn.Width := AWidth;
  end;

  function ToDpi(Value: Integer): Integer;
  begin
    Result := MulDiv(Value, FCurrentPPI, USER_DEFAULT_SCREEN_DPI);
  end;

var
  APage: TTabSheet;
  NewCaption: string;
begin
  NewCaption := ACaption;
  if Length(NewCaption) > 24  then
    NewCaption := Copy(ACaption, 1, 24) + '...';
  APage := TTabSheet.Create(PageControl);
  APage.PageControl := PageControl;
  APage.Caption := ACaption;
  APage.PopupMenu := pmViewer;
  Result := TSearchView.Create(APage);
  Result.Parent := APage;
  APage.Tag := NativeInt(Result);
  Result.Align := alClient;
  Result.EmptyListMessage := 'No data...';
  AddColumn('Address', ToDpi(110));
  AddColumn('MBI Type', ToDpi(70));
  AddColumn('Region Type', ToDpi(90));
  AddColumn('Access', ToDpi(60));
  AddColumn('Details', ToDpi(420));
  AddColumn('Section', ToDpi(70));
  Result.Header.Height := ToDpi(18);
  Result.Header.SortColumn := 0;
  Result.Header.AutoSizeIndex := 4;
  Result.Header.Options :=
    [hoAutoResize, hoColumnResize, hoDrag, hoShowSortGlyphs,
    hoVisible, hoHeaderClickAutoSort];
  Result.TreeOptions.PaintOptions := [toHideFocusRect, toShowButtons,
    toShowDropmark, toShowRoot, toShowVertGridLines, toThemeAware,
    toUseBlendedImages, toUseBlendedSelection, toUseExplorerTheme];
  Result.TreeOptions.SelectionOptions := [toFullRowSelect];
  Result.PopupMenu := pmViewer;
  Result.OnBeforeItemErase := OnBeforeItemErase;
  Result.OnDblClick := OnDblClick;
  Result.OnGetText := OnGetText;
  Result.OnHeaderClick := OnHeaderClick;
  PageControl.ActivePage := APage;
end;

procedure TdlgSearchResult.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if PageControl.PageCount = 0 then
  begin
    Action := TCloseAction.caFree;
    dlgSearchResult := nil;
  end
  else
    Action := TCloseAction.caHide;
end;

procedure TdlgSearchResult.FormKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #27 then
    Close;
end;

function TdlgSearchResult.GetActiveView: TSearchView;
begin
  Result := PageControl.ActivePage.Controls[0] as TSearchView;
end;

function TdlgSearchResult.GetSelectedIndex: Integer;
var
  E: TVTVirtualNodeEnumerator;
begin
  E := GetActiveView.SelectedNodes.GetEnumerator;
  if not E.MoveNext then Exit(-1);
  Result := E.Current^.Index;
end;

procedure TdlgSearchResult.OnBeforeItemErase(Sender: TBaseVirtualTree;
  TargetCanvas: TCanvas; Node: PVirtualNode; ItemRect: TRect;
  var ItemColor: TColor; var EraseAction: TItemEraseAction);
begin
  if not Settings.ShowColors then Exit;
  case TSearchView(Sender).List.List[Node.Index].RegionFilter of
    fiImage: ItemColor := Settings.ImageColor;
    fiPrivate: ItemColor := Settings.PrivateColor;
    fiShareable: ItemColor := Settings.SharedColor;
    fiMapped: ItemColor := Settings.MappedColor;
    fiHeap: ItemColor := Settings.HeapColor;
    fiThread: ItemColor := Settings.ThreadColor;
    fiSystem: ItemColor := Settings.SystemColor;
  else
    ItemColor := clWindow;
  end;
end;

procedure TdlgSearchResult.OnDblClick(Sender: TObject);
var
  Idx: Integer;
begin
  Idx := GetSelectedIndex;
  if Idx < 0 then Exit;
  dlgRegionProps := TdlgRegionProps.Create(Application);
  dlgRegionProps.ShowPropertyAtAddr(
    Pointer(TSearchView(Sender).List.List[Idx].AddrVA));
end;

procedure TdlgSearchResult.OnGetText(Sender: TBaseVirtualTree;
  Node: PVirtualNode; Column: TColumnIndex; TextType: TVSTTextType;
  var CellText: string);
begin
  case Column of
    0: CellText :=
      IntToHex(TSearchView(Sender).List.List[Node.Index].AddrVA,
        IfThen(MemoryMapCore.Process64, 8, 4));
    1: CellText := ExtractRegionTypeString(TSearchView(Sender).List.List[Node.Index].MBI);
    2: CellText := FilterString[TSearchView(Sender).List.List[Node.Index].RegionFilter];
    3: CellText := ExtractAccessString(TSearchView(Sender).List.List[Node.Index].MBI.Protect);
    4:
    begin
      with TSearchView(Sender).List.List[Node.Index] do
        CellText := Format('%s%s', [Details, DebugHint]);
    end;
    5: CellText := TSearchView(Sender).List.List[Node.Index].Section;
  end;
end;

procedure TdlgSearchResult.OnHeaderClick(Sender: TVTHeader;
  HitInfo: TVTHeaderHitInfo);
var
  Header: TVTHeader;
begin
  Header := TVTHeader(Sender);
  TSearchView(Header.Treeview).List.Sort(TComparer<TSearchItem>.Construct(
    function (const A, B: TSearchItem): Integer
    begin
      Result := 0;
      case Header.SortColumn of
        0:
        begin
          if A.AddrVA > B.AddrVA then
            Result := 1
          else
            if A.AddrVA = B.AddrVA then
              Result := 0
            else
              Result := -1;
        end;
        1:
        begin
          if A.MBI.State > B.MBI.State then
            Result := 1
          else
            if A.MBI.State < B.MBI.State then
              Result := -1
            else
            begin
              if A.MBI.Type_9 > B.MBI.Type_9 then
                Result := 1
              else
                if A.MBI.Type_9 < B.MBI.Type_9 then
                  Result := -1
                else
                  Result := 0;
            end;
        end;
        2:
        begin
          if A.MBI.Protect > B.MBI.Protect then
            Result := 1
          else
            if A.MBI.Protect = B.MBI.Protect then
              Result := 0
            else
              Result := -1;
        end;
        3: Result := AnsiCompareStr(A.Details, B.Details);
        4: Result := AnsiCompareStr(A.Section, B.Section);
      end;
      if Header.SortDirection = sdDescending then
        Result := -Result;
    end));
end;

procedure TdlgSearchResult.PageControlChange(Sender: TObject);
begin
  UpdateStatus;
end;

procedure TdlgSearchResult.UpdateSearchList(AView: TSearchView;
  const Value: TSearchItem);
begin
  AView.List.Add(Value);
  AView.RootNodeCount := AView.List.Count;
  AView.Header.Height := MulDiv(18, FCurrentPPI, USER_DEFAULT_SCREEN_DPI);
  UpdateStatus;
end;

procedure TdlgSearchResult.UpdateStatus;
begin
  StatusBar.Height := MulDiv(19, FCurrentPPI, USER_DEFAULT_SCREEN_DPI);
  StatusBar.Panels[0].Text := ' Found: ' + IntToStr(GetActiveView.RootNodeCount);
end;

end.
