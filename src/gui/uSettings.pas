////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uSelectProcess.pas
//  * Purpose   : Диалог настроек
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2024.
//  * Version   : 1.5.44
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uSettings;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, Vcl.ExtCtrls, System.Win.Registry, Vcl.ComCtrls,
  Vcl.Samples.Spin;

type
  TdlgSettings = class(TForm)
    Button1: TButton;
    btnOk: TButton;
    btnReset: TButton;
    ColorDialog: TColorDialog;
    tvNavigate: TTreeView;
    pcSettings: TPageControl;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    TabSheet3: TTabSheet;
    TabSheet4: TTabSheet;
    cbSearchDiff: TCheckBox;
    cbShowDetailedHeapData: TCheckBox;
    cbShowFreeRegions: TCheckBox;
    cbReconnect: TCheckBox;
    cbSuspendProcess: TCheckBox;
    cbLoadLineSymbols: TCheckBox;
    Label9: TLabel;
    cbScannerMode: TComboBox;
    cbUseFilter: TCheckBox;
    cbShowColors: TCheckBox;
    GroupBox1: TGroupBox;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    pnImage0: TPanel;
    pnImage1: TPanel;
    pnImage2: TPanel;
    pnImage3: TPanel;
    pnImage4: TPanel;
    pnImage5: TPanel;
    pnImage6: TPanel;
    pnImage7: TPanel;
    cbDemangleNames: TCheckBox;
    cbShowChildFormsOnTaskBar: TCheckBox;
    cbLoadStrings: TCheckBox;
    seStringLength: TSpinEdit;
    Label10: TLabel;
    cbShowAligns: TCheckBox;
    seSOLimit: TSpinEdit;
    Label11: TLabel;
    Label12: TLabel;
    seLineLimit: TSpinEdit;
    cbLineDirection: TComboBox;
    Label13: TLabel;
    cbCheckStackAddrPCExecutable: TCheckBox;
    cbAutoRefresh: TCheckBox;
    Label14: TLabel;
    seAutoRefreshDelay: TSpinEdit;
    procedure FormCreate(Sender: TObject);
    procedure pnImage0Click(Sender: TObject);
    procedure btnOkClick(Sender: TObject);
    procedure btnResetClick(Sender: TObject);
    procedure tvNavigateClick(Sender: TObject);
  private
    Colors: array [0..7] of TColorRef;
    procedure ShowSettings;
  end;

  TScannerMode = (smNoUpdate, smDefault, smForceUpdate);

  TSettings = class
  strict private const
    RegRootKey = 'Software\ProcessMemoryMap\';
    RegKeys: array [0..7] of string = ('ImageColor', 'ImagePartColor',
      'PrivateColor', 'SharedColor', 'MappedColor', 'HeapColor',
      'ThreadColor', 'SystemColor');
  strict private
    FAutoRefresh: Boolean;
    FAutoRefreshDelay: Integer;
    FColors: array [0..7] of TColorRef;
    FCheckStackAddrPCExecutable: Boolean;
    FSearchDifferences: Boolean;
    FShowColors: Boolean;
    FShowDetailedHeap: Boolean;
    FShowFreeRegions: Boolean;
    FSuspendProcess: Boolean;
    FReconnect: Boolean;
    FUseScannerFilter: Boolean;
    FScannerMode: TScannerMode;
    FLoadLines: Boolean;
    FDemangleNames: Boolean;
    FLineSearchLimit: Integer;
    FLineSearchDown: Boolean;
    FLoadStrings: Boolean;
    FStringMinLengh: Integer;
    FShowChildFormsOnTaskBar: Boolean;
    FShowAligns: Boolean;
    FStackOverflowLimit: Integer;
  public
    constructor Create;
    function GetColor(const Index: Integer): TColorRef;
    procedure SetColor(const Index: Integer; const Value: TColorRef);
    procedure LoadSettings;
    procedure SaveSettings;
    procedure LoadDefault;
    property AutoReconnect: Boolean read FReconnect write FReconnect;
    property AutoRefresh: Boolean read FAutoRefresh write FAutoRefresh;
    property AutoRefreshDelay: Integer read FAutoRefreshDelay write FAutoRefreshDelay;
    property ImageColor: TColorRef index 0 read GetColor write SetColor;
    property ImagePartColor: TColorRef index 1 read GetColor write SetColor;
    property PrivateColor: TColorRef index 2 read GetColor write SetColor;
    property SharedColor: TColorRef index 3 read GetColor write SetColor;
    property MappedColor: TColorRef index 4 read GetColor write SetColor;
    property HeapColor: TColorRef index 5 read GetColor write SetColor;
    property LoadLines: Boolean read FLoadLines write FLoadLines;
    property DemangleNames: Boolean read FDemangleNames write FDemangleNames;
    property ThreadColor: TColorRef index 6 read GetColor write SetColor;
    property SystemColor: TColorRef index 7 read GetColor write SetColor;
    property SearchDifferences: Boolean read FSearchDifferences write FSearchDifferences;
    property ShowColors: Boolean read FShowColors write FShowColors;
    property ShowDetailedHeap: Boolean read FShowDetailedHeap write FShowDetailedHeap;
    property ShowFreeRegions: Boolean read FShowFreeRegions write FShowFreeRegions;
    property SuspendProcess: Boolean read FSuspendProcess write FSuspendProcess;
    property UseScannerFilter: Boolean read FUseScannerFilter write FUseScannerFilter;
    property ScannerMode: TScannerMode read FScannerMode write FScannerMode;
    property LineSearchLimit: Integer read FLineSearchLimit write FLineSearchLimit;
    property LineSearchDown: Boolean read FLineSearchDown write FLineSearchDown;
    property LoadStrings: Boolean read FLoadStrings write FLoadStrings;
    property StackOverflowLimit: Integer read FStackOverflowLimit write FStackOverflowLimit;
    property StringMinLengh: Integer read FStringMinLengh write FStringMinLengh;
    property ShowChildFormsOnTaskBar: Boolean read FShowChildFormsOnTaskBar write FShowChildFormsOnTaskBar;
    property ShowAligns: Boolean read FShowAligns write FShowAligns;
    property CheckStackAddrPCExecutable: Boolean read FCheckStackAddrPCExecutable write FCheckStackAddrPCExecutable;
  end;

  function Settings: TSettings;

var
  dlgSettings: TdlgSettings;
  DebugElapsedMilliseconds, DebugInitialHeapSize: Int64;

implementation

{$R *.dfm}

var
  _Settings: TSettings;

function Settings: TSettings;
begin
  if _Settings = nil then
    _Settings := TSettings.Create;
  Result := _Settings;
end;

{ TSettings }

constructor TSettings.Create;
begin
  LoadSettings;
end;

function TSettings.GetColor(const Index: Integer): TColorRef;
begin
  Result := FColors[Index];
end;

procedure TSettings.LoadDefault;
begin
  ImageColor := RGB(210, 160, 255);
  ImagePartColor := RGB(157, 160, 255);
  PrivateColor := RGB(255, 204, 32);
  SharedColor := RGB(221, 238, 255);
  MappedColor := RGB(176, 215, 255);
  HeapColor := RGB(255, 150, 100);
  ThreadColor := RGB(255, 192, 128);
  SystemColor := RGB(180, 150, 149);
  AutoReconnect := True;
  SearchDifferences := False;
  ShowColors := True;
  ShowDetailedHeap := False;
  ShowFreeRegions := False;
  SuspendProcess := False;
  UseScannerFilter := False;
  ScannerMode := smDefault;
  LoadLines := True;
  LineSearchLimit := 42; // 3 * MaxOpcodeLen
  LineSearchDown := True;
  DemangleNames := True;
  LoadStrings := False;
  StackOverflowLimit := 15;
  StringMinLengh := 6;
  ShowChildFormsOnTaskBar := True;
  ShowAligns := True;
  CheckStackAddrPCExecutable := True;
  AutoRefresh := False;
  AutoRefreshDelay := 5000;
end;

procedure TSettings.LoadSettings;
var
  R: TRegistry;
  I: Integer;
begin
  R := TRegistry.Create;
  try
    R.RootKey := HKEY_CURRENT_USER;
    if not R.OpenKeyReadOnly(RegRootKey) then
    begin
      LoadDefault;
      Exit;
    end;
    try
      LoadDefault;
      if R.ValueExists('AutoReconnect') then
        AutoReconnect := R.ReadBool('AutoReconnect');
      if R.ValueExists('LoadLines') then
        LoadLines := R.ReadBool('LoadLines');
      if R.ValueExists('DemangleNames') then
        DemangleNames := R.ReadBool('DemangleNames');
      if R.ValueExists('LoadStrings') then
        LoadStrings := R.ReadBool('LoadStrings');
      if R.ValueExists('StringMinLengh') then
        StringMinLengh := R.ReadInteger('StringMinLengh');
      SearchDifferences := R.ReadBool('SearchDifferences');
      ShowColors := R.ReadBool('ShowColors');
      ShowDetailedHeap := R.ReadBool('ShowDetailedHeap');
      ShowFreeRegions := R.ReadBool('ShowFreeRegions');
      SuspendProcess := R.ReadBool('SuspendProcess');
      UseScannerFilter := R.ReadBool('UseScannerFilter');
      ScannerMode := TScannerMode(R.ReadInteger('ScannerMode'));
      if R.ValueExists('ShowChildFormsOnTaskBar') then
        ShowChildFormsOnTaskBar := R.ReadBool('ShowChildFormsOnTaskBar');
      if R.ValueExists('ShowAligns') then
        ShowAligns := R.ReadBool('ShowAligns');
      if R.ValueExists('StackOverflowLimit') then
        StackOverflowLimit := R.ReadInteger('StackOverflowLimit');
      if R.ValueExists('LineSearchDown') then
        LineSearchDown := R.ReadBool('LineSearchDown');
      if R.ValueExists('LineSearchLimit') then
        LineSearchLimit := R.ReadInteger('LineSearchLimit');
      for I := 0 to 7 do
        FColors[I] := R.ReadInteger(RegKeys[I]);
      if R.ValueExists('CheckStackAddrPCExecutable') then
        CheckStackAddrPCExecutable := R.ReadBool('CheckStackAddrPCExecutable');
      if R.ValueExists('AutoRefresh') then
        AutoRefresh := R.ReadBool('AutoRefresh');
      if R.ValueExists('AutoRefreshDelay') then
        AutoRefreshDelay := R.ReadInteger('AutoRefreshDelay');
    except
      LoadDefault;
    end;
  finally
    R.Free;
  end;
end;

procedure TSettings.SaveSettings;
var
  R: TRegistry;
  I: Integer;
begin
  R := TRegistry.Create;
  try
    R.RootKey := HKEY_CURRENT_USER;
    if not R.OpenKey(RegRootKey, True) then
      RaiseLastOSError;
    R.WriteBool('AutoReconnect', AutoReconnect);
    R.WriteBool('LoadLines', LoadLines);
    R.WriteBool('DemangleNames', DemangleNames);
    R.WriteBool('LoadStrings', LoadStrings);
    R.WriteInteger('StringMinLengh', StringMinLengh);
    R.WriteBool('SearchDifferences', SearchDifferences);
    R.WriteBool('ShowColors', ShowColors);
    R.WriteBool('ShowDetailedHeap', ShowDetailedHeap);
    R.WriteBool('ShowFreeRegions', ShowFreeRegions);
    R.WriteBool('SuspendProcess', SuspendProcess);
    R.WriteBool('UseScannerFilter', UseScannerFilter);
    R.WriteInteger('ScannerMode', Integer(ScannerMode));
    R.WriteBool('ShowChildFormsOnTaskBar', ShowChildFormsOnTaskBar);
    R.WriteBool('ShowAligns', ShowAligns);
    R.WriteInteger('StackOverflowLimit', StackOverflowLimit);
    R.WriteBool('LineSearchDown', LineSearchDown);
    R.WriteInteger('LineSearchLimit', LineSearchLimit);
    for I := 0 to 7 do
      R.WriteInteger(RegKeys[I], FColors[I]);
    R.WriteBool('CheckStackAddrPCExecutable', CheckStackAddrPCExecutable);
    R.WriteBool('AutoRefresh', AutoRefresh);
    R.WriteInteger('AutoRefreshDelay', AutoRefreshDelay);
  finally
    R.Free;
  end;
end;

procedure TSettings.SetColor(const Index: Integer; const Value: TColorRef);
begin
  FColors[Index] := Value;
end;

{ TdlgSettings }

procedure TdlgSettings.btnResetClick(Sender: TObject);
begin
  Settings.LoadDefault;
  ShowSettings;
end;

procedure TdlgSettings.btnOkClick(Sender: TObject);
var
  I: Integer;
begin
  Settings.AutoReconnect := cbReconnect.Checked;
  Settings.SearchDifferences := cbSearchDiff.Checked;
  Settings.ShowFreeRegions := cbShowFreeRegions.Checked;
  Settings.ShowColors := cbShowColors.Checked;
  Settings.ShowDetailedHeap := cbShowDetailedHeapData.Checked;
  Settings.SuspendProcess := cbSuspendProcess.Checked;
  Settings.UseScannerFilter := cbUseFilter.Checked;
  Settings.ScannerMode := TScannerMode(cbScannerMode.ItemIndex);
  Settings.LoadLines := cbLoadLineSymbols.Checked;
  Settings.DemangleNames := cbDemangleNames.Checked;
  Settings.StringMinLengh := seStringLength.Value;
  Settings.LoadStrings := cbLoadStrings.Checked;
  Settings.ShowChildFormsOnTaskBar := cbShowChildFormsOnTaskBar.Checked;
  Settings.ShowAligns := cbShowAligns.Checked;
  Settings.StackOverflowLimit := seSOLimit.Value;
  Settings.LineSearchLimit := seLineLimit.Value;
  Settings.LineSearchDown := cbLineDirection.ItemIndex = 0;
  for I := 0 to 7 do
    Settings.SetColor(I, Colors[I]);
  Settings.CheckStackAddrPCExecutable := cbCheckStackAddrPCExecutable.Checked;
  Settings.AutoRefresh := cbAutoRefresh.Checked;
  Settings.AutoRefreshDelay := seAutoRefreshDelay.Value;
  Settings.SaveSettings;
  ModalResult := mrOk;
end;

procedure TdlgSettings.FormCreate(Sender: TObject);
begin
  TabSheet1.TabVisible := False;
  TabSheet2.TabVisible := False;
  TabSheet3.TabVisible := False;
  TabSheet4.TabVisible := False;
  pcSettings.ActivePage := TabSheet1;
  tvNavigate.Items[0].Selected := True;
  ShowSettings;
end;

procedure TdlgSettings.pnImage0Click(Sender: TObject);
begin
  ColorDialog.Color := (Sender as TPanel).Color;
  if ColorDialog.Execute then
  begin
    Colors[(Sender as TPanel).Tag] := ColorDialog.Color;
    (Sender as TPanel).Color := ColorDialog.Color;
  end;
end;

procedure TdlgSettings.ShowSettings;
var
  I: Integer;
  P: TPanel;
begin
  cbReconnect.Checked := Settings.AutoReconnect;
  cbSearchDiff.Checked := Settings.SearchDifferences;
  cbShowFreeRegions.Checked := Settings.ShowFreeRegions;
  cbShowColors.Checked := Settings.ShowColors;
  cbShowDetailedHeapData.Checked := Settings.ShowDetailedHeap;
  cbSuspendProcess.Checked := Settings.SuspendProcess;
  cbUseFilter.Checked := Settings.UseScannerFilter;
  cbScannerMode.ItemIndex := Integer(Settings.ScannerMode);
  cbLoadLineSymbols.Checked := Settings.LoadLines;
  cbDemangleNames.Checked := Settings.DemangleNames;
  cbLoadStrings.Checked := Settings.LoadStrings;
  seStringLength.Value := Settings.StringMinLengh;
  cbShowChildFormsOnTaskBar.Checked := Settings.ShowChildFormsOnTaskBar;
  cbShowAligns.Checked := Settings.ShowAligns;
  seSOLimit.Value := Settings.StackOverflowLimit;
  seLineLimit.Value := Settings.LineSearchLimit;
  cbLineDirection.ItemIndex := Byte(not Settings.LineSearchDown);
  for I := 0 to 7 do
  begin
    Colors[I] := Settings.GetColor(I);
    P := TPanel(FindComponent('pnImage' + IntToStr(I)));
    P.Color := Colors[I];
    P.Caption := IntToHex(Colors[I], 8);
  end;
  cbCheckStackAddrPCExecutable.Checked := Settings.CheckStackAddrPCExecutable;
  cbAutoRefresh.Checked := Settings.AutoRefresh;
  seAutoRefreshDelay.Value := Settings.AutoRefreshDelay;
end;

procedure TdlgSettings.tvNavigateClick(Sender: TObject);
begin
  if tvNavigate.Selected <> nil then
  begin
    case tvNavigate.Selected.Index of
      0: pcSettings.ActivePage := TabSheet1;
      1: pcSettings.ActivePage := TabSheet2;
      2: pcSettings.ActivePage := TabSheet3;
      3: pcSettings.ActivePage := TabSheet4;
    end;
  end;
end;

initialization

finalization

  _Settings.Free;

end.
