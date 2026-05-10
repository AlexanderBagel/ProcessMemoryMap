////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uSettings.Form.pas
//  * Purpose   : Диалог настроек
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.6.47
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uSettings.Form;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.ComCtrls, Vcl.Samples.Spin;

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
    Label15: TLabel;
    seSearchLimit: TSpinEdit;
    procedure FormCreate(Sender: TObject);
    procedure pnImage0Click(Sender: TObject);
    procedure btnOkClick(Sender: TObject);
    procedure btnResetClick(Sender: TObject);
    procedure tvNavigateClick(Sender: TObject);
  private
    Colors: array [0..7] of TColorRef;
    procedure ShowSettings;
  end;

var
  dlgSettings: TdlgSettings;

implementation

uses
  uSettings;

{$R *.dfm}

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
  Settings.SearchLimit := seSearchLimit.Value;
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
  seSearchLimit.Value := Settings.SearchLimit;
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

end.
