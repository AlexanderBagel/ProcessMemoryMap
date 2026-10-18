////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : uSettings.Form.pas
//  * Purpose   : Settings dialog
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

unit uSettings.Form;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.ComCtrls, Vcl.Samples.Spin, Vcl.Mask,

  RawScanner.Pdb;

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
    cbShowAligns: TCheckBox;
    seSOLimit: TSpinEdit;
    Label11: TLabel;
    lblSearchDistance: TLabel;
    seLineLimit: TSpinEdit;
    cbLineDirection: TComboBox;
    lblSearchDirection: TLabel;
    cbCheckStackAddrPCExecutable: TCheckBox;
    cbAutoRefresh: TCheckBox;
    Label14: TLabel;
    seAutoRefreshDelay: TSpinEdit;
    Label15: TLabel;
    seSearchLimit: TSpinEdit;
    memSymSrv: TMemo;
    Label16: TLabel;
    cbUsePDBSymbols: TCheckBox;
    cbDownloadSym: TCheckBox;
    TabSheet5: TTabSheet;
    cbCheckUpdates: TCheckBox;
    cbProxy: TComboBox;
    edProxyAddr: TLabeledEdit;
    edProxyPort: TLabeledEdit;
    lblProxyAuth: TLabel;
    cbProxyAuth: TComboBox;
    edProxyUser: TLabeledEdit;
    edProxyPassword: TLabeledEdit;
    btnTestProxy: TButton;
    seStringLength: TSpinEdit;
    Label10: TLabel;
    cbLoadStrings: TCheckBox;
    procedure FormCreate(Sender: TObject);
    procedure pnImage0Click(Sender: TObject);
    procedure btnOkClick(Sender: TObject);
    procedure btnResetClick(Sender: TObject);
    procedure tvNavigateClick(Sender: TObject);
    procedure cbUsePDBSymbolsClick(Sender: TObject);
    procedure btnTestProxyClick(Sender: TObject);
  private
    Colors: array [0..7] of TColorRef;
    function GetProxy: TProxySettings;
    procedure ShowSettings;
    procedure UpdateGUI;
  end;

var
  dlgSettings: TdlgSettings;

implementation

uses
  uSettings,
  uUtils;

{$R *.dfm}

{ TdlgSettings }

procedure TdlgSettings.btnResetClick(Sender: TObject);
begin
  Settings.LoadDefault;
  ShowSettings;
end;

procedure TdlgSettings.btnTestProxyClick(Sender: TObject);
var
  Info: TReseaseInfo;
begin
  if GetLatestRelease(GetProxy, Info) then
    Application.MessageBox(PChar('Connection successful. Latest version: ' + Info.Version),
      PChar(Application.Title), MB_ICONINFORMATION)
  else
    Application.MessageBox(PChar('Connection failed.' + sLineBreak +
      sLineBreak +
      'Unable to connect to the proxy server. Please check the server address, ' +
      'port, and authentication settings.' + sLineBreak +
      sLineBreak +
      Info.ErrorData), PChar(Application.Title), MB_ICONINFORMATION);
end;

procedure TdlgSettings.cbUsePDBSymbolsClick(Sender: TObject);
begin
  UpdateGUI;
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
  Settings.UsePDB := cbUsePDBSymbols.Checked;
  Settings.DownloadPDB := cbDownloadSym.Checked;
  Settings.SymSrv := Trim(memSymSrv.Text);
  Settings.CheckUpdates := cbCheckUpdates.Checked;
  Settings.Proxy := GetProxy;
  Settings.SaveSettings;
  ModalResult := mrOk;
end;

procedure TdlgSettings.FormCreate(Sender: TObject);
begin
  TabSheet1.TabVisible := False;
  TabSheet2.TabVisible := False;
  TabSheet3.TabVisible := False;
  TabSheet4.TabVisible := False;
  TabSheet5.TabVisible := False;
  pcSettings.ActivePage := TabSheet1;
  tvNavigate.Items[0].Selected := True;
  ShowSettings;
end;

function TdlgSettings.GetProxy: TProxySettings;
begin
  Result := Default(TProxySettings);
  case cbProxy.ItemIndex of
    0: ;
    1: Result.Kind := pkDefault;
    2:
    begin
      Result.Host := edProxyAddr.Text;
      TryStrToInt(edProxyPort.Text, Result.Port);
      if cbProxyAuth.ItemIndex > 0 then
      begin
        Result.Kind := pkUserSettingsWithAuthority;
        case cbProxyAuth.ItemIndex of
          1: Result.AuthKind := pakAuto;
          2: Result.AuthKind := pakBasic;
          3: Result.AuthKind := pakNegotiate;
          4: Result.AuthKind := pakNTLM;
        end;
        Result.Login := edProxyUser.Text;
        Result.Password := edProxyPassword.Text;
      end
      else
        Result.Kind := pkUserSettings;
    end;
  end;
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
  cbUsePDBSymbols.Checked := Settings.UsePDB;
  cbDownloadSym.Checked := Settings.DownloadPDB;
  memSymSrv.Text := Settings.SymSrv;
  cbCheckUpdates.Checked := Settings.CheckUpdates;
  case Settings.Proxy.Kind of
    pkNone: cbProxy.ItemIndex := 0;
    pkDefault: cbProxy.ItemIndex := 1;
  else
    cbProxy.ItemIndex := 2;
    edProxyAddr.Text := Settings.Proxy.Host;
    edProxyPort.Text := IntToStr(Settings.Proxy.Port);
    if Settings.Proxy.Kind = pkUserSettingsWithAuthority then
    begin
      cbProxyAuth.ItemIndex := 1 + Byte(Settings.Proxy.AuthKind);
      edProxyUser.Text := Settings.Proxy.Login;
      edProxyPassword.Text := Settings.Proxy.Password;
    end;
  end;
  UpdateGUI;
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
      4: pcSettings.ActivePage := TabSheet5;
    end;
  end;
end;

procedure TdlgSettings.UpdateGUI;
var
  ProxyLvl: Integer;
begin
  cbDownloadSym.Enabled := cbUsePDBSymbols.Checked;
  memSymSrv.Enabled := cbUsePDBSymbols.Checked;
  seLineLimit.Enabled := cbLoadLineSymbols.Checked;
  cbLineDirection.Enabled := cbLoadLineSymbols.Checked;
  if cbLoadLineSymbols.Checked then
  begin
    lblSearchDistance.Font.Color := clWindowText;
    lblSearchDirection.Font.Color := clWindowText;
  end
  else
  begin
    lblSearchDistance.Font.Color := clGrayText;
    lblSearchDirection.Font.Color := clGrayText;
  end;
  if cbProxy.ItemIndex < 2 then
    ProxyLvl := 0
  else
  begin
    if cbProxyAuth.ItemIndex = 0 then
      ProxyLvl := 1
    else
      ProxyLvl := 2;
  end;
  edProxyAddr.Enabled := ProxyLvl > 0;
  edProxyPort.Enabled := ProxyLvl > 0;
  cbProxyAuth.Enabled := ProxyLvl > 0;
  edProxyUser.Enabled := ProxyLvl = 2;
  edProxyPassword.Enabled := ProxyLvl = 2;
end;

end.
