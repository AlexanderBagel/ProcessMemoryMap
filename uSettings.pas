////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uSelectProcess.pas
//  * Purpose   : Диалог настроек
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2017.
//  * Version   : 1.01
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
  Vcl.StdCtrls, Vcl.ExtCtrls, System.Win.Registry;

type
  TdlgSettings = class(TForm)
    cbShowFreeRegions: TCheckBox;
    cbShowColors: TCheckBox;
    GroupBox1: TGroupBox;
    Button1: TButton;
    btnOk: TButton;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    btnReset: TButton;
    ColorDialog: TColorDialog;
    pnImage0: TPanel;
    pnImage1: TPanel;
    pnImage2: TPanel;
    pnImage3: TPanel;
    pnImage4: TPanel;
    pnImage5: TPanel;
    pnImage6: TPanel;
    pnImage7: TPanel;
    cbSearchDiff: TCheckBox;
    cbShowDetailedHeapData: TCheckBox;
    cbSuspendProcess: TCheckBox;
    cbReconnect: TCheckBox;
    procedure FormCreate(Sender: TObject);
    procedure pnImage0Click(Sender: TObject);
    procedure btnOkClick(Sender: TObject);
    procedure btnResetClick(Sender: TObject);
  private
    Colors: array [0..7] of TColorRef;
    procedure ShowSettings;
  end;

  TSettings = class
  strict private const
    RegRootKey = 'Software\ProcessMemoryMap\';
    RegKeys: array [0..7] of string = ('ImageColor', 'ImagePartColor',
      'PrivateColor', 'SharedColor', 'MappedColor', 'HeapColor',
      'ThreadColor', 'SystemColor');
  strict private
    FColors: array [0..7] of TColorRef;
    FSearchDifferences: Boolean;
    FShowColors: Boolean;
    FShowDetailedHeap: Boolean;
    FShowFreeRegions: Boolean;
    FSuspendProcess: Boolean;
    FReconnect: Boolean;
  public
    constructor Create;
    function GetColor(const Index: Integer): TColorRef;
    procedure SetColor(const Index: Integer; const Value: TColorRef);
    procedure LoadSettings;
    procedure SaveSettings;
    procedure LoadDefault;
    property AutoReconnect: Boolean read FReconnect write FReconnect;
    property ImageColor: TColorRef index 0 read GetColor write SetColor;
    property ImagePartColor: TColorRef index 1 read GetColor write SetColor;
    property PrivateColor: TColorRef index 2 read GetColor write SetColor;
    property SharedColor: TColorRef index 3 read GetColor write SetColor;
    property MappedColor: TColorRef index 4 read GetColor write SetColor;
    property HeapColor: TColorRef index 5 read GetColor write SetColor;
    property ThreadColor: TColorRef index 6 read GetColor write SetColor;
    property SystemColor: TColorRef index 7 read GetColor write SetColor;
    property SearchDifferences: Boolean read FSearchDifferences write FSearchDifferences;
    property ShowColors: Boolean read FShowColors write FShowColors;
    property ShowDetailedHeap: Boolean read FShowDetailedHeap write FShowDetailedHeap;
    property ShowFreeRegions: Boolean read FShowFreeRegions write FShowFreeRegions;
    property SuspendProcess: Boolean read FSuspendProcess write FSuspendProcess;
  end;

  function Settings: TSettings;

var
  dlgSettings: TdlgSettings;

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
  SearchDifferences := True;
  ShowColors := True;
  ShowDetailedHeap := False;
  ShowFreeRegions := False;
  SuspendProcess := False;
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
      AutoReconnect := True;
      if R.ValueExists('AutoReconnect') then
        AutoReconnect := R.ReadBool('AutoReconnect');
      SearchDifferences := R.ReadBool('SearchDifferences');
      ShowColors := R.ReadBool('ShowColors');
      ShowDetailedHeap := R.ReadBool('ShowDetailedHeap');
      ShowFreeRegions := R.ReadBool('ShowFreeRegions');
      SuspendProcess := R.ReadBool('SuspendProcess');
      for I := 0 to 7 do
        FColors[I] := R.ReadInteger(RegKeys[I]);
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
    R.WriteBool('SearchDifferences', SearchDifferences);
    R.WriteBool('ShowColors', ShowColors);
    R.WriteBool('ShowDetailedHeap', ShowDetailedHeap);
    R.WriteBool('ShowFreeRegions', ShowFreeRegions);
    R.WriteBool('SuspendProcess', SuspendProcess);
    for I := 0 to 7 do
      R.WriteInteger(RegKeys[I], FColors[I]);
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
  for I := 0 to 7 do
    Settings.SetColor(I, Colors[I]);
  Settings.SaveSettings;
  ModalResult := mrOk;
end;

procedure TdlgSettings.FormCreate(Sender: TObject);
begin
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
  for I := 0 to 7 do
  begin
    Colors[I] := Settings.GetColor(I);
    P := TPanel(FindComponent('pnImage' + IntToStr(I)));
    P.Color := Colors[I];
    P.Caption := IntToHex(Colors[I], 8);
  end;
end;

initialization

finalization

  _Settings.Free;

end.
