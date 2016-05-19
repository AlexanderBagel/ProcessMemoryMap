////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uMemoryMapListInfoSettings.pas
//  * Purpose   : Диалог настроек для процедуры сканирования памяти
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2016.
//  * Version   : 1.0
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uMemoryMapListInfoSettings;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.Buttons, Vcl.StdCtrls, Vcl.ExtCtrls;

type
  TdlgMemoryMapListInfoSettings = class(TForm)
    OpenMMListDialog: TOpenDialog;
    edMML: TLabeledEdit;
    SpeedButton1: TSpeedButton;
    cbShowMiniDump: TCheckBox;
    cbShowDisasm: TCheckBox;
    cbDumpSize: TComboBox;
    Label1: TLabel;
    cbSave: TCheckBox;
    edSave: TLabeledEdit;
    SpeedButton2: TSpeedButton;
    SaveResultDialog: TSaveDialog;
    cbSaveFullDump: TCheckBox;
    Bevel1: TBevel;
    Button1: TButton;
    Button2: TButton;
    cbSaveIfWrongCRC: TCheckBox;
    cbGenerateMML: TCheckBox;
    procedure SpeedButton1Click(Sender: TObject);
    procedure SpeedButton2Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  dlgMemoryMapListInfoSettings: TdlgMemoryMapListInfoSettings;

implementation

{$R *.dfm}

procedure TdlgMemoryMapListInfoSettings.Button2Click(Sender: TObject);
begin
  if not FileExists(edMML.Text) then
    raise Exception.CreateFmt('File "%s" not found.', [edMML.Text]);
  if cbSave.Checked then
  begin
    if edSave.Text = '' then
      raise Exception.Create('Path to result file is empty.');
    try
      TFileStream.Create(edSave.Text, fmCreate).Free;
    except
      raise Exception.CreateFmt('Can not create result file "%s".', [edSave.Text]);
    end;
  end;
  ModalResult := mrOk;
end;

procedure TdlgMemoryMapListInfoSettings.SpeedButton1Click(Sender: TObject);
begin
  if OpenMMListDialog.Execute then
    edMML.Text := OpenMMListDialog.FileName;
end;

procedure TdlgMemoryMapListInfoSettings.SpeedButton2Click(Sender: TObject);
begin
  if SaveResultDialog.Execute then
    edSave.Text := SaveResultDialog.FileName;
end;

end.
