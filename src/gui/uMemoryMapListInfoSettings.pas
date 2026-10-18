////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : uMemoryMapListInfoSettings.pas
//  * Purpose   : Memory Scan Options
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

unit uMemoryMapListInfoSettings;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.Buttons, Vcl.StdCtrls, Vcl.ExtCtrls,
  uBaseForm, Vcl.Mask;

type
  TdlgMemoryMapListInfoSettings = class(TBaseAppForm)
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
