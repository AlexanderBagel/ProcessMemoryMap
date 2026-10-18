////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : uProgress.pas
//  * Purpose   : Helper dialog for displaying progress
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

unit uProgress;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.ComCtrls, Vcl.StdCtrls, Vcl.ExtCtrls,

  FWProgressBar,
  uBaseForm;

type
  TdlgProgress = class(TForm)
    Panel1: TPanel;
    lblProgress: TLabel;
    procedure FormDestroy(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { Private declarations }
  public
    ProgressBar, ProgressBarAdv: TFWProgressBar;
    procedure ShowWithCallback(Value: TProc);
    procedure UpdateCaption(const Value: string; APosition: Integer);
  end;

var
  dlgProgress: TdlgProgress;

implementation

uses
  uUtils;

{$R *.dfm}

{ TdlgProgress }

procedure TdlgProgress.FormCreate(Sender: TObject);
begin
  ProgressBar := TFWProgressBar.Create(Self);
  ProgressBar.Parent := Self;
  ProgressBar.SetBounds(
    ToDpi(16, FCurrentPPI),
    ToDpi(35, FCurrentPPI),
    ClientWidth - ToDpi(16, FCurrentPPI) shl 1,
    ToDpi(17, FCurrentPPI));
  ProgressBarAdv := TFWProgressBar.Create(Self);
  ProgressBarAdv.Parent := Self;
  ProgressBarAdv.SetBounds(
    ToDpi(16, FCurrentPPI),
    ToDpi(48, FCurrentPPI),
    ClientWidth - ToDpi(16, FCurrentPPI) shl 1,
    ToDpi(17, FCurrentPPI));
  ProgressBarAdv.CancelHint := 'Cancel download';
  ProgressBarAdv.ShowHint := True;
  ProgressBarAdv.Visible := False;
end;

procedure TdlgProgress.FormDestroy(Sender: TObject);
begin
  dlgProgress := nil;
end;

procedure TdlgProgress.ShowWithCallback(Value: TProc);
begin
  Show;
  Application.ProcessMessages;
  Value;
end;

procedure TdlgProgress.UpdateCaption(const Value: string; APosition: Integer);
begin
  lblProgress.Caption := Value;
  lblProgress.Repaint;
  ProgressBar.Position := APosition;
  ProgressBar.Repaint;
end;

end.
