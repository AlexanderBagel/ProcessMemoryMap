////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uProgress.pas
//  * Purpose   : Вспомогательный диалог для отображения прогреса
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.2.28
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uProgress;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.ComCtrls, Vcl.StdCtrls, Vcl.ExtCtrls,

  FWProgressBar;

type
  TdlgProgress = class(TForm)
    Panel1: TPanel;
    lblProgress: TLabel;
    procedure FormDestroy(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { Private declarations }
  public
    ProgressBar: TFWProgressBar;
    procedure ShowWithCallback(Value: TProc);
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

end.
