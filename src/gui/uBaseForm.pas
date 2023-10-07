////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uBaseForm.pas
//  * Purpose   : Базовая форма от которой наследуются все дочерние
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.4.30
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uBaseForm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs;

type
  TBaseAppForm = class(TForm)
  protected
    procedure CreateParams(var Params: TCreateParams); override;
  end;

var
  BaseAppForm: TBaseAppForm;

implementation

uses
  uSettings;

{$R *.dfm}

procedure TBaseAppForm.CreateParams(var Params: TCreateParams);
begin
  inherited;
  if Settings.ShowChildFormsOnTaskBar then
  begin
    Params.ExStyle := Params.ExStyle or WS_EX_APPWINDOW;
    Params.WndParent := 0;
  end;
end;

end.
