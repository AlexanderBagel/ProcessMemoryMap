////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : uBaseForm.pas
//  * Purpose   : The base form from which all child forms are derived
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

unit uBaseForm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Generics.Collections;

type
  TBaseAppForm = class(TForm)
    procedure FormKeyPress(Sender: TObject; var Key: Char);
  private
    class var BaseFormList: TList<TBaseAppForm>;
    class constructor ClassCreate;
    class destructor ClassDestroy;
  protected
    procedure CreateParams(var Params: TCreateParams); override;
    function ShouldBeStandalone: Boolean; virtual;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    class function CloseAllBaseForm: Boolean;
  end;

var
  BaseAppForm: TBaseAppForm;

implementation

uses
  uSettings;

{$R *.dfm}

class constructor TBaseAppForm.ClassCreate;
begin
  BaseFormList := TList<TBaseAppForm>.Create;
end;

class destructor TBaseAppForm.ClassDestroy;
begin
  BaseFormList.Free;
end;

class function TBaseAppForm.CloseAllBaseForm: Boolean;
var
  BaseForm: TBaseAppForm;
begin
  Result := False;
  for BaseForm in BaseFormList do
    if not BaseForm.CloseQuery then Exit;
  for BaseForm in BaseFormList do
    BaseForm.Close;
  Result := True;
end;

constructor TBaseAppForm.Create(AOwner: TComponent);
begin
  inherited;
  BaseFormList.Add(Self);
end;

procedure TBaseAppForm.CreateParams(var Params: TCreateParams);
begin
  inherited;
  if ShouldBeStandalone then
  begin
    Params.ExStyle := Params.ExStyle or WS_EX_APPWINDOW;
    Params.WndParent := 0;
  end;
end;

destructor TBaseAppForm.Destroy;
var
  Idx: Integer;
begin
  Idx := BaseFormList.IndexOf(Self);
  if Idx >= 0 then
    BaseFormList.Delete(Idx);
  inherited;
end;

procedure TBaseAppForm.FormKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #27 then Close;
end;

function TBaseAppForm.ShouldBeStandalone: Boolean;
begin
  Result := Settings.ShowChildFormsOnTaskBar;
end;

end.
