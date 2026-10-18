////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : uAbout.pas
//  * Purpose   : "About the Program" Dialog Box
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

unit uAbout;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.ExtCtrls, Vcl.StdCtrls, Winapi.ShellAPI, System.StrUtils;

type
  TdlgAbout = class(TForm)
    Image1: TImage;
    lblPMMVer: TLabel;
    Label2: TLabel;
    LinkLabel3: TLinkLabel;
    Button1: TButton;
    Label3: TLabel;
    LinkLabel4: TLinkLabel;
    lblDistorm: TLinkLabel;
    LinkLabel1: TLinkLabel;
    lblMMVer: TLabel;
    lblRawVer: TLabel;
    Label1: TLabel;
    lblZipVer: TLinkLabel;
    lblHexView: TLinkLabel;
    LinkLabel5: TLinkLabel;
    procedure LinkLabel1LinkClick(Sender: TObject; const Link: string;
      LinkType: TSysLinkType);
    procedure FormCreate(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  dlgAbout: TdlgAbout;

implementation

uses
  MemoryMap.Core,
  RawScanner.Core,
  FWZipConsts,
  distorm,
  FWHexView,
  uUtils;

{$R *.dfm}

procedure TdlgAbout.FormCreate(Sender: TObject);
var
  Info: TVersionInfo;
  dwVer: DWORD;
begin
  if GetVersionInfo(Info) then
  begin
    with Info do
      lblPMMVer.Caption := Format('Process Memory Map: %d.%d.%d.%d%s', [
        Major, Minor, Release, Build, IfThen(Beta, ' (Beta)', '')]);
  end
  else
    lblPMMVer.Caption := 'Process Memory Map ' + MemoryMapVersionStr;

  dwVer := get_distorm_version;
  lblDistorm.Caption :=
    Format(
    'Disasm engine: <a href="https://github.com/gdabah/distorm">' +
    'diStorm version %d.%d.%d</a>',
    [dwVer shr 16, Byte(dwVer shr 8), Byte(dwVer)]);

  dwVer := MemoryMapVersionInt;
  lblMMVer.Caption := Format(
    'MemoryMap Core: version %d.%d (revision %d)',
    [dwVer shr 24, Byte(dwVer shr 16), Word(dwVer)]);

  dwVer := RawScannerVersionInt;
  lblRawVer.Caption := Format(
    'RawScanner Core: version %d.%d (revision %d)',
    [dwVer shr 24, Byte(dwVer shr 16), Word(dwVer)]);

  dwVer := FWZipVersionInt;
  lblZipVer.Caption := Format(
    'Compression Library: <a href="https://github.com/AlexanderBagel/FWZip">' +
    'FWZip version %d.%d.%d</a>',
    [dwVer shr 24, Byte(dwVer shr 16), Word(dwVer)]);

  dwVer := FWHexViewVersionInt;
  lblHexView.Caption := Format(
    'HexView Project: <a href="https://github.com/AlexanderBagel/FWHexView">' +
    'FWHexView version %d.%d.%d</a>',
    [dwVer shr 24, Byte(dwVer shr 16), Word(dwVer)]);
end;

procedure TdlgAbout.LinkLabel1LinkClick(Sender: TObject; const Link: string;
  LinkType: TSysLinkType);
begin
  ShellExecute(Handle, 'open', PChar(Link), nil, nil, SW_SHOWNORMAL);
end;

end.
