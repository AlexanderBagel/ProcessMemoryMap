////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uAbout.pas
//  * Purpose   : Диалог "О программе"
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.3.25
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uAbout;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.ExtCtrls, Vcl.StdCtrls, Winapi.ShellAPI;

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
  distorm;

{$R *.dfm}

procedure TdlgAbout.FormCreate(Sender: TObject);
begin
  lblPMMVer.Caption := 'Process Memory Map ' + MemoryMapVersionStr;
  var dver := get_distorm_version;
  lblDistorm.Caption :=
    Format(
    'Disasm engine: <a href="https://github.com/gdabah/distorm">' +
    'diStorm version %d.%d.%d</a>',
    [dver shr 16, Byte(dver shr 8), Byte(dver)]);
end;

procedure TdlgAbout.LinkLabel1LinkClick(Sender: TObject; const Link: string;
  LinkType: TSysLinkType);
begin
  ShellExecute(Handle, 'open', PChar(Link), nil, nil, SW_SHOWNORMAL);
end;

end.
