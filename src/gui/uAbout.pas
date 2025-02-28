////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uAbout.pas
//  * Purpose   : Диалог "О программе"
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2025.
//  * Version   : 1.5.46
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
    lblMMVer: TLabel;
    lblRawVer: TLabel;
    Label1: TLabel;
    lblZipVer: TLinkLabel;
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
  distorm;

{$R *.dfm}

procedure TdlgAbout.FormCreate(Sender: TObject);
const
  VFF_PRERELEASE = 2;
var
  dwVer: DWORD;
  VerInfoSize, Dummy: DWORD;
  PVerBbuff, PFixed: Pointer;
  FixLength: UINT;
  VerLoaded: Boolean;
  BetaMark: string;
begin
  VerInfoSize := GetFileVersionInfoSize(PChar(ParamStr(0)), Dummy);
  VerLoaded := False;
  if VerInfoSize > 0 then
  begin
    GetMem(PVerBbuff, VerInfoSize);
    try
      if GetFileVersionInfo(PChar(ParamStr(0)), 0, VerInfoSize, PVerBbuff) then
      begin
        if VerQueryValue(PVerBbuff, '\', PFixed, FixLength) then
        begin
          if PVSFixedFileInfo(PFixed)^.dwFileFlags and VFF_PRERELEASE <> 0 then
            BetaMark := ' (Beta)'
          else
            BetaMark := '';
          lblPMMVer.Caption := Format('Process Memory Map: %d.%d.%d.%d%s', [
            PVSFixedFileInfo(PFixed)^.dwFileVersionMS shr 16,
            PVSFixedFileInfo(PFixed)^.dwFileVersionMS and $FFFF,
            PVSFixedFileInfo(PFixed)^.dwFileVersionLS shr 16,
            PVSFixedFileInfo(PFixed)^.dwFileVersionLS and $FFFF,
            BetaMark]);
          VerLoaded := True;
        end;
      end;
    finally
      FreeMem(PVerBbuff);
    end;
  end;

  if not VerLoaded then
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
end;

procedure TdlgAbout.LinkLabel1LinkClick(Sender: TObject; const Link: string;
  LinkType: TSysLinkType);
begin
  ShellExecute(Handle, 'open', PChar(Link), nil, nil, SW_SHOWNORMAL);
end;

end.
