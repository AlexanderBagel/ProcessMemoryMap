////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uDebugInfoDlg.pas
//  * Purpose   : Краткая отладочная информация об открытом проекте
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2016, 2023.
//  * Version   : 1.4.27
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uDebugInfoDlg;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.Menus,
  Winapi.ShLwApi,

  ScaledCtrls;

type
  TdlgDbgInfo = class(TForm)
    edDebugInfo: TRichEdit;
    PopupMenu1: TPopupMenu;
    Copydebuginfointoclipboard1: TMenuItem;
    Copyselected1: TMenuItem;
    procedure Copydebuginfointoclipboard1Click(Sender: TObject);
    procedure Copyselected1Click(Sender: TObject);
    procedure FormKeyPress(Sender: TObject; var Key: Char);
  private
    { Private declarations }
  public
    procedure ShowDebugInfo;
  end;

var
  dlgDbgInfo: TdlgDbgInfo;

implementation

uses
  Clipbrd,
  MemoryMap.Core,
  RawScanner.SymbolStorage,
  uPluginManager,
  uSettings,
  uUtils;

{$R *.dfm}

{ TdlgDbgInfo }

procedure TdlgDbgInfo.Copydebuginfointoclipboard1Click(Sender: TObject);
begin
  Clipboard.AsText := edDebugInfo.Text;
end;

procedure TdlgDbgInfo.Copyselected1Click(Sender: TObject);
begin
  edDebugInfo.CopyToClipboard;
end;

procedure TdlgDbgInfo.FormKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #27 then Close;
end;

procedure TdlgDbgInfo.ShowDebugInfo;
var
  Tmp: string;
  I: Integer;
begin
  if MemoryMapCore.PID <> 0 then
  begin
    if MemoryMapCore.Process64 then
      Tmp := ' (x64)'
    else
      Tmp := ' (x86)';
    edDebugInfo.Lines.Add('PID: ' + IntToStr(MemoryMapCore.PID) + Tmp);
    edDebugInfo.Lines.Add('Name: ' + MemoryMapCore.ProcessName);
    edDebugInfo.Lines.Add('Path: ' + MemoryMapCore.ProcessPath);

    edDebugInfo.Lines.Add(EmptyStr);
    edDebugInfo.Lines.Add('Elapsed: ' +
      Format('%2.3f sec', [DebugElapsedMilliseconds / 1000]));
    SetLength(Tmp, 50);
    StrFormatByteSize(GetMemAlloc - DebugInitialHeapSize, @Tmp[1], 50);
    edDebugInfo.Lines.Add('Memory allocated: ' + PChar(Tmp));

    edDebugInfo.Lines.Add(EmptyStr);
    edDebugInfo.Lines.Add('Symbols count: ' +
      Format('%.0n', [SymbolStorage.Count + 0.0]));
    edDebugInfo.Lines.Add('Symbols unique count: ' +
      Format('%.0n', [SymbolStorage.UniqueCount + 0.0]));
    edDebugInfo.Lines.Add('Duplicates: ' +
      Format('%.0n', [SymbolStorage.Count - SymbolStorage.UniqueCount + 0.0]));
    if Settings.LoadStrings or (SymbolStorage.StringsCount > 0) then
      edDebugInfo.Lines.Add('Strings: ' +
        Format('%.0n', [SymbolStorage.StringsCount + 0.0]))
    else
      edDebugInfo.Lines.Add('Strings: disabled in settings');
    edDebugInfo.Lines.Add(EmptyStr);
    if MemoryMapCore.DebugMapData.LoadedMap.Count > 0 then
    begin
      edDebugInfo.Lines.Add('Loaded MAP files:');
      for I := 0 to MemoryMapCore.DebugMapData.LoadedMap.Count - 1 do
        edDebugInfo.Lines.Add(Format('%d: %s', [I + 1,
          MemoryMapCore.DebugMapData.LoadedMap[I]]));
      edDebugInfo.Lines.Add(EmptyStr);
      edDebugInfo.Lines.Add('Function count: ' +
        Format('%.0n', [MemoryMapCore.DebugMapData.Items.Count + 0.0]));
      if MemoryMapCore.DebugMapData.Units.Count > 0 then
      begin
        edDebugInfo.Lines.Add('Units count: ' +
          Format('%.0n', [MemoryMapCore.DebugMapData.Units.Count + 0.0]));
        edDebugInfo.Lines.Add('Lines count: ' +
          Format('%.0n', [MemoryMapCore.DebugMapData.Lines.Count + 0.0]));
      end;
      edDebugInfo.Lines.Add(EmptyStr);
    end;
    if PluginManager.Items.Count > 0 then
    begin
      edDebugInfo.Lines.Add('Plugins:');
      edDebugInfo.Lines.Add(EmptyStr);
      for var Plugin in PluginManager.Items do
      begin
        edDebugInfo.Lines.Add('Name: ' + Plugin.Name + ', UID: ' + IntToHex(Plugin.UID, 1));
        edDebugInfo.Lines.Add('Author: ' + Plugin.Author);
        edDebugInfo.Lines.Add('Page: ' + Plugin.Page);
        edDebugInfo.Lines.Add('Description: ' + Plugin.Description);
        if Assigned(Plugin.Gate.DescriptorCount) then
        try
          edDebugInfo.Lines.Add(EmptyStr);
          edDebugInfo.Lines.Add('Descriptors count: ' +
            Format('%.0n', [Plugin.Gate.DescriptorCount + 0.0]));
        except
          on E: Exception do
          begin
            edDebugInfo.Lines.Add('Error get descriptors count');
            edDebugInfo.Lines.Add(E.ClassName + ': ' + E.Message);
          end;
        end;
        edDebugInfo.Lines.Add(EmptyStr);
      end;
    end;
  end;
  ShowModal;
end;

end.
