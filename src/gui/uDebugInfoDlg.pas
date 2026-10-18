////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : uDebugInfoDlg.pas
//  * Purpose   : Brief debug information about the open project
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

unit uDebugInfoDlg;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.Menus,
  Winapi.ShLwApi,

  uUtils,
  ScaledCtrls;

type
  TdlgDbgInfo = class(TForm)
    edDebugInfo: TRichEdit;
    PopupMenu1: TPopupMenu;
    Copydebuginfointoclipboard1: TMenuItem;
    Copyselected1: TMenuItem;
    procedure Copydebuginfointoclipboard1Click(Sender: TObject);
    procedure Copyselected1Click(Sender: TObject);
  private
    { Private declarations }
  public
    procedure ShowDebugInfo(Advanced: TStringList; const RemoteGitInfo: TReseaseInfo);
  end;

var
  dlgDbgInfo: TdlgDbgInfo;

implementation

uses
  Clipbrd,
  MemoryMap.Core,
  RawScanner.Core,
  RawScanner.SymbolStorage,
  uPluginManager,
  RawScanner.Pdb,
  uSettings;

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

procedure TdlgDbgInfo.ShowDebugInfo(Advanced: TStringList;
  const RemoteGitInfo: TReseaseInfo);
var
  Tmp: string;
  S: TArray<string>;
  I, A, Total: Integer;
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
    if RawScannerCore.PdbStorage.Items.Count > 0 then
    begin
      edDebugInfo.Lines.Add('Loaded PDB files:');
      Tmp := IntToStr(Length(IntToStr(RawScannerCore.PdbStorage.Items.Count)));
      A := 1;
      Total := 0;
      for I := 0 to RawScannerCore.PdbStorage.Items.Count - 1 do
      begin
        if RawScannerCore.PdbStorage.Items[I].State <> psReady then Continue;
        edDebugInfo.Lines.Add(Format('%.' + Tmp + 'd: "%s", symbols: %.0n', [A,
          RawScannerCore.PdbStorage.Items[I].LocalPath, RawScannerCore.PdbStorage.Items[I].Count + 0.0]));
        Inc(Total, RawScannerCore.PdbStorage.Items[I].Count);
        Inc(A);
      end;
      edDebugInfo.Lines.Add(EmptyStr);
      edDebugInfo.Lines.Add('Total PDB Symbols count: ' + Format('%.0n', [Total + 0.0]));
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

  if Advanced.Count > 0 then
  begin
    edDebugInfo.Lines.Add('Debug Log: ');
    for I := 0 to Advanced.Count - 1 do
      edDebugInfo.Lines.Add(Advanced[I]);
    edDebugInfo.Lines.Add(EmptyStr);
  end;

  if RemoteGitInfo.Version <> '' then
  begin
    edDebugInfo.Lines.Add('Git latest resease: ' + RemoteGitInfo.Version);
    edDebugInfo.Lines.Add('Published date: ' + RemoteGitInfo.PublishedDate);
    edDebugInfo.Lines.Add('Git page: ' + RemoteGitInfo.HtmlUrl);
    edDebugInfo.Lines.Add('Download count: ' + RemoteGitInfo.DownloadCount);
    edDebugInfo.Lines.Add(EmptyStr);
    if RemoteGitInfo.Body <> '' then
    begin
      edDebugInfo.Lines.Add('Release info:');
      S := RemoteGitInfo.Body.Split([sLineBreak]);
      for Tmp in S do
        edDebugInfo.Lines.Add(Tmp);
      edDebugInfo.Lines.Add(EmptyStr);
    end;
  end;

  edDebugInfo.SelStart := 0;

  ShowModal;
end;

end.
