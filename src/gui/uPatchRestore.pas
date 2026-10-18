////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : uPatchDetect.pas
//  * Purpose   : Restore Hooked Functions
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
unit uPatchRestore;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls,
  Vcl.CheckLst, Generics.Collections,

  uBaseForm,
  RawScanner.Types,
  MemoryMap.Core,
  uUtils;

type
  TPatchedData = record
    Description: string;
    AddrVA: ULONG_PTR64;
    OriginalBuff: array of Byte;
  end;
  TPatchList = class(TList<TPatchedData>);

  TdlgPatchRestore = class(TBaseAppForm)
    clbPatches: TCheckListBox;
    Label1: TLabel;
    btnCancel: TButton;
    btnRestore: TButton;
    procedure clbPatchesClickCheck(Sender: TObject);
  public
    procedure Restore(AList: TPatchList);
  end;

var
  dlgPatchRestore: TdlgPatchRestore;

implementation

{$R *.dfm}

procedure TdlgPatchRestore.clbPatchesClickCheck(Sender: TObject);
var
  CanWork: Boolean;
  I: Integer;
begin
  CanWork := False;
  for I := 0 to clbPatches.Items.Count - 1 do
    if clbPatches.Checked[I] then
    begin
      CanWork := True;
      Break;
    end;
  btnRestore.Enabled := CanWork;
end;

procedure TdlgPatchRestore.Restore(AList: TPatchList);
var
  Process: THandle;
  PatchedData: TPatchedData;
  I: Integer;
begin
  for PatchedData in AList do
    clbPatches.Items.Add(PatchedData.Description);
  if ShowModal = mrOk then
  begin
    Process := OpenProcess(PROCESS_VM_WRITE or PROCESS_VM_OPERATION, False, MemoryMapCore.PID);
    if Process = 0 then
      raise Exception.Create(
        'Can not open process ID: ' + IntToStr(MemoryMapCore.PID) + sLineBreak +
        Format('Error %d: %s', [GetLastError, SysErrorMessage(GetLastError)]));
    try
      for I := 0 to clbPatches.Items.Count - 1 do
        if clbPatches.Checked[I] then
        begin
          PatchedData := AList[I];
          if not WriteProcessData(Process, Pointer(PatchedData.AddrVA),
            @PatchedData.OriginalBuff[0], Length(PatchedData.OriginalBuff)) then
            raise Exception.Create(
              'Can not restore hook: ' + PatchedData.Description + sLineBreak +
              Format('Error %d: %s', [GetLastError, SysErrorMessage(GetLastError)]));
        end;
    finally
      CloseHandle(Process);
    end;
  end;
end;

end.
