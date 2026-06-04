////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uPatchDetect.pas
//  * Purpose   : Диалог для работы со сканером перехваченых функций
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.6.49
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
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
    procedure FormKeyPress(Sender: TObject; var Key: Char);
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

procedure TdlgPatchRestore.FormKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #27 then Close;
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
