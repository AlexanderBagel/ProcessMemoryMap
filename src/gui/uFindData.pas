////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uFindData.pas
//  * Purpose   : Диалог для поиска данных в памяти процесса
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2013, 2023.
//  * Version   : 1.4.30
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uFindData;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, Vcl.ComCtrls,

  MemoryMap.Core,
  MemoryMap.Utils,

  uBaseForm;

type
  TdlgFindData = class(TBaseAppForm)
    Label1: TLabel;
    edAnsi: TEdit;
    Label2: TLabel;
    edUnicode: TEdit;
    Label3: TLabel;
    edHex: TMemo;
    btnCancel: TButton;
    btnSearch: TButton;
    cbSkipROMem: TCheckBox;
    ProgressBar: TProgressBar;
    btnSearchNext: TButton;
    Label4: TLabel;
    edStartAddr: TEdit;
    procedure edAnsiChange(Sender: TObject);
    procedure edUnicodeChange(Sender: TObject);
    procedure edHexChange(Sender: TObject);
    procedure edHexKeyPress(Sender: TObject; var Key: Char);
    procedure FormCreate(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure btnSearchClick(Sender: TObject);
    procedure btnSearchNextClick(Sender: TObject);
    procedure edStartAddrChange(Sender: TObject);
    procedure btnCancelClick(Sender: TObject);
  private
    Process: THandle;
    InUpdateMode: Boolean;
    SerchBuff: array of Byte;
    SearchPos: Pointer;
    ProgressDelta: NativeInt;
    HasSearchResult: Boolean;
    procedure SearchAtSearchPos;
    function Search(Data: Pointer; DataSize: NativeInt): Boolean;
  end;

var
  dlgFindData: TdlgFindData;

implementation

uses
  uUtils,
  uSettings,
  uRegionProperties;


{$R *.dfm}

procedure TdlgFindData.btnCancelClick(Sender: TObject);
begin
  Close;
end;

procedure TdlgFindData.btnSearchClick(Sender: TObject);
begin
  ProgressBar.Position := 0;
  SearchPos := Pointer(StrToInt64Def('$' + edStartAddr.Text, 0));
  HasSearchResult := False;
  SearchAtSearchPos;
end;

procedure TdlgFindData.btnSearchNextClick(Sender: TObject);
begin
  SearchAtSearchPos;
end;

procedure TdlgFindData.edAnsiChange(Sender: TObject);
var
  AnsiBuff: AnsiString;
begin
  if InUpdateMode then Exit;
  edUnicode.Text := '';
  edHex.Text := '';
  btnSearchNext.Enabled := False;
  InUpdateMode := True;
  try
    AnsiBuff := AnsiString(edAnsi.Text);
    if Length(AnsiBuff) = 0 then Exit;
    SetLength(SerchBuff, Length(AnsiBuff));
    Move(AnsiBuff[1], SerchBuff[0], Length(AnsiBuff));
  finally
    InUpdateMode := False;
  end;
end;

procedure TdlgFindData.edHexChange(Sender: TObject);
var
  Buff: string;
  I, ByteCount: Integer;
  LoPartPresent: Boolean;
  ByteValue: Byte;
begin
  if InUpdateMode then Exit;
  edAnsi.Text := '';
  edUnicode.Text := '';
  btnSearchNext.Enabled := False;
  InUpdateMode := True;
  try
    Buff := Trim(edHex.Text);
    SetLength(SerchBuff, Length(Buff));
    LoPartPresent := False;
    ByteValue := 0;
    ByteCount := 0;
    for I := 1 to Length(Buff) do
    begin
      if CharInSet(Buff[I], ['0'..'9', 'a'..'f', 'A'..'F']) then
      begin
        if LoPartPresent then
        begin
          ByteValue := ByteValue shl 4;
          Inc(ByteValue, StrToInt('$' + Buff[I]));
          SerchBuff[ByteCount] := ByteValue;
          ByteValue := 0;
          LoPartPresent := False;
          Inc(ByteCount);
        end
        else
        begin
          ByteValue := StrToInt('$' + Buff[I]);
          LoPartPresent := True;
        end;
      end
      else
        if Buff[I] <> #32 then
        begin
          edHex.Text := '';
          ShowErrorHint(edHex.Handle);
        end;
    end;
    if LoPartPresent then
      SerchBuff[ByteCount] := ByteValue;
    SetLength(SerchBuff, ByteCount);
  finally
    InUpdateMode := False;
  end;
end;

procedure TdlgFindData.edHexKeyPress(Sender: TObject; var Key: Char);
begin
  if not CharInSet(Key, [#8, #22, '0'..'9', 'a'..'f', 'A'..'F']) then
    Key := #0
  else
    if Key > #22 then
      Key := UpCase(Key);
end;

procedure TdlgFindData.edStartAddrChange(Sender: TObject);
var
  AStartAddr: Int64;
begin
  if edStartAddr.Text = '' then
  begin
    edStartAddr.Text := '0';
    Exit;
  end;
  if not TryStrToInt64('$' + edStartAddr.Text, AStartAddr) then
  begin
    edStartAddr.Text := '0';
    ShowErrorHint(edStartAddr.Handle);
  end;
end;

procedure TdlgFindData.edUnicodeChange(Sender: TObject);
var
  Buff: string;
begin
  if InUpdateMode then Exit;
  edAnsi.Text := '';
  edHex.Text := '';
  btnSearchNext.Enabled := False;
  InUpdateMode := True;
  try
    Buff := edUnicode.Text;
    SetLength(SerchBuff, Length(Buff) * 2);
    Move(Buff[1], SerchBuff[0], Length(Buff) * 2);
  finally
    InUpdateMode := False;
  end;
end;

procedure TdlgFindData.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  CloseHandle(Process);
  Action := caFree;
end;

procedure TdlgFindData.FormCreate(Sender: TObject);
begin
  Process := OpenProcessWithReconnect;
  ProgressDelta := MemoryMapCore.HighAddress div 100;
end;

function TdlgFindData.Search(Data: Pointer; DataSize: NativeInt): Boolean;
var
  pRemote, pSearch, pTmp: PByte;
  I, A: NativeInt;
begin
  Result := False;
  pRemote := Data;
  pSearch := @SerchBuff[0];
  for I := 0 to DataSize - 1 do
  begin
    if pRemote^ <> pSearch^ then
    begin
      Inc(pRemote);
      Continue;
    end;
    pTmp := pRemote;
    Inc(pRemote);
    for A := 1 to Length(SerchBuff) - 1 do
      if pTmp^ <> pSearch^ then
        Break
      else
      begin
        Inc(pTmp);
        Inc(pSearch);
      end;
    Result := pTmp^ = pSearch^;
    if Result then
    begin
      dlgRegionProps := TdlgRegionProps.Create(Application);
      dlgRegionProps.ShowPropertyAtAddr(Pointer(NativeInt(SearchPos) + I), False);
      SearchPos := Pointer(NativeInt(SearchPos) + I + Length(SerchBuff));
      Exit;
    end
    else
      pSearch := @SerchBuff[0];
  end;
end;

procedure TdlgFindData.SearchAtSearchPos;

  procedure IncSearchPos(Value: NativeUInt);
  begin
    SearchPos := Pointer(NativeUInt(SearchPos) + Value);
    ProgressBar.Position := NativeInt(SearchPos) div ProgressDelta;
    Application.ProcessMessages;
  end;

var
  Buff: array of Byte;
  MBI: TMemoryBasicInformation;
  dwLength: Cardinal;
  Size, RegionSize: NativeUInt;
  ProcessLock: TProcessLockHandleList;
  ReadCondition: TReadCondition;
begin
  ProcessLock := nil;
  if Settings.SuspendProcess then
    ProcessLock := SuspendProcess(MemoryMapCore.PID);
  try
    while NativeUInt(SearchPos) < MemoryMapCore.HighAddress do
    begin
      dwLength := SizeOf(TMemoryBasicInformation);
      if VirtualQueryEx(Process,
        SearchPos, MBI, dwLength) <> dwLength then
        RaiseLastOSError;
      if MBI.State <> MEM_COMMIT then
      begin
        IncSearchPos(MBI.RegionSize);
        Continue;
      end;
      Size := MBI.RegionSize;
      SetLength(Buff, Size);
      if cbSkipROMem.Checked then
        ReadCondition := rcReadIfReadWriteAccessPresent
      else
        ReadCondition := rcReadIfReadAccessPresent;
      if not ReadProcessData(Process, SearchPos, @Buff[0],
        Size, RegionSize, ReadCondition) then
      begin
        IncSearchPos(RegionSize);
        Continue;
      end;
      if Search(@Buff[0], Size) then
      begin
        HasSearchResult := True;
        Break;
      end;
      IncSearchPos(Size);
    end;
  finally
    if Settings.SuspendProcess then
      ResumeProcess(ProcessLock);
  end;
  if NativeUInt(SearchPos) >= MemoryMapCore.HighAddress then
  begin
    if HasSearchResult then
      Application.MessageBox('No data available', PChar(Caption), MB_ICONINFORMATION)
    else
      Application.MessageBox('All data found', PChar(Caption), MB_ICONINFORMATION);
    btnSearchNext.Enabled := False;
    ProgressBar.Position := 0;
    SearchPos := nil;
  end
  else
    btnSearchNext.Enabled := True;
end;

end.
