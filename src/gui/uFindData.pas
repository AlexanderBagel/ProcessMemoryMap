////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uFindData.pas
//  * Purpose   : Диалог для поиска данных в памяти процесса
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2024.
//  * Version   : 1.5.45
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
  Vcl.StdCtrls, Vcl.ComCtrls, VirtualTrees,

  MemoryMap.Core,
  MemoryMap.Utils,

  uBaseForm,
  uSearchResult;

type
  TSearchType = (stAnsi, stUnicode, stBuff,
    stHex8, stHex16, stHex32, stHex64,
    stInt8, stInt16, stInt32, stInt64,
    stUInt8, stUInt16, stUInt32, stUInt64,
    stFloat32, stFloat64);

  TdlgFindData = class(TBaseAppForm)
    Label1: TLabel;
    Label2: TLabel;
    btnCancel: TButton;
    btnSearch: TButton;
    cbSkipROMem: TCheckBox;
    ProgressBar: TProgressBar;
    Label4: TLabel;
    edStartAddr: TEdit;
    cbSearchInputType: TComboBox;
    cbSearchText: TComboBox;
    procedure FormCreate(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure btnSearchClick(Sender: TObject);
    procedure edStartAddrChange(Sender: TObject);
    procedure btnCancelClick(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure cbSearchInputTypeChange(Sender: TObject);
  private
    Process: THandle;
    SearchBuff: array of Byte;
    SearchPos: Pointer;
    ProgressDelta: NativeInt;
    HasSearchResult: Boolean;
    SearchCount: Integer;
    SearchResults: TSearchView;
    LastMBI: TMemoryBasicInformation;
    FNextСontinued: Boolean;
    procedure FillSearchResult(AddrVA: ULONG_PTR);
    function MakeSearchBuff: Boolean;
    procedure SearchAtSearchPos;
    procedure Search(Data: Pointer; DataSize: NativeInt);
  end;

var
  dlgFindData: TdlgFindData;

implementation

uses
  MemoryMap.RegionData,
  uUtils,
  uSettings;

var
  PreviousSearches: TStringList;
  PreviousSkipRO: Boolean = True;
  PreviousSearchType: Integer = 0;

type
  TComboBoxAccess = class(TComboBox);

const
  stCaptions: array [TSearchType] of string = (
    'ANSI Text', 'UNICODE Text', 'Hex buffer',
    'Hex Byte (8-bit)', 'Hex Short (16-bit)', 'Hex Long (32-bit)',
    'Hex Long Long (64-bit)', 'Signed Byte (8-bit)',
    'Signed Short (16-bit)', 'Signed Long (32-bit)',
    'Signed Long Long (64-bit)', 'Unsigned Byte (8-bit)',
    'Unsigned Short (16-bit)', 'Unsigned Long (32-bit)',
    'Unsigned Long Long (64-bit)', 'Float (32-bit)', 'Double (64-bit)');
  stHintCaptions: array [TSearchType] of string = (
    'Ansi: ', 'Wide: ', 'HexBuf: ',
    'Hex8: ', 'Hex16: ', 'Hex32: ', 'Hex64: ',
    'Int8: ', 'Int16: ', 'Int32: ', 'Int64: ',
    'UInt8: ', 'UInt16: ', 'UInt32: ', 'UInt64: ',
    'Single: ', 'Double: ');

{$R *.dfm}

procedure TdlgFindData.btnCancelClick(Sender: TObject);
begin
  Close;
end;

procedure TdlgFindData.btnSearchClick(Sender: TObject);
var
  Index: Integer;
begin
  if PreviousSearches.Count = 0 then
    PreviousSearches.Add(cbSearchText.Text)
  else
  begin
    Index := PreviousSearches.IndexOf(cbSearchText.Text);
    if Index >= 0 then
      PreviousSearches.Delete(Index);
    PreviousSearches.Insert(0, cbSearchText.Text);
  end;
  PreviousSkipRO := cbSkipROMem.Checked;
  PreviousSearchType := cbSearchInputType.ItemIndex;
  try
    ProgressBar.Position := 0;
    SearchPos := Pointer(StrToInt64Def('$' + edStartAddr.Text, 0));
    HasSearchResult := False;
    SearchCount := 0;
    SearchAtSearchPos;
  finally
    cbSearchText.Items.Assign(PreviousSearches);
  end;
end;

procedure TdlgFindData.cbSearchInputTypeChange(Sender: TObject);
begin
  FNextСontinued := False;
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

procedure TdlgFindData.FillSearchResult(AddrVA: ULONG_PTR);
var
  SearchItem: TSearchItem;
  Index: Integer;
  RegionData: TRegionData;
  NestPfx: string;
begin
  if not HasSearchResult then
  begin
    if dlgSearchResult = nil then
      dlgSearchResult := TdlgSearchResult.Create(Application);
    dlgSearchResult.Show;
    if FNextСontinued then
      NestPfx := '-> ';
    SearchResults := dlgSearchResult.AddNewSearchList(NestPfx +
      stHintCaptions[TSearchType(cbSearchInputType.ItemIndex)] + '"' + cbSearchText.Text + '"');
    HasSearchResult := True;
  end;
  SearchItem := Default(TSearchItem);
  SearchItem.AddrVA := AddrVA;
  SearchItem.MBI := LastMBI;
  MemoryMapCore.GetRegionIndex(Pointer(AddrVA), Index);
  if Index >= 0 then
  begin
    RegionData := MemoryMapCore.GetRegionAtUnfilteredIndex(Index);
    SearchItem.RegionFilter := MemoryMapCore.RegionToFilterType(RegionData,fiMapped);
    SearchItem.RegionType := RegionData.RegionType;
    SearchItem.Details := RegionData.Details;
    if RegionData.Parent <> nil then
      SearchItem.Details :=  RegionData.Parent.Details;
    SearchItem.Section := string(RegionData.Section.Caption);
  end;
  dlgSearchResult.UpdateSearchList(SearchResults, SearchItem);
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
  for var S in stCaptions do
    cbSearchInputType.Items.Add(S);
  cbSearchInputType.ItemIndex := 0;
  cbSearchText.Items.Assign(PreviousSearches);
  if PreviousSearches.Count > 0 then
    cbSearchText.ItemIndex := 0;
  cbSkipROMem.Checked := PreviousSkipRO;
  cbSearchInputType.ItemIndex := PreviousSearchType;
end;

procedure TdlgFindData.FormShow(Sender: TObject);
begin
  cbSearchText.SetFocus;
end;

function TdlgFindData.MakeSearchBuff: Boolean;
var
  AnsiBuff: AnsiString;
  UnicodeBuff: string;
  I, ByteCount: Integer;
  LoPartPresent: Boolean;
  ByteValue: Byte;
  IntBuf: Int64;
  UIntBuf: UInt64;
  SingleBuff: Single;
  DoubleBuff: Double;
begin
  Result := False;
  if cbSearchText.Text = '' then
    Exit;
  IntBuf := 0;
  UIntBuf := 0;
  case TSearchType(cbSearchInputType.ItemIndex) of
    stAnsi:
    begin
      AnsiBuff := AnsiString(cbSearchText.Text);
      SetLength(SearchBuff, Length(AnsiBuff));
      Move(AnsiBuff[1], SearchBuff[0], Length(AnsiBuff));
    end;
    stUnicode:
    begin
      UnicodeBuff := cbSearchText.Text;
      SetLength(SearchBuff, Length(UnicodeBuff) shl 1);
      Move(UnicodeBuff[1], SearchBuff[0], Length(SearchBuff));
    end;
    stBuff:
    begin
      UnicodeBuff := StringReplace(cbSearchText.Text, ' ', '', [rfReplaceAll]);
      UnicodeBuff := StringReplace(UnicodeBuff, '$', '', [rfReplaceAll]);
      UnicodeBuff := StringReplace(UnicodeBuff, '0x', '', [rfReplaceAll]);
      if UnicodeBuff = '' then Exit;
      SetLength(SearchBuff, Length(UnicodeBuff));
      LoPartPresent := False;
      ByteValue := 0;
      ByteCount := 0;
      for I := 1 to Length(UnicodeBuff) do
      begin
        if CharInSet(UnicodeBuff[I], ['0'..'9', 'a'..'f', 'A'..'F']) then
        begin
          if LoPartPresent then
          begin
            ByteValue := ByteValue shl 4;
            Inc(ByteValue, StrToInt('$' + UnicodeBuff[I]));
            SearchBuff[ByteCount] := ByteValue;
            LoPartPresent := False;
            Inc(ByteCount);
          end
          else
          begin
            ByteValue := StrToInt('$' + UnicodeBuff[I]);
            LoPartPresent := True;
          end;
        end
        else
        begin
          ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle);
          Exit;
        end;
      end;
      if LoPartPresent then
        SearchBuff[ByteCount] := ByteValue;
      SetLength(SearchBuff, ByteCount);
    end;
    stHex8..stHex64:
    begin
      if not TryStrToUInt64('$' + cbSearchText.Text, UIntBuf) then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle);
        Exit;
      end;
    end;
    stInt8..stInt64:
    begin
      if not TryStrToInt64(cbSearchText.Text, IntBuf) then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle);
        Exit;
      end;
    end;
    stUInt8..stUInt64:
    begin
      if not TryStrToUInt64(cbSearchText.Text, UIntBuf) then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle);
        Exit;
      end;
    end;
    stFloat32:
    begin
      UnicodeBuff := StringReplace(cbSearchText.Text, ',', FormatSettings.DecimalSeparator, [rfReplaceAll]);
      UnicodeBuff := StringReplace(UnicodeBuff, '.', FormatSettings.DecimalSeparator, [rfReplaceAll]);
      if not TryStrToFloat(UnicodeBuff, SingleBuff) then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle);
        Exit;
      end;
    end;
    stFloat64:
    begin
      UnicodeBuff := StringReplace(cbSearchText.Text, ',', FormatSettings.DecimalSeparator, [rfReplaceAll]);
      UnicodeBuff := StringReplace(UnicodeBuff, '.', FormatSettings.DecimalSeparator, [rfReplaceAll]);
      if not TryStrToFloat(UnicodeBuff, DoubleBuff) then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle);
        Exit;
      end;
    end;
  end;

  case TSearchType(cbSearchInputType.ItemIndex) of
    stHex8, stInt8, stUInt8: SetLength(SearchBuff, 1);
    stHex16, stInt16, stUInt16: SetLength(SearchBuff, 2);
    stHex32, stInt32, stUInt32, stFloat32: SetLength(SearchBuff, 4);
    stHex64, stInt64, stUInt64, stFloat64: SetLength(SearchBuff, 8);
  end;

  case TSearchType(cbSearchInputType.ItemIndex) of
    stHex8..stHex64, stUInt8..stUInt64: Move(UIntBuf, SearchBuff[0], Length(SearchBuff));
    stInt8..stInt64: Move(IntBuf, SearchBuff[0], Length(SearchBuff));
    stFloat32: Move(SingleBuff, SearchBuff[0], Length(SearchBuff));
    stFloat64: Move(DoubleBuff, SearchBuff[0], Length(SearchBuff));
  end;

  SearchCount := 0;
  Result := Length(SearchBuff) > 0;
end;

procedure TdlgFindData.Search(Data: Pointer; DataSize: NativeInt);
var
  pRemote, pSearch, pTmp: PByte;
  I, A: NativeInt;
begin
  pRemote := Data;
  pSearch := @SearchBuff[0];
  for I := 0 to DataSize - 1 do
  begin
    if pRemote^ <> pSearch^ then
    begin
      Inc(pRemote);
      Continue;
    end;
    pTmp := pRemote;
    Inc(pRemote);
    for A := 1 to Length(SearchBuff) - 1 do
      if pTmp^ <> pSearch^ then
        Break
      else
      begin
        Inc(pTmp);
        Inc(pSearch);
      end;
    if pTmp^ = pSearch^ then
    begin
      FillSearchResult(NativeInt(SearchPos) + I);
      Inc(SearchCount);
      if SearchCount >= Settings.SearchLimit then
      begin
        SearchPos := Pointer(NativeInt(SearchPos) + I + Length(SearchBuff));
        Exit;
      end;
    end
    else
      pSearch := @SearchBuff[0];
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
  dwLength: Cardinal;
  Size, RegionSize: NativeUInt;
  ProcessLock: TProcessLockHandleList;
  ReadCondition: TReadCondition;
begin
  if not MakeSearchBuff then Exit;  
  ProcessLock := nil;
  if Settings.SuspendProcess then
    ProcessLock := SuspendProcess(MemoryMapCore.PID);
  try
    while NativeUInt(SearchPos) < MemoryMapCore.HighAddress do
    begin
      dwLength := SizeOf(TMemoryBasicInformation);
      if VirtualQueryEx(Process,
        SearchPos, LastMBI, dwLength) <> dwLength then
        RaiseLastOSError;
      if LastMBI.State <> MEM_COMMIT then
      begin
        IncSearchPos(LastMBI.RegionSize);
        Continue;
      end;
      Size := LastMBI.RegionSize;
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
      Search(@Buff[0], Size);
      if SearchCount >= Settings.SearchLimit then
        Break;
      IncSearchPos(Size);
    end;
  finally
    if Settings.SuspendProcess then
      ResumeProcess(ProcessLock);
    ProgressBar.Position := 0;
    FNextСontinued := False;
  end;
  if HasSearchResult then
  begin
    if SearchCount >= Settings.SearchLimit then
    begin
      Application.MessageBox(PChar(
        Format('The set search limit (%d) has been reached', [Settings.SearchLimit])),
        PChar(Caption), MB_ICONINFORMATION);
      FNextСontinued := True;
    end
    else
      SearchPos := nil;
  end
  else
  begin
    Application.MessageBox('No data available', PChar(Caption), MB_ICONINFORMATION);
    SearchPos := nil;
  end;
  edStartAddr.Text := IntToHex(NativeUInt(SearchPos));
end;

initialization

  PreviousSearches := TStringList.Create;

finalization

  PreviousSearches.Free;

end.
