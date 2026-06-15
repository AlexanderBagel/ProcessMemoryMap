////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uFindData.pas
//  * Purpose   : Диалог для поиска данных в памяти процесса
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.6.50
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
  Vcl.Buttons, Vcl.StdCtrls, Vcl.ExtCtrls, VirtualTrees, StrUtils, Math,

  MemoryMap.Core,
  MemoryMap.Utils,

  RawScanner.SymbolStorage,

  uBaseForm,
  uSearchResult,
  uDumpDisplayUtils,
  FWProgressBar;

type
  TSearchType = (stAnsi, stUnicode, stBuff,
    stHex8, stHex16, stHex32, stHex64,
    stInt8, stInt16, stInt32, stInt64,
    stUInt8, stUInt16, stUInt32, stUInt64,
    stFloat32, stFloat64,
    stReference, stMask);

  TCallPushRefSearchBuff = packed record
    JmpOpcode: Byte;
    Offset: Cardinal;
  end;

  TMaskKind = (mkByte, mkWild, mkNibble, mkRel32);
  TMaskEntry = record
    Kind: TMaskKind;
    Value: Byte;
    NibbleMask: Byte;
    Rel32Target: UInt64;
  end;
  TMaskPattern = array of TMaskEntry;

  TdlgFindData = class(TBaseAppForm)
    Label1: TLabel;
    Label2: TLabel;
    btnCancel: TButton;
    btnSearch: TButton;
    cbSkipROMem: TCheckBox;
    Label4: TLabel;
    edStartAddr: TEdit;
    cbSearchInputType: TComboBox;
    cbSearchText: TComboBox;
    pnProgress: TPanel;
    btnHelp: TSpeedButton;
    procedure FormCreate(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure btnSearchClick(Sender: TObject);
    procedure edStartAddrChange(Sender: TObject);
    procedure btnCancelClick(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure cbSearchInputTypeChange(Sender: TObject);
    procedure btnHelpClick(Sender: TObject);
  private
    ProgressBar: TFWProgressBar;
    Process: THandle;
    SearchBuff: array of Byte;
    MaskPattern: array of TMaskPattern;
    SearchPos: Pointer;
    ProgressDelta: NativeInt;
    HasSearchResult, RelPresent: Boolean;
    SearchCount: Integer;
    SearchResults: TSearchView;
    LastMBI: TMemoryBasicInformation;
    FNextСontinued: Boolean;
    procedure InternalSearchInBuff(Data: Pointer; DataSize: NativeInt);
    procedure InternalSearchAsMask(Data: PByte; DataSize: NativeInt);
    procedure FillSearchResult(AddrVA: ULONG_PTR);
    function MakeSearchBuff: Boolean;
    function MakeMaskPattern(const AMask: string): Boolean;
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

const
  DefErrTitle = 'Invalid search pattern';
  ErrNotNumber = 'You can only type a number here.';
  ErrNotHex = 'You can only enter numbers and letters from A to F here.';
  ErrNotFloat = 'You can only enter numbers and a period or a comma here.';
  ErrWrongMask = 'Look at the help to the right of the search pattern input field, which describes the valid patterns.';
  ErrNoData = 'No search pattern found.';

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
    'Unsigned Long Long (64-bit)', 'Float (32-bit)', 'Double (64-bit)',
    'Reference to Address', 'Mask');
  stHintCaptions: array [TSearchType] of string = (
    'Ansi: ', 'Wide: ', 'HexBuf: ',
    'Hex8: ', 'Hex16: ', 'Hex32: ', 'Hex64: ',
    'Int8: ', 'Int16: ', 'Int32: ', 'Int64: ',
    'UInt8: ', 'UInt16: ', 'UInt32: ', 'UInt64: ',
    'Single: ', 'Double: ', 'Address: ', 'Mask: ');

{$R *.dfm}

procedure TdlgFindData.btnCancelClick(Sender: TObject);
begin
  Close;
end;

procedure TdlgFindData.btnHelpClick(Sender: TObject);
begin
  Application.MessageBox(PChar(
    'You may enter hexadecimal values, question marks for unknown bytes or parts of bytes, and curly braces to specify an address calculated based on RIP.' + sLineBreak +
    'Spaces are ignored.' + sLineBreak +
    sLineBreak +
    'For example: (enter without quotes)' + sLineBreak +
    '“E8 {AddrVA}” - to search for CALL instructions at the specified rel32 AddrVA' + sLineBreak +
    '“4? 8D ?5 {AddrVA}” - to search for LEA reg64 [RIP + rel32] instructions (with the REX prefix)' + sLineBreak +
    '“68 ???????? E8 {AddrVA} C3”  - to search for the instruction sequence push (any imm32) + call rel32 AddrVA + ret' + sLineBreak +
    '“68 [AddrVA]” - to search for PUSH instructions at the specified imm32 AddrVA'),
    'Search Pattern Help');
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
  if TSearchType(cbSearchInputType.ItemIndex) = stMask then
  begin
    btnHelp.Visible := True;
    cbSearchText.Width := btnHelp.Left - cbSearchInputType.Left - ToDpi(4, FCurrentPPI);;
  end
  else
  begin
    btnHelp.Visible := False;
    cbSearchText.Width := cbSearchInputType.Width;
  end;
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
    ShowErrorHint(edStartAddr.Handle, DefErrTitle, ErrNotHex);
  end;
end;

procedure TdlgFindData.FillSearchResult(AddrVA: ULONG_PTR);
var
  SearchItem: TSearchItem;
  Index: Integer;
  RegionData: TRegionData;
  NestPfx, DescriptionAtAddr: string;
  KnownTypes: TSymbolDataTypes;
begin
  if not HasSearchResult then
  begin
    if dlgSearchResult = nil then
      dlgSearchResult := TdlgSearchResult.Create(Application);
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
    if SearchItem.RegionFilter = fiImage then
    begin
      DescriptionAtAddr :=
        MemoryMapCore.DebugMapData.GetDescriptionAtAddrWithOffset(ULONG_PTR(AddrVA),
        SearchItem.Details, False);
      if DescriptionAtAddr = '' then
        DescriptionAtAddr := GetAddrDescription(ULONG_PTR(AddrVA), stExport, KnownTypes, True, True);
      if DescriptionAtAddr = '' then
        SearchItem.DebugHint := ''
      else
        SearchItem.DebugHint := Format(' (%s)', [DescriptionAtAddr]);
    end;
  end;
  dlgSearchResult.UpdateSearchList(SearchResults, SearchItem);
end;

procedure TdlgFindData.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  CloseHandle(Process);
  Action := caFree;
end;

procedure TdlgFindData.FormCreate(Sender: TObject);
var
  ProgressHeight: Integer;
begin
  ProgressBar := TFWProgressBar.Create(Self);
  ProgressBar.Parent := pnProgress;
  ProgressHeight := ToDpi(6, FCurrentPPI);
  ProgressBar.SetBounds(0, (pnProgress.Height - ProgressHeight) div 2,
    pnProgress.ClientWidth, ProgressHeight);
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
  btnHelp.Visible := False;
  cbSearchText.Width := cbSearchInputType.Width;
end;

procedure TdlgFindData.FormShow(Sender: TObject);
begin
  cbSearchText.SetFocus;
end;

procedure TdlgFindData.InternalSearchAsMask(Data: PByte; DataSize: NativeInt);
const
  Disp32Size = 4;
var
  Idx, PtCount, I, A, Disp: Integer;
  Matched: Boolean;
  pRemote, pCur: PByte;
  MaxSearchPos: UInt64;
begin
  MaxSearchPos := UInt64(SearchPos);
  for I := 0 to Length(MaskPattern) - 1 do
  begin
    PtCount := Length(MaskPattern[I]);
    pRemote := Data;

    for Idx := 0 to DataSize - PtCount - 1 do
    begin

      if RelPresent then
      begin
        A := 0;
        while A < PtCount do
        begin
          if MaskPattern[I][A].Kind = mkRel32 then
          begin
            Disp := Int32(
              Int64(MaskPattern[I][A].Rel32Target) - Int64(Int64(SearchPos) + Idx + A + Disp32Size));
            MaskPattern[I][A].Value := Byte(Disp);
            MaskPattern[I][A + 1].Value := Byte(Disp shr 8);
            MaskPattern[I][A + 2].Value := Byte(Disp shr 16);
            MaskPattern[I][A + 3].Value := Byte(Disp shr 24);
            Inc(A, 3);
          end;
          Inc(A);
        end;
      end;

      pCur := pRemote;
      Matched := True;
      for A := 0 to PtCount - 1 do
      begin
        case MaskPattern[I][A].Kind of
          mkWild: ;
          mkByte, mkRel32:
          begin
            if pCur^ <> MaskPattern[I][A].Value then
            begin
              Matched := False;
              Break;
            end;
          end;
          mkNibble:
          begin
            if pCur^ and MaskPattern[I][A].NibbleMask <> MaskPattern[I][A].Value then
            begin
              Matched := False;
              Break;
            end;
          end;
        end;
        Inc(pCur);
      end;

      Inc(pRemote);

      if Matched then
      begin
        FillSearchResult(NativeInt(SearchPos) + Idx);
        Inc(SearchCount);
        if SearchCount >= Settings.SearchLimit then
        begin
          MaxSearchPos := Max(MaxSearchPos, NativeUInt(SearchPos) + Cardinal(Idx + PtCount));
          SearchPos := Pointer(MaxSearchPos);
          Exit;
        end;
      end;
    end;
  end;
end;

procedure TdlgFindData.InternalSearchInBuff(Data: Pointer; DataSize: NativeInt);
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

function TdlgFindData.MakeMaskPattern(const AMask: string): Boolean;
const
  Disp32Size = 4;
  WildCard = '?';
  ValidHexChars = ['0'..'9', 'a'..'f', 'A'..'F', WildCard];
var
  Idx, Len, EndBrace, PtCount, TmpVal, PtIdx: Integer;
  Target: UInt64;
  HiWild, LowWild, ValPresent: Boolean;
  NibbleMask: Byte;
begin
  Result := False;
  PtIdx := Length(MaskPattern);
  SetLength(MaskPattern, PtIdx + 1);
  Idx := 1;
  PtCount := 0;
  ValPresent := False;
  Len := Length(AMask);
  while Idx < Len do
  begin

    if AMask[Idx] = ' ' then
    begin
      Inc(Idx);
      Continue;
    end;

    if AMask[Idx] = '{' then
    begin
      EndBrace := PosEx('}', AMask, Idx);
      if EndBrace = 0 then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrWrongMask);
        Exit;
      end;
      if not TryStrToUInt64('$' + Trim(Copy(AMask, Idx + 1, EndBrace - Idx - 1)), Target) then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrWrongMask);
        Exit;
      end;
      SetLength(MaskPattern[PtIdx], PtCount + Disp32Size);
      MaskPattern[PtIdx][PtCount].Kind := mkRel32;
      MaskPattern[PtIdx][PtCount].Rel32Target := Target;
      Inc(PtCount, Disp32Size);
      Idx := EndBrace + 1;
      RelPresent := True;
      Continue;
    end;

    if AMask[Idx] = '[' then
    begin
      EndBrace := PosEx(']', AMask, Idx);
      if EndBrace = 0 then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrWrongMask);
        Exit;
      end;
      if not TryStrToUInt64('$' + Trim(Copy(AMask, Idx + 1, EndBrace - Idx - 1)), Target) then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrWrongMask);
        Exit;
      end;
      SetLength(MaskPattern[PtIdx], PtCount + Disp32Size);
      MaskPattern[PtIdx][PtCount].Value := Byte(Target);
      MaskPattern[PtIdx][PtCount + 1].Value := Byte(Target shr 8);
      MaskPattern[PtIdx][PtCount + 2].Value := Byte(Target shr 16);
      MaskPattern[PtIdx][PtCount + 3].Value := Byte(Target shr 24);
      Inc(PtCount, Disp32Size);
      Idx := EndBrace + 1;
      Continue;
    end;

    if not (CharInSet(AMask[Idx], ValidHexChars) and CharInSet(AMask[Idx + 1], ValidHexChars)) then
    begin
      ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrWrongMask);
      Exit;
    end;

    HiWild := AMask[Idx] = WildCard;
    LowWild := AMask[Idx + 1] = WildCard;

    if LowWild and HiWild then
    begin
      SetLength(MaskPattern[PtIdx], PtCount + 1);
      MaskPattern[PtIdx][PtCount].Kind := mkWild;
      Inc(PtCount);
      Inc(Idx, 2);
      Continue;
    end;

    if LowWild or HiWild then
    begin
      if LowWild then
      begin
        NibbleMask := $F0;
        if not TryStrToInt('$' + AMask[Idx] + '0', TmpVal) then
        begin
          ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrWrongMask);
          Exit;
        end;
      end
      else
      begin
        NibbleMask := $0F;
        if not TryStrToInt('$' + '0' + AMask[Idx + 1], TmpVal) then
        begin
          ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrWrongMask);
          Exit;
        end;
      end;
      SetLength(MaskPattern[PtIdx], PtCount + 1);
      MaskPattern[PtIdx][PtCount].Kind := mkNibble;
      MaskPattern[PtIdx][PtCount].Value := Byte(TmpVal);
      MaskPattern[PtIdx][PtCount].NibbleMask := NibbleMask;
      ValPresent := True;
      Inc(PtCount);
      Inc(Idx, 2);
      Continue;
    end;

    if not TryStrToInt('$' + AMask[Idx] + AMask[Idx + 1], TmpVal) then
    begin
      ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrWrongMask);
      Exit;
    end;
    SetLength(MaskPattern[PtIdx], PtCount + 1);
    MaskPattern[PtIdx][PtCount].Value := Byte(TmpVal);
    ValPresent := True;
    Inc(PtCount);
    Inc(Idx, 2);

  end;

  Result := (PtCount > 0) and (RelPresent or ValPresent);
  if not Result then
    ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrNoData);
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
  if TSearchType(cbSearchInputType.ItemIndex) in [stBuff, stHex8..stHex64, stReference] then
  begin
    UnicodeBuff := StringReplace(cbSearchText.Text, ' ', '', [rfReplaceAll]);
    UnicodeBuff := StringReplace(UnicodeBuff, '$', '', [rfReplaceAll]);
    UnicodeBuff := StringReplace(UnicodeBuff, '0x', '', [rfReplaceAll]);
    if UnicodeBuff = '' then Exit;
  end;
  SetLength(MaskPattern, 0);
  RelPresent := False;
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
          ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrNotHex);
          Exit;
        end;
      end;
      if LoPartPresent then
        SearchBuff[ByteCount] := ByteValue;
      SetLength(SearchBuff, ByteCount);
    end;
    stHex8..stHex64:
    begin
      if not TryStrToUInt64('$' + UnicodeBuff, UIntBuf) then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrNotHex);
        Exit;
      end;
    end;
    stInt8..stInt64:
    begin
      if not TryStrToInt64(cbSearchText.Text, IntBuf) then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrNotNumber);
        Exit;
      end;
    end;
    stUInt8..stUInt64:
    begin
      if not TryStrToUInt64(cbSearchText.Text, UIntBuf) then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrNotNumber);
        Exit;
      end;
    end;
    stFloat32:
    begin
      UnicodeBuff := StringReplace(cbSearchText.Text, ',', FormatSettings.DecimalSeparator, [rfReplaceAll]);
      UnicodeBuff := StringReplace(UnicodeBuff, '.', FormatSettings.DecimalSeparator, [rfReplaceAll]);
      if not TryStrToFloat(UnicodeBuff, SingleBuff) then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrNotFloat);
        Exit;
      end;
    end;
    stFloat64:
    begin
      UnicodeBuff := StringReplace(cbSearchText.Text, ',', FormatSettings.DecimalSeparator, [rfReplaceAll]);
      UnicodeBuff := StringReplace(UnicodeBuff, '.', FormatSettings.DecimalSeparator, [rfReplaceAll]);
      if not TryStrToFloat(UnicodeBuff, DoubleBuff) then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrNotFloat);
        Exit;
      end;
    end;
    stReference:
    begin
      if not TryStrToUInt64('$' + UnicodeBuff, UIntBuf) then
      begin
        ShowErrorHint(TComboBoxAccess(cbSearchText).EditHandle, DefErrTitle, ErrNotHex);
        Exit;
      end;
      // CALL rel32
      MakeMaskPattern(Format('E8{%X}', [UIntBuf]));
      // JMP rel32
      MakeMaskPattern(Format('E9{%X}', [UIntBuf]));
      // PUSH imm32
      MakeMaskPattern(Format('68[%X]', [UIntBuf]));
      // LEA reg64, [RIP+rel32]
      MakeMaskPattern(Format('4?8D?5{%X}', [UIntBuf]));
      // MOV reg, imm32
      MakeMaskPattern(Format('B?[%X]', [UIntBuf]));
      // MOV [mem], imm32
      MakeMaskPattern(Format('C7??[%X]', [UIntBuf]));
      // MOV [mem+disp8], imm32
      MakeMaskPattern(Format('C7????[%X]', [UIntBuf]));
      // Jcc long 32-bit
      MakeMaskPattern(Format('0F8?{%X}', [UIntBuf]));
      // CALL [RIP+rel32]
      MakeMaskPattern(Format('FF15{%X}', [UIntBuf]));
      // JMP [RIP+rel32]
      MakeMaskPattern(Format('FF25{%X}', [UIntBuf]));
      // MOV eax, [addr32]
      MakeMaskPattern(Format('A1[%X]', [UIntBuf]));
      // MOV [addr32], eax
      MakeMaskPattern(Format('A3[%X]', [UIntBuf]));
      // MOV reg, [RIP+rel32]
      MakeMaskPattern(Format('4?8B??{%X}', [UIntBuf]));
      // MOV [RIP+rel32], reg
      MakeMaskPattern(Format('4?89??{%X}', [UIntBuf]));
      // MOV [RIP+rel32], imm32
      MakeMaskPattern(Format('4?C7??{%X}', [UIntBuf]));
      // MOV r32, [addr32] - любой регистр
      MakeMaskPattern(Format('8B?5[%X]', [UIntBuf]));
      // MOV [addr32], r32
      MakeMaskPattern(Format('89?5[%X]', [UIntBuf]));
      Exit(True);
    end;
    stMask:
    begin
      SearchCount := 0;
      Exit(MakeMaskPattern(Trim(cbSearchText.Text)));
    end;
  end;

  case TSearchType(cbSearchInputType.ItemIndex) of
    stHex8, stInt8, stUInt8: SetLength(SearchBuff, 1);
    stHex16, stInt16, stUInt16: SetLength(SearchBuff, 2);
    stHex32, stInt32, stUInt32, stFloat32: SetLength(SearchBuff, 4);
    stHex64, stInt64, stUInt64, stFloat64, stReference: SetLength(SearchBuff, 8);
  end;

  case TSearchType(cbSearchInputType.ItemIndex) of
    stHex8..stHex64, stUInt8..stUInt64, stReference: Move(UIntBuf, SearchBuff[0], Length(SearchBuff));
    stInt8..stInt64: Move(IntBuf, SearchBuff[0], Length(SearchBuff));
    stFloat32: Move(SingleBuff, SearchBuff[0], Length(SearchBuff));
    stFloat64: Move(DoubleBuff, SearchBuff[0], Length(SearchBuff));
  end;

  SearchCount := 0;
  Result := Length(SearchBuff) > 0;
end;

procedure TdlgFindData.Search(Data: Pointer; DataSize: NativeInt);
begin
  case TSearchType(cbSearchInputType.ItemIndex) of
    stReference, stMask:
      InternalSearchAsMask(Data, DataSize);
  else
    InternalSearchInBuff(Data, DataSize);
  end;
end;

procedure TdlgFindData.SearchAtSearchPos;
var
  PreviosPos: Integer;

  procedure IncSearchPos(Value: NativeUInt);
  var
    NewPos: Integer;
  begin
    SearchPos := Pointer(NativeUInt(SearchPos) + Value);
    NewPos := NativeInt(SearchPos) div ProgressDelta;
    if NewPos <> PreviosPos then
    begin
      ProgressBar.Position := NewPos;
      PreviosPos := NewPos;
      ProgressBar.Repaint;
    end;
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
    PreviosPos := 0;
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
  if Assigned(dlgSearchResult) then
    dlgSearchResult.Show;
end;

initialization

  PreviousSearches := TStringList.Create;

finalization

  PreviousSearches.Free;

end.
