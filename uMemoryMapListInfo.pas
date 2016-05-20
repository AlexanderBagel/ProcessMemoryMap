////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uMemoryMapListInfo.pas
//  * Purpose   : Сканирование памяти процесса на основе адресов и контрольных сумм
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2016.
//  * Version   : 1.0
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uMemoryMapListInfo;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls,
  Generics.Collections, PsAPI,

  uUtils,
  MemoryMap.Core,
  MemoryMap.Utils,
  MemoryMap.WorkSet,
  MemoryMap.Symbols,
  uDumpDisplayUtils;

type
  TScanSettings = record
    MMLFile: string;
    ShowDump: Boolean;
    DumpSize: Integer;
    ShowDisasm: Boolean;
    NeedGenerateMML: Boolean;
    NeedSave: Boolean;
    SavePath: string;
    DumpFullRegIfNotShared: Boolean;
    DumpFullRegIfWrongCRC: Boolean;
  end;

  TMMLRecord = record
    Comment: string;
    Addr: Pointer;
    CRC: DWORD;
  end;

  TdlgMemoryMapListInfo = class(TForm)
    edReport: TRichEdit;
  private
    ScanSettings: TScanSettings;
    MMLData: TList<TMMLRecord>;
    Process: THandle;
    Workset: TWorkset;
    DumpList: TStringList;
    Symbols: TSymbols;
    NotSharedCount, WrongCRCCount, DumpFailed: Integer;
    procedure LoadMMLData;
    function ReadMMLRecord(Data: TStringList; Index: Integer): Integer;
    procedure SaveMMLData;
    procedure Scan;
    procedure ProcessMMLRecord(Index: Integer);
    procedure SaveReport;
    procedure SaveDump(Addr: ULONG_PTR; RawBuff: TMemoryDump);
  public
    procedure ShowMemoryMapInfo;
  end;

var
  dlgMemoryMapListInfo: TdlgMemoryMapListInfo;

implementation

uses
  FWZipWriter,
  uSettings,
  uDisplayUtils,
  uMemoryMapListInfoSettings,
  uProgress;

{$R *.dfm}

{ TdlgMemoryMapListInfo }

procedure TdlgMemoryMapListInfo.LoadMMLData;
var
  S: TStringList;
  I: Integer;
begin
  S := TStringList.Create;
  try
    S.LoadFromFile(ScanSettings.MMLFile);
    I := 0;
    while I < S.Count - 1 do
      I := ReadMMLRecord(S, I);
  finally
    S.Free;
  end;
end;

procedure TdlgMemoryMapListInfo.ProcessMMLRecord(Index: Integer);

  procedure Add(const Value: string);
  begin
    edReport.Lines.Add(Value);
  end;

var
  MMLRecord: TMMLRecord;
  MBI: TMemoryBasicInformation;
  dwLength, CRC: DWORD;
  Shared, DumpSaved: Boolean;
  SharedCount: Byte;
  RawBuff: TMemoryDump;
  Size, RegionSize: NativeUInt;
  OwnerName: array [0..MAX_PATH - 1] of Char;
  Path: string;
begin
  MMLRecord := MMLData[Index];
  dlgProgress.ProgressBar.Position := Index + 1;
  dlgProgress.lblProgress.Caption :=
    'Process address: ' + IntToHex(UINT_PTR(MMLRecord.Addr), 1);
  Application.ProcessMessages;

  Add(EmptyHeader);
  Add(dlgProgress.lblProgress.Caption);
  Add(EmptyHeader);
  Add('');

  Add(MMLRecord.Comment);

  dwLength := SizeOf(TMemoryBasicInformation);
  if VirtualQueryEx(Process,
     Pointer(MMLRecord.Addr), MBI, dwLength) <> dwLength then
     RaiseLastOSError;
  Add('AllocationBase: ' + UInt64ToStr(ULONG_PTR(MBI.AllocationBase)));
  Add('RegionSize: ' + SizeToStr(MBI.RegionSize));
  Add('Type: ' + ExtractRegionTypeString(MBI));
  Add('Access: ' + ExtractAccessString(MBI.Protect));
  Add('Initail Access: ' + ExtractInitialAccessString(MBI.AllocationProtect));
  Workset.GetPageSharedInfo(Pointer(ULONG_PTR(MMLRecord.Addr) and
   {$IFDEF WIN32}$FFFFF000{$ELSE}$FFFFFFFFFFFFF000{$ENDIF}), Shared, SharedCount);
  Add('Shared: ' + BoolToStr(Shared, True));
  Add('Shared count: ' + IntToStr(SharedCount));

  Size := 4096;
  SetLength(RawBuff, Size);
  if not ReadProcessData(Process, MMLRecord.Addr, @RawBuff[0],
    Size, RegionSize, rcReadAllwais) then
  begin
    Inc(DumpFailed);
    Add('Dump failed.');
    Exit;
  end;
  SetLength(RawBuff, Size);

  DumpSaved := False;
  if not Shared or (SharedCount = 0) then
  begin
    Inc(NotSharedCount);
    if ScanSettings.DumpFullRegIfNotShared then
    begin
      Add('Not shared - see dump file.');
      SaveDump(ULONG_PTR(MMLRecord.Addr), RawBuff);
      DumpSaved := True;
    end;
  end;

  CRC := CRC32(RawBuff);

  if (MMLRecord.CRC <> 0) and (CRC <> MMLRecord.CRC) then
  begin
    Inc(WrongCRCCount);
    if ScanSettings.DumpFullRegIfWrongCRC then
    begin
      Add('Wrong CRC - see dump file.');
      if not DumpSaved then
        SaveDump(ULONG_PTR(MMLRecord.Addr), RawBuff);
    end
    else
      Add('Wrong CRC.');
  end;

  if ScanSettings.NeedGenerateMML then
  begin
    MMLRecord.CRC := CRC;
    MMLData[Index] := MMLRecord;
  end;

  if ScanSettings.ShowDump then
    Add(DumpMemoryFromBuff(RawBuff, MMLRecord.Addr, ScanSettings.DumpSize));

  if ScanSettings.ShowDisasm then
  begin
    if GetMappedFileName(Process, MBI.AllocationBase,
      @OwnerName[0], MAX_PATH) > 0 then
    begin
      Path := NormalizePath(string(OwnerName));
      Add(DisassemblyFromBuff(RawBuff, Symbols, MMLRecord.Addr,
        MBI.AllocationBase, Path, MemoryMapCore.Process64, ScanSettings.DumpSize));
    end
    else
      Add(DisassemblyFromBuff(RawBuff, nil, MMLRecord.Addr,
        nil, '', MemoryMapCore.Process64, ScanSettings.DumpSize));
  end;
end;

function TdlgMemoryMapListInfo.ReadMMLRecord(
  Data: TStringList; Index: Integer): Integer;
var
  Line: string;
  MML: TMMLRecord;
  I, Position: Integer;
  Value: Int64;

  function GetValue(S: string; Index: Integer): string;
  begin
    Delete(S, 1, Index);
    Index := Pos(' ', S);
    if Index > 0 then
      Result := Copy(S, 1, Index - 1)
    else
      Result := S;
  end;

begin
  MML.Comment := '';
  MML.Addr := nil;
  MML.CRC := 0;
  Result := Data.Count;
  for I := Index to Data.Count - 1 do
  begin
    Line := Trim(LowerCase(Data[I]));
    Position := Pos('addr: ', Line);
    if Position = 0 then
      MML.Comment := MML.Comment + Data[I] + sLineBreak
    else
    begin
      TryStrToInt64('$' + GetValue(Line, Position + 5), Value);
      if Value > $100000 then
      begin
        MML.Addr := Pointer(Value);
        Position := Pos('crc: ', Line);
        if Position <> 0 then
        begin
          TryStrToInt64('$' + GetValue(Line, Position + 4), Value);
          MML.CRC := DWORD(Value);
        end;
        MMLData.Add(MML);
      end;
      Result := I + 1;
      Break;
    end;
  end;
end;

procedure TdlgMemoryMapListInfo.SaveDump(Addr: ULONG_PTR; RawBuff: TMemoryDump);
var
  Path: string;
  F: TFileStream;
begin
  if not ScanSettings.NeedSave then Exit;
  SetLength(Path, MAX_PATH);
  GetTempPath(MAX_PATH, @Path[1]);
  Path := IncludeTrailingPathDelimiter(PChar(Path)) + IntToHex(ULONG_PTR(Addr), 16) + '.bin';
  F := TFileStream.Create(Path, fmCreate);
  try
    F.WriteBuffer(RawBuff[0], Length(RawBuff));
  finally
    F.Free;
  end;
  DumpList.Add(ExtractFileName(Path) + '=' + Path);
end;

procedure TdlgMemoryMapListInfo.SaveMMLData;
var
  S: TStringList;
  I: Integer;
begin
  S := TStringList.Create;
  try
    for I := 0 to MMLData.Count - 1 do
    begin
      S.Add(MMLData[I].Comment);
      S.Add('addr: ' + IntToHex(DWORD(MMLData[I].Addr), 16) +
            ' crc: ' + IntToHex(MMLData[I].CRC, 8));
    end;
    S.SaveToFile(ChangeFileExt(ScanSettings.MMLFile, '_updated_crc.mml'));
  finally
    S.Free;
  end;
end;

procedure TdlgMemoryMapListInfo.SaveReport;
var
  I: Integer;
  Zip: TFWZipWriter;
  M: TMemoryStream;
begin
  try
    if not ScanSettings.NeedSave then Exit;
    Zip := TFWZipWriter.Create;
    try
      M := TMemoryStream.Create;
      try
        edReport.Lines.SaveToStream(M);
        Zip.AddStream('report.rtf', M);
      finally
        M.Free;
      end;
      Zip.AddFiles(DumpList);
      Zip.BuildZip(ScanSettings.SavePath);
    finally
      Zip.Free;
    end;
  finally
    for I := 0 to DumpList.Count - 1 do
      DeleteFile(DumpList[I]);
  end;
end;

procedure TdlgMemoryMapListInfo.Scan;
var
  ProcessLock: TProcessLockHandleList;
  I: Integer;
  Hint: string;

  procedure UpdateHint(Value: Integer; const HintMsg: string);
  begin
    if Value = 0 then Exit;
    if Hint <> '' then
      Hint := Hint + ', ';
    Hint := Hint + HintMsg + IntToStr(Value);
  end;

begin
  ProcessLock := nil;
  MMLData := TList<TMMLRecord>.Create;
  try
    LoadMMLData;
    if MMLData.Count = 0 then
      raise Exception.Create('Empty MML data file.');
    Process := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ or
      PROCESS_VM_OPERATION, False, MemoryMapCore.PID);
    if Process = 0 then
      RaiseLastOSError;
    try
      if Settings.SuspendProcess then
        ProcessLock := SuspendProcess(MemoryMapCore.PID);
      try
        DumpList := TStringList.Create;
        try
          dlgProgress := TdlgProgress.Create(Self);
          try
            dlgProgress.ProgressBar.Max := MMLData.Count;
            dlgProgress.lblProgress.Caption := 'Workset initialization...';
            dlgProgress.Show;
            Application.ProcessMessages;
            Workset := TWorkset.Create(Process);
            try
              NotSharedCount := 0;
              WrongCRCCount := 0;
              DumpFailed := 0;
              Symbols := TSymbols.Create(Process);
              try
                for I := 0 to MMLData.Count - 1 do
                  ProcessMMLRecord(I);
              finally
                Symbols.Free;
              end;
            finally
              Workset.Free;
            end;
          finally
            dlgProgress.Free;;
          end;
          SaveReport;
        finally
          DumpList.Free;
        end;
      finally
        if Settings.SuspendProcess then
          ResumeProcess(ProcessLock);
      end;
    finally
      CloseHandle(Process);
    end;
    if ScanSettings.NeedGenerateMML then
      SaveMMLData;
  finally
    MMLData.Free;
  end;
  Hint := '';
  UpdateHint(DumpFailed, 'Dump Failed: ');
  UpdateHint(NotSharedCount, 'Not Shared: ');
  UpdateHint(WrongCRCCount, 'Wrong CRC: ');
  if Hint <> '' then
    Caption := Caption + ' [' + Hint + ']';
  ShowModal;
end;

procedure TdlgMemoryMapListInfo.ShowMemoryMapInfo;
begin
  dlgMemoryMapListInfoSettings := TdlgMemoryMapListInfoSettings.Create(Self);
  try
    if dlgMemoryMapListInfoSettings.ShowModal = mrCancel then
    begin
      Close;
      Exit;
    end;
    ScanSettings.MMLFile := dlgMemoryMapListInfoSettings.edMML.Text;
    ScanSettings.ShowDump := dlgMemoryMapListInfoSettings.cbShowMiniDump.Checked;
    if dlgMemoryMapListInfoSettings.cbDumpSize.ItemIndex = 9 then
      ScanSettings.DumpSize := 0
    else
      ScanSettings.DumpSize := 16 shl dlgMemoryMapListInfoSettings.cbDumpSize.ItemIndex;
    ScanSettings.ShowDisasm := dlgMemoryMapListInfoSettings.cbShowDisasm.Checked;
    ScanSettings.NeedGenerateMML := dlgMemoryMapListInfoSettings.cbGenerateMML.Checked;
    ScanSettings.NeedSave := dlgMemoryMapListInfoSettings.cbSave.Checked;
    ScanSettings.SavePath := dlgMemoryMapListInfoSettings.edSave.Text;
    ScanSettings.DumpFullRegIfNotShared := dlgMemoryMapListInfoSettings.cbSaveFullDump.Checked;
    ScanSettings.DumpFullRegIfWrongCRC := dlgMemoryMapListInfoSettings.cbSaveIfWrongCRC.Checked;
  finally
    dlgMemoryMapListInfoSettings.Free;
  end;
  Scan;
end;

end.
