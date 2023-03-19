////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uMemoryMapListInfo.pas
//  * Purpose   : Сканирование памяти процесса на основе адресов и контрольных сумм
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.4.28
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
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.Menus,
  Generics.Collections, PsAPI,

  uUtils,
  MemoryMap.Core,
  MemoryMap.Utils,
  MemoryMap.WorkSet,
  MemoryMap.DebugMapData,
  uDumpDisplayUtils,
  ScaledCtrls;

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
    PopupMenu: TPopupMenu;
    mnuCopy: TMenuItem;
    SelectAll1: TMenuItem;
    SaveMMLDialog: TSaveDialog;
    procedure mnuCopyClick(Sender: TObject);
    procedure SelectAll1Click(Sender: TObject);
  private
    ScanSettings: TScanSettings;
    MMLData: TList<TMMLRecord>;
    Process: THandle;
    Workset: TWorkset;
    DumpList: TStringList;
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
    procedure GenerateMemoryMapInfo;
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


procedure TdlgMemoryMapListInfo.GenerateMemoryMapInfo;

  function IsVclFunction(const FuncName: string): Boolean;
  begin
    Result := FuncName.StartsWith('Winapi.');
    if not Result then
      Result := FuncName.StartsWith('System.');
    if not Result then
      Result := FuncName.StartsWith('Vcl.');
    if not Result then
      Result := FuncName.StartsWith('Generics.');
    if not Result then
      Result := FuncName.StartsWith('SysInit.');
  end;

const
  FuncPrefix = '             // ';
var
  DebugMap: TDebugMap;
  FuncDataList: TDictionary<ULONG_PTR, string>;
  RegionAddr: ULONG_PTR;
  RegionData, MMLPath: string;
  Enumerator: TEnumerator<ULONG_PTR>;
  MML: TStringList;
  ProcessLock: TProcessLockHandleList;
  AddrSize: Integer;
  Size, RegionSize: NativeUInt;
  RawBuff: TMemoryDump;
  CRC: DWORD;
begin
  if MemoryMapCore.Process64 then
    AddrSize := 16
  else
    AddrSize := 8;
  MMLPath := ChangeFileExt(MemoryMapCore.ProcessPath, '.mml');
  DebugMap := MemoryMapCore.DebugMapData;
  FuncDataList := TDictionary<ULONG_PTR, string>.Create;
  try

    // создаем список адресов по 4096 байт куда входит хотябы одна функция
    for var I := 0 to DebugMap.Items.Count - 1 do
    begin
      with DebugMap.Items.List[I] do
      begin
        if IsVclFunction(FunctionName) then
          Continue;
        RegionAddr := Address and not $FFF;
        if not FuncDataList.TryGetValue(RegionAddr, RegionData) then
          RegionData := FuncPrefix + FunctionName
        else
          RegionData := FuncPrefix + FunctionName + sLineBreak + RegionData;
        FuncDataList.AddOrSetValue(RegionAddr, RegionData);
      end;
    end;

    Enumerator := FuncDataList.Keys.GetEnumerator;
    try
      MML := TStringList.Create;
      try

        Process := OpenProcessWithReconnect;
        try
          ProcessLock := nil;
          if Settings.SuspendProcess then
            ProcessLock := SuspendProcess(MemoryMapCore.PID);
          try

            while Enumerator.MoveNext do
            begin

              // рассчитываем контрольную сумму каждого блока
              Size := 4096;
              SetLength(RawBuff, Size);
              if not ReadProcessData(Process, Pointer(Enumerator.Current), @RawBuff[0],
                Size, RegionSize, rcReadAllwais) then
                Continue;
              SetLength(RawBuff, Size);

              CRC := CRC32(RawBuff);

              // помещаем в MML описание блока, какие функции в него входят
              // адрес и контрольную сумму блока
              FuncDataList.TryGetValue(Enumerator.Current, RegionData);
              MML.Add(RegionData);
              MML.Add('addr: ' + IntToHex(Enumerator.Current, AddrSize) +
                ' crc: ' + IntToHex(CRC, 8));
            end;

          finally
            if Assigned(ProcessLock) then
              ResumeProcess(ProcessLock);
          end;
        finally
          CloseHandle(Process);
        end;

        if MML.Count > 0 then
        try
          MML.SaveToFile(MMLPath);
        except
          SaveMMLDialog.InitialDir := ExtractFilePath(MMLPath);
          SaveMMLDialog.FileName := ExtractFileName(MMLPath);
          if SaveMMLDialog.Execute then
          begin
            MMLPath := SaveMMLDialog.FileName;
            MML.SaveToFile(MMLPath);
          end;
        end;

        OpenExplorerAndSelectFile(MMLPath);

      finally
        MML.Free;
      end;
    finally
      Enumerator.Free;
    end;
  finally
    FuncDataList.Free;
  end;

  // если файл сгенерировался успешно то открываем его с настройками по умолчанию
  if FileExists(MMLPath) then
  begin
    ScanSettings.MMLFile := MMLPath;
    ScanSettings.ShowDump := False;
    ScanSettings.DumpSize := 0;
    ScanSettings.ShowDisasm := False;
    ScanSettings.NeedGenerateMML := False;
    ScanSettings.NeedSave := False;
    ScanSettings.SavePath := EmptyStr;
    ScanSettings.DumpFullRegIfNotShared := False;
    ScanSettings.DumpFullRegIfWrongCRC := False;
    Scan;
  end;
end;

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

procedure TdlgMemoryMapListInfo.mnuCopyClick(Sender: TObject);
begin
  edReport.CopyToClipboard;
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
  DumpPresent, Shared, DumpSaved, Dasm64Mode: Boolean;
  SharedCount: Byte;
  RawBuff: TMemoryDump;
  Size, RegionSize: NativeUInt;
begin
  MMLRecord := MMLData[Index];
  dlgProgress.ProgressBar.Position := Index + 1;
  dlgProgress.lblProgress.Caption :=
    'Process address: ' + IntToHex(UINT_PTR(MMLRecord.Addr), 1);
  Application.ProcessMessages;

  CRC := DWORD(-1);
  Shared := False;
  SharedCount := 255;

  Size := 4096;
  SetLength(RawBuff, Size);
  DumpPresent := ReadProcessData(Process, MMLRecord.Addr, @RawBuff[0],
    Size, RegionSize, rcReadAllwais);

  if DumpPresent then
    CRC := CRC32(RawBuff);

  dwLength := SizeOf(TMemoryBasicInformation);
  if VirtualQueryEx(Process,
     Pointer(MMLRecord.Addr), MBI, dwLength) <> dwLength then
     RaiseLastOSError;

  Workset.GetPageSharedInfo(Pointer(ULONG_PTR(MMLRecord.Addr) and
   {$IFDEF WIN32}$FFFFF000{$ELSE}$FFFFFFFFFFFFF000{$ENDIF}), Shared, SharedCount);

  if ScanSettings.NeedGenerateMML then
  begin
    MMLRecord.CRC := CRC;
    MMLData[Index] := MMLRecord;
  end;

  if DumpPresent and Shared and (SharedCount > 0) and
    ((MMLRecord.CRC <> 0) and (CRC = MMLRecord.CRC)) then
    Exit;

  Add(EmptyHeader);
  Add(dlgProgress.lblProgress.Caption);
  Add(EmptyHeader);
  Add('');

  Add(MMLRecord.Comment);

  Add('AllocationBase: ' + UInt64ToStr(ULONG_PTR(MBI.AllocationBase)));
  Add('RegionSize: ' + SizeToStr(MBI.RegionSize));
  Add('Type: ' + ExtractRegionTypeString(MBI));
  Add('Access: ' + ExtractAccessString(MBI.Protect));
  Add('Initail Access: ' + ExtractInitialAccessString(MBI.AllocationProtect));
  Add('Shared: ' + BoolToStr(Shared, True));
  Add('Shared count: ' + IntToStr(SharedCount));

  if not DumpPresent then
  begin
    Inc(DumpFailed);
    Add('Dump failed.');
    Exit;
  end;

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

  if ScanSettings.ShowDump then
    Add(DumpMemoryFromBuff(Process, MMLRecord.Addr, RawBuff, ScanSettings.DumpSize));

  if ScanSettings.ShowDisasm then
  begin
    if not CheckPEImage(Process, MBI.AllocationBase, Dasm64Mode) then
      Dasm64Mode := MemoryMapCore.Process64;
    Add(DisassemblyFromBuff(Process, RawBuff, MMLRecord.Addr,
      MBI.AllocationBase, Dasm64Mode, ScanSettings.DumpSize));
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
    if edReport.Lines.Count > 0 then
    begin
      edReport.Lines.Add('');
      edReport.Lines.Add(EmptyHeader);
    end
    else
      edReport.Lines.Add('All clear.');
    edReport.Lines.Add('');
    edReport.Lines.Add('Done.');
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
    Process := OpenProcessWithReconnect;
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
              for I := 0 to MMLData.Count - 1 do
                ProcessMMLRecord(I);
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

procedure TdlgMemoryMapListInfo.SelectAll1Click(Sender: TObject);
begin
  edReport.SelectAll;
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
