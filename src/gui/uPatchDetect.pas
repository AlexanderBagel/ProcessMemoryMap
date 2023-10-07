////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uPatchDetect.pas
//  * Purpose   : Диалог для работы со сканером перехваченых функций
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.4.30
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uPatchDetect;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.Menus, Vcl.StdCtrls, Vcl.ComCtrls,

  Math,
  Generics.Collections,

  MemoryMap.Core,

  RawScanner.Core,
  RawScanner.Types,
  RawScanner.Logger,
  RawScanner.Disassembler,
  RawScanner.Analyzer,
  RawScanner.Filter,
  RawScanner.ModulesData,
  RawScanner.Utils,

  ScaledCtrls,
  uBaseForm;

type
  TCalculateHookData = record
    ProcessHandle: THandle;
    AddrVA, ImageBase,
    LimitMin, LimitMax: ULONG_PTR64;
    Is64Code: Boolean;
    LibraryFuncName, HookHandlerModule: string;
    HookType: THookType;
    DumpStrings: TStringList;
  end;

  TdlgPatches = class(TBaseAppForm)
    edLog: TRichEdit;
    mnuPopup: TPopupMenu;
    mnuGotoAddress: TMenuItem;
    N3: TMenuItem;
    mnuCopy: TMenuItem;
    N1: TMenuItem;
    mnuRefresh: TMenuItem;
    SelectAll1: TMenuItem;
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure FormKeyPress(Sender: TObject; var Key: Char);
    procedure FormShow(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure mnuPopupPopup(Sender: TObject);
    procedure mnuCopyClick(Sender: TObject);
    procedure mnuGotoAddressClick(Sender: TObject);
    procedure SelectAll1Click(Sender: TObject);
  private
    FCodeError, FImportError, FDelayedImportError, FExportError: Integer;
    FFilter: TFilter;
    // обработчики событий анализатора
    procedure ProcessCodeHook(const Data: TCodeHookData);
    procedure ProcessTableHook(const Data: THookData);
    // и глобального логера
    procedure OnLog(ALevel: TLogLevel; AType: TLogType;
      const FuncName, Description: string);
  private
    // вспомогательные функции
    function CheckHookHandler(var chd: TCalculateHookData): Boolean;
    function DumpExternalAddr(chd: TCalculateHookData): Boolean;
    function InitCalculateHookData: TCalculateHookData; overload;
    function InitCalculateHookData(const Data: THookData): TCalculateHookData; overload;
    function InitCalculateHookData(const CodeData: TCodeHookData): TCalculateHookData; overload;
    function GetHintString(var chd: TCalculateHookData;
      Inst: TInstruction; var ShortJmp: Boolean): string;
    procedure ReleaseCalculateHookData(const Value: TCalculateHookData);
  private
    // форматирование
    FLastIsEmptyLine: Boolean;
    procedure AddTableHeader(RawOffset: DWORD; chd: TCalculateHookData);
    procedure Add(const Value: string;
      AColor: TColor = clDefault); overload;
    procedure Add(const Caption, Description: string;
      AColor: TColor = clDefault); overload;
    procedure EmptyLine;
    procedure ShowModuleInfo(Index: Integer; Module: TRawPEImage);
  protected
    SelectedAddr: ULONG_PTR;
  public
    procedure FindPatches;
  end;

var
  dlgPatches: TdlgPatches;

implementation

uses
  uProgress,
  uSettings,
  uRegionProperties,
  uUtils;

const
  Separator = '|';
  HexPfx = '0x';
  PatchedPfx = '. Status: PATCHED!';
  ModifiedPfx = '. Status: Modified. Probably wrong detect.';
  ExpectedPfx = 'Expected: ';
  PresentPfx = ', present: ';
  AddrPfx = ', at address: ';
  ValidColor = $96542F;
  InvalidColor = clRed;
  WarningColor = $007CD8;
  DefaultBuffSize = 64;

{$R *.dfm}

procedure TdlgPatches.Add(const Value: string; AColor: TColor);
begin
  FLastIsEmptyLine := False;
  edLog.Lines.Add(Value);
end;

procedure TdlgPatches.Add(const Caption, Description: string; AColor: TColor);
begin
  Add(Caption + Description, AColor);
end;

procedure TdlgPatches.AddTableHeader(RawOffset: DWORD; chd: TCalculateHookData);
var
  Line, HexStr: string;
begin
  HexStr := HexPfx + IntToHex(RawOffset, 0);
  Line := 'Addr:' + StringOfChar(Space, 11) + '|Raw (' +
    HexPfx + IntToHex(RawOffset, 0) + '):';
  Line := Line +
    StringOfChar(Space, 51 - Length(HexStr)) +
    '|Remote:';
  chd.DumpStrings.Add(Line);
  chd.DumpStrings.Add(StringOfChar('-', 124));
end;

function TdlgPatches.CheckHookHandler(var chd: TCalculateHookData): Boolean;
var
  FilterStatus: TFilterStatus;
begin
  if not Settings.UseScannerFilter then Exit(False);
  if chd.HookHandlerModule.IsEmpty then Exit(False);
  FilterStatus :=
    FFilter.Check(chd.HookHandlerModule, chd.LibraryFuncName, chd.HookType);
  Result := FilterStatus <> fsNone;
end;

function TdlgPatches.DumpExternalAddr(chd: TCalculateHookData): Boolean;
var
  Buff: array of Byte;
  Disasm: TDisassembler;
  Inst: TInstructionArray;
  I: Integer;
  HintString: string;
  AddHeader, ShortJmp: Boolean;
begin
  Result := False;
  SetLength(Buff, DefaultBuffSize);
  if not ReadRemoteMemory(chd.ProcessHandle, chd.AddrVA,
    @Buff[0], DefaultBuffSize) then
    Exit;

  Disasm := TDisassembler.Create(chd.ProcessHandle, chd.AddrVA,
    DefaultBuffSize, chd.Is64Code);
  try
    Inst := Disasm.DecodeBuff(@Buff[0], dmUntilUndefined);
    if Length(Inst) = 0 then Exit;
  finally
    Disasm.Free;
  end;

  AddHeader := True;
  for I := 0 to Min(8, Length(Inst) - 1) do
  begin
    if (Inst[I].AddrVa >= chd.LimitMin) and
      (Inst[I].AddrVa <= chd.LimitMax) then Break;
    if Inst[I].JmpAddrVa <> 0 then
    begin
      HintString := GetHintString(chd, Inst[I], ShortJmp);
      Result := CheckHookHandler(chd);
      if Result then
        Break;
    end
    else
      HintString := EmptyStr;
    if AddHeader then
    begin
      chd.DumpStrings.Add(StringOfChar('-', 124));
      chd.DumpStrings.Add('External jump disassembly: ');
      AddHeader := False;
    end;
    chd.DumpStrings.Add('  ' + IntToHex(Inst[I].AddrVa, 16) + ': ' +
      Inst[I].DecodedString + Space + HintString);
  end;
end;

procedure TdlgPatches.EmptyLine;
begin
  if FLastIsEmptyLine then Exit;
  Add(EmptyStr);
  FLastIsEmptyLine := True;
end;

procedure TdlgPatches.FindPatches;
begin
  Show;
end;

procedure TdlgPatches.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  Action := caFree;
  dlgPatches := nil;
end;

procedure TdlgPatches.FormCreate(Sender: TObject);
begin
  FFilter := TFilter.Create;
end;

procedure TdlgPatches.FormDestroy(Sender: TObject);
begin
  FFilter.Free;
end;

procedure TdlgPatches.FormKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #27 then Close;
end;

function MakeAnalizedStr(const Value: string;
  const Item: TAnalizedItem): string;
begin
  Result := Format('Total %s scanned: %d', [Value, Item.Scanned]);
  if Item.Skipped > 0 then
    Result := Result + ', skipped: ' + IntToStr(Item.Skipped);
end;

procedure TdlgPatches.FormShow(Sender: TObject);
var
  ir: TInitializationResult;
  ar: TAnalizeResult;
  ActualState: Boolean;
begin
  RawScannerLogger.OnLog := OnLog;
  try
    dlgProgress := TdlgProgress.Create(nil);
    try
      dlgProgress.lblProgress.Caption := 'Initialization...';
      dlgProgress.ShowWithCallback(procedure()
      begin
        edLog.Lines.BeginUpdate;
        try
          edLog.Lines.Clear;
          Add('Initialization...');

          FImportError := 0;
          FExportError := 0;
          FCodeError := 0;

          ActualState := RawScannerCore.IsActualState;
          case Settings.ScannerMode of
            smNoUpdate: Add('Actual State: ' + BoolToStr(ActualState, True));
            smDefault:
            begin
              if ActualState then
                Add('Actual State: True')
              else
              begin
                Add('Actual State: False - Updated');
                RawScannerCore.InitFromProcess(MemoryMapCore.PID);
              end;
            end;
            smForceUpdate:
            begin
              Add('Actual State: Force Updated');
              RawScannerCore.InitFromProcess(MemoryMapCore.PID);
            end;
          end;

          ir := RawScannerCore.InitializationResult;

          EmptyLine;
          Add(Format('ApiSet version: %d', [ir.ApiSetVer]));
          if ir.ApiSetCount > 0 then
            Add(Format('ApiSet count: %d', [ir.ApiSetCount]));
          if ir.Loader32 + ir.Loader64 = 0 then
            Add('No loader data!!!', InvalidColor)
          else
          begin
            if ir.Loader32 > 0 then
              Add(Format('Loader32 modules count: %d', [ir.Loader32]));
            if ir.Loader64 > 0 then
              Add(Format('Loader64 modules count: %d', [ir.Loader64]));
          end;
          EmptyLine;

          var I := 0;
          for var M in RawScannerCore.Modules.Items do
          begin
            ShowModuleInfo(I, M);
            Inc(I);
          end;

          EmptyLine;
          Add('Analize...');
          EmptyLine;

          RawScannerCore.Analizer.OnProgress := RawScannerCore.OnProgress;
          ar := RawScannerCore.Analizer.Analyze(ProcessTableHook, ProcessCodeHook);

          EmptyLine;
          Add('Done');

          EmptyLine;
          Add(MakeAnalizedStr('modules', ar.Modules));
          Add(MakeAnalizedStr('import', ar.Import));
          Add(MakeAnalizedStr('export', ar.Export));
          Add(MakeAnalizedStr('code', ar.Code));

          EmptyLine;

          if FImportError > 0 then
            Add(Format('Total import hook: %d', [FImportError]));
          if FDelayedImportError > 0 then
            Add(Format('Total delayed import hook: %d', [FDelayedImportError]));
          if FExportError > 0 then
            Add(Format('Total export hook: %d', [FExportError]));
          if FCodeError > 0 then
            Add(Format('Total code hook: %d', [FCodeError]));

        finally
          edLog.Lines.EndUpdate;
        end;
      end);
    finally
      FreeAndNil(dlgProgress);
    end;
  finally
    RawScannerLogger.OnLog := nil;
  end;
end;

function TdlgPatches.GetHintString(var chd: TCalculateHookData;
  Inst: TInstruction; var ShortJmp: Boolean): string;
var
  MBI: TMemoryBasicInformation64;
  dwLength: NativeUInt;
  HexAddr: string;
begin
  chd.HookHandlerModule := EmptyStr;
  HexAddr := IntToHex(Inst.JmpAddrVa, 2);
  if Pos(HexAddr, Inst.DecodedString) = 0 then
    Result := '(0x' + HexAddr + ') '
  else
    Result := EmptyStr;

  dwLength := SizeOf(TMemoryBasicInformation64);
  if VirtualQueryEx64(chd.ProcessHandle,
    Inst.JmpAddrVa, MBI, dwLength) <> dwLength then
    Exit;

  chd.HookHandlerModule := GetMappedModule(chd.ProcessHandle, MBI.AllocationBase);
  if not chd.HookHandlerModule.IsEmpty then
    Result := ' --> ' + Result + chd.HookHandlerModule;

  ShortJmp := chd.ImageBase = ULONG64(MBI.AllocationBase);
end;

function TdlgPatches.InitCalculateHookData: TCalculateHookData;
begin
  ZeroMemory(@Result, SizeOf(TCalculateHookData));
  Result.DumpStrings := TStringList.Create;
end;

function TdlgPatches.InitCalculateHookData(
  const Data: THookData): TCalculateHookData;
begin
  Result := InitCalculateHookData;
  Result.ProcessHandle := Data.ProcessHandle;
  Result.AddrVA := Data.AddrVA;
  Result.ImageBase := Data.ImageBase;
  Result.Is64Code := Data.Image64;
  Result.HookType := Data.HookType;
  Result.LibraryFuncName := Data.FuncName;
end;

function TdlgPatches.InitCalculateHookData(
  const CodeData: TCodeHookData): TCalculateHookData;
begin
  Result := InitCalculateHookData;
  Result.ProcessHandle := CodeData.ProcessHandle;
  Result.AddrVA := CodeData.AddrVA;
  Result.ImageBase := CodeData.ImageBase;
  Result.Is64Code := CodeData.Image64;
  Result.HookType := htCode;
  Result.LibraryFuncName := CodeData.ExportFunc;
end;

procedure TdlgPatches.mnuCopyClick(Sender: TObject);
begin
  edLog.CopyToClipboard;
end;

procedure TdlgPatches.mnuGotoAddressClick(Sender: TObject);
begin
  if SelectedAddr <> 0 then
  begin
    dlgRegionProps := TdlgRegionProps.Create(Application);
    dlgRegionProps.ShowPropertyAtAddr(Pointer(SelectedAddr), True);
  end;
end;

procedure TdlgPatches.mnuPopupPopup(Sender: TObject);
var
  HexAddr: Int64;
begin
  SelectedAddr := 0;
  if HexValueToInt64(edLog.SelText, HexAddr) then
    SelectedAddr := ULONG_PTR(HexAddr);
  mnuGotoAddress.Enabled := SelectedAddr <> 0;
end;

procedure TdlgPatches.OnLog(ALevel: TLogLevel; AType: TLogType; const FuncName,
  Description: string);

  function LogStr: string;
  begin
    if FuncName = EmptyStr then
      Result := Description
    else
      Result := FuncName + ': ' + Description;
  end;

begin
  if ALevel = llContext then Exit; // контекст пока не закончен
  if ALevel = llApiSet then Exit; // данные по аписету не нужны
  if (ALevel = llAnalizer) and (AType = ltNotify) then Exit;
  if AType <> ltNotify then
    EmptyLine;
  case AType of
    ltNotify:   Add(LogStr);
    ltInfo:     Add('[.]        ', LogStr);
    ltWarning:  Add('[+] WARN:  ', LogStr, WarningColor);
    ltError:    Add('[-] ERR:   ', LogStr, InvalidColor);
    ltFatal:    Add('[-] FATAL: ', LogStr, InvalidColor);
  end;
  if AType <> ltNotify then
    EmptyLine;
end;

procedure TdlgPatches.ProcessCodeHook(const Data: TCodeHookData);

  function GetOutString(Inst: TInstruction): string;
  var
    I: Integer;
  begin
    Result := EmptyStr;
    for I := 0 to Inst.OpcodesLen - 1 do
      Result := Result + IntToHex(Inst.Opcodes[I], 2) + Space;
    Result := Result + StringOfChar(Space, 28 - Length(Result));
    Result := Result + Inst.DecodedString +
      StringOfChar(Space, 30 - Length(Inst.DecodedString));
  end;

  function ByteToHexStr(Value: PByte; BuffSize: Integer): string;
  begin
    Result := EmptyStr;
    for var I := 0 to BuffSize - 1 do
    begin
      Result := Result + IntToHex(Value^, 2) + Space;
      Inc(Value);
    end;
  end;

const
  ExpModified = 'Export modified';

type
  TByteArray = array of Byte;

var
  Disasm: TDisassembler;
  RawDecodedInst, RemoteDecodedInst: TInstructionArray;
  I, RawCount, RemoteCount, RawIndex, RemoteIndex: Integer;
  Modified, ShortJmp: Boolean;
  Cursor, MaxAddr: ULONG_PTR64;
  Pfx, RawOut, RemoteOut, HintString: string;
  ExternalJmps: TList<ULONG_PTR64>;
  chd: TCalculateHookData;
begin
  Disasm := TDisassembler.Create(
    Data.ProcessHandle, Data.AddrVA, Data.BufSize, Data.Image64);
  try

    RawDecodedInst := Disasm.DecodeBuff(Data.Raw, dmUntilUndefined);
    RawCount := Length(RawDecodedInst);

    RemoteDecodedInst := Disasm.DecodeBuff(Data.Remote, dmUntilRet);
    RemoteCount := Length(RemoteDecodedInst);
  finally
    Disasm.Free;
  end;

  // если не смогли дизассемблировать один из буферов (или оба) выводим как есть
  if (RawCount = 0) or (RemoteCount = 0) then
  begin
    Inc(FCodeError);
    var Log: string := Data.ExportFunc + AddrPfx + IntToHex(Data.AddrVA);
    if Data.Patched then
    begin
      Log := Log + PatchedPfx;
      RawScannerLogger.Warn(llAnalizer, ExpModified, Log);
    end
    else
    begin
      Log := Log + ModifiedPfx;
      RawScannerLogger.Warn(llAnalizer, ExpModified, Log);
    end;
    RawScannerLogger.Info(llAnalizer,
      ExpectedPfx + ByteToHexStr(Data.Raw, Data.BufSize));
    RawScannerLogger.Info(llAnalizer,
      'Present:  ' + ByteToHexStr(Data.Remote, Data.BufSize));
    Exit;
  end;

  // исключаем все лишнее что не отностся к патченым данным

  // 1. определяем минимальный размер дизассемблированого блока
  MaxAddr := RawDecodedInst[RawCount - 1].AddrVa +
    RawDecodedInst[RawCount - 1].OpcodesLen;
  MaxAddr := Min(MaxAddr, RemoteDecodedInst[RemoteCount - 1].AddrVa +
    RemoteDecodedInst[RemoteCount - 1].OpcodesLen);
  Dec(MaxAddr, Data.AddrVA);

  // 2. находим с какой позиции пошли расхождения
  for I := MaxAddr - 1 downto 0 do
  begin
    if TByteArray(Data.Raw)[I] <> TByteArray(Data.Remote)[I] then
    begin
      MaxAddr := Data.AddrVA + Cardinal(I);
      Break;
    end;
  end;

  // 3. если расхождений не обнаружилось - восстанавливаем максимальный адрес
  if MaxAddr <= DefaultBuffSize then
    Inc(MaxAddr, Data.AddrVA - 1);

  // 4. убираем все лишние блоки который выходят за максимальный адрес
  while (RemoteCount > 0) and (RemoteDecodedInst[RemoteCount - 1].AddrVa > MaxAddr) do
    Dec(RemoteCount);
  while (RawCount > 0) and (RawDecodedInst[RawCount - 1].AddrVa > MaxAddr) do
    Dec(RawCount);

  // теперь идет проверка совпадают ли декодированиые буферы?
  Modified := RawCount <> RemoteCount;
  if not Modified then
    for I := 0 to RawCount - 1 do
      if (RawDecodedInst[I].OpcodesLen <> RemoteDecodedInst[I].OpcodesLen) or
        not CompareMem(
          @RawDecodedInst[I].Opcodes[0],
          @RemoteDecodedInst[I].Opcodes[0],
          RawDecodedInst[I].OpcodesLen) then
      begin
        Modified := True;
        Break;
      end;

  if not Modified then Exit;

  // если не совпали, нужно определить - подпадает ли под фильтр?
  chd := InitCalculateHookData(Data);
  try
    Cursor := Data.AddrVA;
    RawIndex := 0;
    RemoteIndex := 0;

    Pfx := 'Code modified ' + Data.ExportFunc;
    if Data.Patched then
      chd.DumpStrings.Add(Pfx + PatchedPfx)
    else
      chd.DumpStrings.Add(Pfx + ModifiedPfx);

    AddTableHeader(Data.RawOffset, chd);

    ExternalJmps := TList<ULONG_PTR64>.Create;
    try
      for I := 0 to Data.BufSize - 1 do
      begin
        Modified := True;

        if (RawIndex < RawCount) and (RawDecodedInst[RawIndex].AddrVa = Cursor) then
        begin
          RawOut := GetOutString(RawDecodedInst[RawIndex]);
          Inc(RawIndex);
        end
        else
          RawOut := EmptyStr;

        if (RemoteIndex < RemoteCount) and (RemoteDecodedInst[RemoteIndex].AddrVa = Cursor) then
        begin
          RemoteOut := GetOutString(RemoteDecodedInst[RemoteIndex]);

          // проверка, работаем ли мы с измененной инструкцией?
          Modified :=
            RawDecodedInst[RawIndex - 1] <> RemoteDecodedInst[RemoteIndex];

          // вывод подсказки куда осуществляется переход
          if Modified and (RemoteDecodedInst[RemoteIndex].JmpAddrVa <> 0) then
          begin
            HintString :=
              GetHintString(chd, RemoteDecodedInst[RemoteIndex], ShortJmp);

            // если определен модуль перехода, проверяем фильтр
            if CheckHookHandler(chd) then
              Exit;

            // добавляем подсказку
            if not HintString.IsEmpty then
              RemoteOut := RemoteOut + HintString;

            // и запоминаем возможный адрес перехода для последующей обработки
            if ShortJmp or HintString.IsEmpty then
              ExternalJmps.Add(RemoteDecodedInst[RemoteIndex].JmpAddrVa);
          end;

          Inc(RemoteIndex);
        end
        else
          RemoteOut := EmptyStr;

        Inc(Cursor);
        if RawOut.IsEmpty and RemoteOut.IsEmpty then
          Continue;

        if not Modified then
          Continue;

        // если патч посредине инструкции - выделяем это отдельно
        if (RawIndex > 1) and (chd.DumpStrings.Count = 3) then
        begin
          chd.DumpStrings.Add(IntToHex(RawDecodedInst[0].AddrVa, 16) +
            Separator + ' !!! skipped ' +
            IntToStr(Cursor - 1 - RawDecodedInst[0].AddrVa) + ' bytes');
          chd.DumpStrings.Add(' ... ');
        end;

        if RawOut.IsEmpty then
          RawOut := StringOfChar(Space, 58);
        chd.DumpStrings.Add(IntToHex(Cursor - 1, 16) +
          Separator + RawOut + Separator + RemoteOut);
      end;

      for I := 0 to ExternalJmps.Count - 1 do
      begin
        chd.AddrVA := ExternalJmps[I];
        chd.LimitMin := Data.AddrVA;
        chd.LimitMax := Data.AddrVA + DefaultBuffSize;
        if DumpExternalAddr(chd) then
          Exit;
      end;
    finally
      ExternalJmps.Free;
    end;

    for I := 0 to chd.DumpStrings.Count - 1 do
    begin
      if I = 0 then
      begin
        if Data.Patched then
          Add(chd.DumpStrings[I], InvalidColor)
        else
          Add(chd.DumpStrings[I], WarningColor);
      end
      else
        Add(chd.DumpStrings[I]);
    end;

    Inc(FCodeError);
    EmptyLine;
    Add('*** end code hook data ***');
    EmptyLine;

  finally
    ReleaseCalculateHookData(chd);
  end;
end;

procedure TdlgPatches.ProcessTableHook(const Data: THookData);

  function ByteToHexStr(Value: PByte): string;
  begin
    Result := '';
    for var I := 0 to 3 do
    begin
      Result := Result + IntToHex(Value^, 2) + Space;
      Inc(Value);
    end;
    Result := Result + StringOfChar(Space, 46);
  end;

const
  ExMiss = 'Export record missing, present: ';

var
  chd: TCalculateHookData;
  Pfx, ExternalModule: string;
begin
  Pfx := EmptyStr;
  chd := InitCalculateHookData(Data);
  try

    chd.HookHandlerModule := GetMappedModule(Data.ProcessHandle, Data.RemoteVA);
    ExternalModule := chd.HookHandlerModule;
    if CheckHookHandler(chd) then Exit;

    if not ExternalModule.IsEmpty then
      ExternalModule := ' --> ' + ExternalModule;

    if Data.HookType <> htExport then
    begin
      case Data.HookType of
        htImport: Pfx := 'Import';
        htDelayedImport: Pfx := 'Delayed import';
      end;
      chd.DumpStrings.Add(Pfx + ' modified ' + Data.ModuleName + ' -> ' +
        Data.FuncName + AddrPfx + IntToHex(Data.AddrVA, 1));
      if Data.Calculated or (Data.HookType = htDelayedImport) then
        chd.DumpStrings.Add(ExpectedPfx + IntToHex(Data.RawVA) +
          PresentPfx + IntToHex(Data.RemoteVA) + ExternalModule)
      else
        if Data.ImportAdv.ForvardedTo <> EmptyStr then
          chd.DumpStrings.Add(ExMiss + IntToHex(Data.RemoteVA) +
            ', forvarded to "' + Data.ImportAdv.ForvardedTo + '"' + ExternalModule)
        else
          chd.DumpStrings.Add(ExMiss + IntToHex(Data.RemoteVA) + ExternalModule);
    end
    else
    begin
      Pfx := 'Export modified ' + Data.ModuleName + ' -> ' + Data.FuncName;

      if Data.ExportAdv.Patched then
        chd.DumpStrings.Add(Pfx + PatchedPfx)
      else
        chd.DumpStrings.Add(Pfx + ModifiedPfx);

      if Data.Calculated then
      begin
        chd.DumpStrings.Add(ExpectedPfx + IntToHex(Data.RawVA) +
          PresentPfx + IntToHex(Data.RemoteVA) + ExternalModule);
        AddTableHeader(Data.ExportAdv.RawOffset, chd);
        chd.DumpStrings.Add(IntToHex(Data.AddrVA, 16) + Separator +
          ByteToHexStr(@Data.ExportAdv.ExpRawRva) + Separator +
          ByteToHexStr(@Data.ExportAdv.ExpRemoteRva));
      end
      else
        chd.DumpStrings.Add(ExMiss + IntToHex(Data.RemoteVA) + ExternalModule);
    end;

    if ExternalModule.IsEmpty then
    begin
      chd.AddrVA := Data.RemoteVA;
      chd.LimitMin := Data.ImageBase;
      chd.LimitMax := Data.ImageBase + Data.VirtualSize;
      if DumpExternalAddr(chd) then
        Exit;
    end;

    for var I := 0 to chd.DumpStrings.Count - 1 do
    begin
      if I = 0 then
      begin
        if (Data.HookType = htExport) and Data.ExportAdv.Patched then
          Add(chd.DumpStrings[I], InvalidColor)
        else
          Add(chd.DumpStrings[I], WarningColor);
      end
      else
        Add(chd.DumpStrings[I]);
    end;

    case Data.HookType of
      htImport: Inc(FImportError);
      htDelayedImport: Inc(FDelayedImportError);
      htExport: Inc(FExportError);
    end;

    EmptyLine;
    Add('*** end table hook data ***');
    EmptyLine;


  finally
    ReleaseCalculateHookData(chd);
  end;
end;

procedure TdlgPatches.ReleaseCalculateHookData(const Value: TCalculateHookData);
begin
  Value.DumpStrings.Free;
end;

procedure TdlgPatches.SelectAll1Click(Sender: TObject);
begin
  edLog.SelectAll;
end;

procedure TdlgPatches.ShowModuleInfo(Index: Integer; Module: TRawPEImage);
var
  BitStr, FlagStr: string;

  function AddFlagStr(const Value: string): string;
  begin
    if FlagStr = EmptyStr then
      Result := Value
    else
      Result := FlagStr + ', ' + Value;
  end;

begin
  FlagStr := EmptyStr;
  if Module.Rebased then
    FlagStr := 'REBASED';
  if Module.ComPlusILOnly then
    FlagStr := AddFlagStr('IL_CORE');
  if Module.Redirected then
    FlagStr := AddFlagStr('REDIRECTED');

  if Module.Image64 then
    BitStr := Format('[x64] %.12x ', [Module.ImageBase])
  else
    BitStr := IntToHex(Module.ImageBase, 8) + Space;

  if FlagStr <> EmptyStr then
    FlagStr := ' (' + FlagStr + ')';

  Add(Format('%.3d: ', [Index + 1]),
    BitStr + Module.ImagePath + FlagStr, clGray);
end;

end.
