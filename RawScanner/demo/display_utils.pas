unit display_utils;

interface

uses
  Windows,
  SysUtils,
  Classes,
  Math,
  Generics.Collections,
  RawScanner.Types,
  RawScanner.Logger,
  RawScanner.ModulesData,
  RawScanner.Disassembler,
  RawScanner.Analyzer,
  RawScanner.Filter,
  RawScanner.Utils;

var
  Filter: TFilter;
  GlobalFiltered: Integer = 0;
  GlobalChecked: Integer = 0;

  procedure OnLog(ALevel: TLogLevel; AType: TLogType;
    const FuncName, Description: string);
  procedure ShowModuleInfo(Index: Integer; Module: TRawPEImage);
  procedure ProcessTableHook(const Data: THookData);
  procedure ProcessCodeHook(const Data: TCodeHookData);

implementation

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

const
  Separator = '|';
  HexPfx = '0x';
  PatchedPfx = '. Status: PATCHED!';
  ModifiedPfx = '. Status: Modified. Probably wrong detect.';
  ExpectedPfx = 'Expected: ';
  PresentPfx = ', present: ';
  AddrPfx = ', at address: ';

function InitCalculateHookData: TCalculateHookData; overload;
begin
  ZeroMemory(@Result, SizeOf(TCalculateHookData));
  Result.DumpStrings := TStringList.Create;
end;

function InitCalculateHookData(const Data: THookData): TCalculateHookData; overload;
begin
  Result := InitCalculateHookData;
  Result.ProcessHandle := Data.ProcessHandle;
  Result.AddrVA := Data.AddrVA;
  Result.ImageBase := Data.ImageBase;
  Result.Is64Code := Data.Image64;
  Result.HookType := Data.HookType;
  Result.LibraryFuncName := Data.FuncName;
end;

function InitCalculateHookData(const CodeData: TCodeHookData): TCalculateHookData; overload;
begin
  Result := InitCalculateHookData;
  Result.ProcessHandle := CodeData.ProcessHandle;
  Result.AddrVA := CodeData.AddrVA;
  Result.ImageBase := CodeData.ImageBase;
  Result.Is64Code := CodeData.Image64;
  Result.HookType := htCode;
  Result.LibraryFuncName := CodeData.ExportFunc;
end;

procedure ReleaseCalculateHookData(const Value: TCalculateHookData);
begin
  Value.DumpStrings.Free;
end;

function CheckHookHandler(var chd: TCalculateHookData): Boolean;
var
  FilterStatus: TFilterStatus;
begin
  if chd.HookHandlerModule.IsEmpty then Exit(False);
  FilterStatus :=
    Filter.Check(chd.HookHandlerModule, chd.LibraryFuncName, chd.HookType);
  Result := FilterStatus <> fsNone;
  case FilterStatus of
    fsNone: chd.HookHandlerModule := EmptyStr;
    fsIgnore:
    begin
      // чисто для демо, это мы игнорим
      Inc(GlobalFiltered);
      Writeln(chd.LibraryFuncName + ArrowMarker + chd.HookHandlerModule, ' filtered');
    end;
    fsCheck:
    begin
      // а это мы чекаем, потом можно как-то обыграть
      Inc(GlobalChecked);
      Writeln(GlobalChecked, ': ', chd.LibraryFuncName + ArrowMarker + chd.HookHandlerModule, ' checked');
    end;
  end;
end;

const
  DefaultBuffSize = 64;

procedure ShowModuleInfo(Index: Integer; Module: TRawPEImage);
const
  Step = 'Loading... ';
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
  if not Module.Rebased then
    FlagStr := 'REBASED';
  if Module.ComPlusILOnly then
    FlagStr := AddFlagStr('IL_CORE');
  if Module.Redirected then
    FlagStr := AddFlagStr('REDIRECTED');

  if Module.Image64 then
    BitStr := '[x64] ' + IntToHex(Module.ImageBase) + Space
  else
    BitStr := IntToHex(Module.ImageBase, 8) + Space;

  if FlagStr <> EmptyStr then
    FlagStr := ' (' + FlagStr + ')';

  Writeln(Index + 1, ': ', Step, BitStr, Module.ImagePath, FlagStr);
end;

procedure AddTableHeader(RawOffset: DWORD; cdh: TCalculateHookData);
var
  Line, HexStr: string;
begin
  HexStr := HexPfx + IntToHex(RawOffset, 0);
  Line := 'Addr:' + StringOfChar(Space, 11) + '|Raw (' +
    HexPfx + IntToHex(RawOffset, 0) + '):';
  Line := Line +
    StringOfChar(Space, 51 - Length(HexStr)) +
    '|Remote:';
  cdh.DumpStrings.Add(Line);
  cdh.DumpStrings.Add(StringOfChar('-', 124));
end;

procedure OnLog(ALevel: TLogLevel; AType: TLogType;
  const FuncName, Description: string);

  function LogStr: string;
  begin
    if FuncName = EmptyStr then
      Result := Description
    else
      Result := FuncName + ': ' + Description;
  end;

begin
  if ALevel = llContext then Exit; // контекст еще не доделан
  case AType of
    ltNotify:   Writeln(LogStr);
    ltInfo:     Writeln('[.]        ', LogStr);
    ltWarning:  Writeln('[+] WARN:  ', LogStr);
    ltError:    Writeln('[-] ERR:   ', LogStr);
    ltFatal:    Writeln('[-] FATAL: ', LogStr);
  end;
end;

function GetHintString(var chd: TCalculateHookData; Inst: TInstruction): string;
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

  if chd.ImageBase <> ULONG_PTR64(MBI.AllocationBase) then
  begin
    chd.HookHandlerModule := GetMappedModule(chd.ProcessHandle, MBI.AllocationBase);
    if not chd.HookHandlerModule.IsEmpty then
      Result := ' --> ' + Result + chd.HookHandlerModule;
  end;
end;

function DumpExternalAddr(chd: TCalculateHookData): Boolean;
var
  Buff: array of Byte;
  Disasm: TDisassembler;
  Inst: TInstructionArray;
  I: Integer;
  HintString: string;
  AddHeader: Boolean;
begin
  Result := False;
  SetLength(Buff, DefaultBuffSize);
  if not ReadRemoteMemory(chd.ProcessHandle, chd.AddrVA,
    @Buff[0], DefaultBuffSize) then
    Exit;

  Disasm := TDisassembler.Create(chd.ProcessHandle, chd.AddrVA,
    DefaultBuffSize, chd.Is64Code);
  try
    Inst := Disasm.DecodeBuff(@Buff[0], True);
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
      HintString := GetHintString(chd, Inst[I]);
      Result := CheckHookHandler(chd);
      if Result then
        Break;
    end
    else
      HintString := EmptyStr;
    if AddHeader then
    begin
      chd.DumpStrings.Add('External jump disassembly: ');
      AddHeader := False;
    end;
    chd.DumpStrings.Add(IntToHex(Inst[I].AddrVa, 16) + ': ' +
      Inst[I].DecodedString + Space + HintString);
  end;
end;

procedure ProcessTableHook(const Data: THookData);

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

    chd.DumpStrings.Add(EmptyStr);

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
      Writeln(chd.DumpStrings[I]);

  finally
    ReleaseCalculateHookData(chd);
  end;

end;

procedure ProcessCodeHook(const Data: TCodeHookData);
const
  Space = Space;

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
  Modified: Boolean;
  Cursor, MaxAddr: ULONG_PTR64;
  Pfx, RawOut, RemoteOut, HintString: string;
  ExternalJmps: TList<ULONG_PTR64>;
  chd: TCalculateHookData;
begin
  Disasm := TDisassembler.Create(
    Data.ProcessHandle, Data.AddrVA, Data.BufSize, Data.Image64);
  try

    RawDecodedInst := Disasm.DecodeBuff(Data.Raw, True);
    RawCount := Length(RawDecodedInst);

    RemoteDecodedInst := Disasm.DecodeBuff(Data.Remote, False);
    RemoteCount := Length(RemoteDecodedInst);
  finally
    Disasm.Free;
  end;

  // если не смогли дизассемблировать один из буферов (или оба) выводим как есть
  if (RawCount = 0) or (RemoteCount = 0) then
  begin
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

      // 3. убираем все лишние блоки
      while (RemoteCount > 0) and (RemoteDecodedInst[RemoteCount - 1].AddrVa > MaxAddr) do
        Dec(RemoteCount);
      while (RawCount > 0) and (RawDecodedInst[RawCount - 1].AddrVa > MaxAddr) do
        Dec(RawCount);

      Break;
    end;
  end;

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

    chd.DumpStrings.Add(EmptyStr);
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
              GetHintString(chd, RemoteDecodedInst[RemoteIndex]);

            // если определен модуль перехода, проверяем фильтр
            if CheckHookHandler(chd) then
              Exit;

            if HintString.IsEmpty then
              ExternalJmps.Add(RemoteDecodedInst[RemoteIndex].JmpAddrVa)
            else
              RemoteOut := RemoteOut + HintString;
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
      Writeln(chd.DumpStrings[I]);

  finally
    ReleaseCalculateHookData(chd);
  end;

end;

end.
