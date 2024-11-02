////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : dwarfreader.dpr
//  * Purpose   : Утилита статического анализа PE/ELF файлов и вывода DWARF информации
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2024.
//  * Version   : 1.0
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

program dwarfreader;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  Windows,
  SysUtils,
  Math,
  RawScanner.ApiSet in '..\..\..\RawScanner\RawScanner.ApiSet.pas',
  RawScanner.CoffDwarf in '..\..\..\RawScanner\RawScanner.CoffDwarf.pas',
  RawScanner.Elf in '..\..\..\RawScanner\RawScanner.Elf.pas',
  RawScanner.MapGenerator in '..\..\..\RawScanner\RawScanner.MapGenerator.pas',
  RawScanner.SymbolStorage in '..\..\..\RawScanner\RawScanner.SymbolStorage.pas',
  RawScanner.Types in '..\..\..\RawScanner\RawScanner.Types.pas',
  RawScanner.Wow64 in '..\..\..\RawScanner\RawScanner.Wow64.pas',
  RawScanner.Utils in '..\..\..\RawScanner\RawScanner.Utils.pas',
  RawScanner.X64Gates in '..\..\..\RawScanner\RawScanner.X64Gates.pas',
  RawScanner.AbstractImage in '..\..\..\RawScanner\RawScanner.AbstractImage.pas',
  RawScanner.Image.Coff in '..\..\..\RawScanner\RawScanner.Image.Coff.pas',
  RawScanner.Image.Elf in '..\..\..\RawScanner\RawScanner.Image.Elf.pas',
  RawScanner.Image.Pe in '..\..\..\RawScanner\RawScanner.Image.Pe.pas';

var
  DemangleNames: Boolean;
  ShowRawOffset: Boolean;
  ShowVariables: Boolean;
  IncludeUnitName: Boolean;
  ShowProfiler: Boolean;
  MapPath: string;

  ProfileUnitElapsed, ProfileLinesElapsed, ProfileImageElapsed: Int64;

const
  RawHeader = '  Raw   |';
  VaHeader = '  AddrVA  |';
  SizeHdr = ' Size |';
  AccessHeader = 'RWE|';

procedure ShowHeader;
begin
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN or FOREGROUND_RED);
  Writeln('------------------------------------------------------------------------------');
  Writeln('                              PMM plugin - DWARF Reader' );
  Writeln('                         ( C ) 2024 Alexander (Rouse_) Bagel' );
  Writeln('------------------------------------------------------------------------------');
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN or
    FOREGROUND_RED or FOREGROUND_BLUE);
end;

procedure Line;
begin
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN);
  Writeln('------------------------------------------------------------------------------');
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN or
    FOREGROUND_RED or FOREGROUND_BLUE);
end;

function SystemPause(const Prompt: AnsiString): Boolean;
const
  EventCount = 128;
var
  hStdIn, hStdOut: THandle;
  I: Integer;
  lpNumberOfBytesWritten, lpNumberOfEventsRead: Cardinal;
  InputRecords: array [0..EventCount - 1] of TInputRecord;
begin
  hStdIn := GetStdHandle(STD_INPUT_HANDLE);
  hStdOut := GetStdHandle(STD_OUTPUT_HANDLE);
  Result := (hStdIn <> 0) and (hStdOut <> 0);
  if not Result then Exit;
  WriteFile(hStdOut, Prompt[1], Length(Prompt), lpNumberOfBytesWritten, nil);
  while ReadConsoleInput(hStdIn, InputRecords[0], EventCount, lpNumberOfEventsRead) do
    for I := 0 to lpNumberOfEventsRead - 1 do
    begin
      Result :=
        (InputRecords[I].EventType = KEY_EVENT) and
        (InputRecords[i].Event.KeyEvent.bKeyDown);
      if Result then
        Exit;
    end;
end;

procedure ShowHelp;
begin
  Writeln('  Usage option:');
  Writeln('    "path to file" - mandatory parameter always specified first');
  Writeln('    /n - show non executable variables info');
  Writeln('    /d - demangle Symbol/COFF names');
  Writeln('    /r - show raw offset');
  Writeln('    /u - include unit name in DWARF output');
  Writeln('    /p - show profiler info');
  Writeln('    /m="path" - generate MAP file');
  Writeln;
  Writeln('  Example:');
  Writeln('    Show debug info');
  WriteLn('    dwarfreader.exe "c:\test_executeable_with_dwarf.exe"');
  Writeln('');
  Writeln('    Generate MAP file');
  WriteLn('    dwarfreader.exe "c:\test_executeable_with_dwarf.exe" /m=c:\dwarf.map');
  Writeln('');
  Writeln('    Show detailed debug info');
  WriteLn('    dwarfreader.exe "c:\test_executeable_with_dwarf.exe" /n /r');
  Writeln('');
  Writeln('  Error codes:');
  Writeln('    0 - all done');
  Writeln('    1 - invalid parameters, check parameters combination');
  Writeln('    2 - file not found, check file path in first parameter');
  Writeln('    3 - unknown file type (no PE/ELF/COFF)');
  Writeln('    7 - unknown error');
end;

procedure WriteSuccess(const Value: string);
begin
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN);
  Writeln(Value);
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN or
    FOREGROUND_RED or FOREGROUND_BLUE);
end;

procedure WriteFailed(const Value: string);
begin
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
  Writeln(Value);
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN or
    FOREGROUND_RED or FOREGROUND_BLUE);
end;

procedure WriteWarning(const Value: string);
begin
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY or FOREGROUND_RED);
  Write(Value);
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN or
    FOREGROUND_RED or FOREGROUND_BLUE);
end;

procedure Finished(AExitCode: Integer);
begin
  ExitCode := AExitCode;
  ExitProcess(ExitCode);
end;

function FindAndExtractCmdParamValue(Switch: string;
  out ParamValue: string;
  SwitchCharList: TSysCharSet = []): Boolean;
var
  I: Integer;
  ParamData: string;
begin
  Result := False;
  ParamValue := '';
  Switch := AnsiLowerCase(Trim(Switch));
  for I := 1 to ParamCount do
  begin
    ParamData := AnsiLowerCase(ParamStr(I));
    if SwitchCharList <> [] then
    begin
      if not CharInSet(ParamData[1], SwitchCharList) then Continue;
      Delete(ParamData, 1, 1);
    end;
    if Pos(Switch, ParamData) <> 1 then Continue;
    Delete(ParamData, 1, Length(Switch));
    ParamValue := ParamData;
    Result := ParamValue <> '';
  end;
end;

function CheckFileType(const Path: string): Integer;
var
  Image: TAbstractImage;
begin
  Result := -1;
  Image := TRawPEImage.Create(Path, True);
  try
    if Image.ImageType in [itPE32, itPE64] then
      Exit(0);
  finally
    Image.Free;
  end;
  Image := TRawELFImage.Create(Path, True);
  try
    if Image.ImageType in [itELF32, itELF64] then
      Exit(1);
  finally
    Image.Free;
  end;
  Image := TRawCoffImage.Create(Path, True);
  try
    if Image.ImageType in [itCOFF32, itCOFF64] then
      Exit(2);
  finally
    Image.Free;
  end;
end;

procedure DumpUInt64(Value: UInt64; ACharCount: Integer);
begin
  if Value = 0 then
  begin
    WriteWarning(StringOfChar('0', ACharCount));
    Write('|');
  end
  else
    Write(IntToHex(Value, ACharCount), '|');
end;

procedure DumpImageInfo(AImage: TAbstractImage);
begin
  Write('Image type: ');
  case AImage.ImageType of
    itUnknown: WriteFailed('Unknown');
    itPE32: Writeln('PE32');
    itPE64: Writeln('PE64');
    itELF32: Writeln('ELF32');
    itELF64: Writeln('ELF64');
    itCOFF32: Writeln('COFF32');
    itCOFF64: Writeln('COFF64');
    itOMF32: Writeln('OMF32');
    itOMF64: Writeln('OMF64');
  end;
end;

function DumpDwarf(AImage: TAbstractImage): Integer;
var
  AUnit: TDwarfInfoUnit;
  ALineUnit: TDwarfLinesUnit;
  AUnitAdded: Boolean;
  AEntry: TDebugInformationEntry;
  Section: TSectionData;
  Flags: string;
  ASize: UInt64;
begin
  Writeln;
  Writeln('Dump DWARF.');
  Line;
  Result := 0;

  if ShowProfiler then
  begin
    ProfileLinesElapsed := 0;
    for ALineUnit in AImage.DwarfDebugInfo.UnitLines do
      Inc(ProfileLinesElapsed, ALineUnit.Elapsed);
  end;

  ProfileUnitElapsed := 0;
  for AUnit in AImage.DwarfDebugInfo.UnitInfos do
  begin
    AUnitAdded := False;
    Inc(ProfileUnitElapsed, AUnit.Elapsed);
    for AEntry in AUnit.Data do
    begin
      Flags := '...|';
      if AImage.GetSectionData(AImage.VaToRva(AEntry.AddrVA), Section) then
      begin
        if Section.Read then
          Flags[1] := 'R';
        if Section.Write then
          Flags[2] := 'W';
        if Section.Execute then
          Flags[3] := 'E';
      end;

      if not Section.Execute and not ShowVariables and not AEntry.Executable then
        Continue;

      if not AUnitAdded then
      begin
        Writeln;
        if ShowProfiler then
          Writeln('unit: "', AUnit.UnitName, '", loaded: ', AUnit.Elapsed, ' msec')
        else
          Writeln('unit: ', AUnit.UnitName);
        Line;
        if ShowRawOffset then
          Write(RawHeader);
        Writeln(VaHeader, SizeHdr, AccessHeader);
        Line;
        AUnitAdded := True;
      end;
      Inc(Result);

      if AEntry.EndOfCode <= AEntry.AddrVA then
        ASize := 0
      else
        ASize := AEntry.EndOfCode - AEntry.AddrVA;

      if ShowRawOffset then
        DumpUInt64(AImage.VaToRaw(AEntry.AddrVA), 8);
      DumpUInt64(AEntry.AddrVA, 10);
      DumpUInt64(ASize, 6);
      Writeln(Flags, AEntry.LongName);
    end;
  end;
  if Result = 0 then
  begin
    Write('Something wrong: ');
    WriteFailed('no valid dwarf data.');
  end
  else
  begin
    Writeln;
    Write('Done: ');
    WriteSuccess(IntToStr(Result) + ' entries');
  end;
end;

procedure DumpPEImage(AImage: TRawPEImage);
var
  Sym: TCoffFunction;
  Section: TSectionData;
  Flags, AName: string;
  ACount: Integer;
begin
  DumpImageInfo(AImage);

  if MapPath <> '' then
  begin
    Writeln;
    Writeln('Generate MAP: ', MapPath, '... ');
    if MakeDebugMap(ParamStr(1), MapPath, AImage.DwarfDebugInfo, AImage.EntryPoint) then
      WriteSuccess('done.')
    else
      WriteFailed('failed.');
    Exit;
  end;

  DumpDwarf(AImage);

  if AImage.CoffDebugInfo.CoffStrings.Count > 0 then
  begin
    Writeln;
    Writeln('Dump COFF.');
    Line;
    if ShowRawOffset then
      Write(RawHeader);
    Writeln(VaHeader, AccessHeader);
    Line;

    ACount := 0;
    for Sym in AImage.CoffDebugInfo.CoffStrings do
    begin
      if Sym.DisplayName = '' then
        Continue;

      if not AImage.GetSectionData(AImage.VaToRva(Sym.FuncAddrVA), Section) then
        Continue;

      Flags := '...|';
      if Section.Read then
        Flags[1] := 'R';
      if Section.Write then
        Flags[2] := 'W';
      if Section.Execute then
        Flags[3] := 'E'
      else
        if not ShowVariables then
          Continue;

      if DemangleNames then
        AName := DemangleName(Sym.DisplayName, Sym.Executable)
      else
        AName := Sym.DisplayName;

      if ShowRawOffset then
        DumpUInt64(AImage.VaToRaw(Sym.FuncAddrVA), 8);
      DumpUInt64(Sym.FuncAddrVA, 10);
      Writeln(Flags, AName);

      Inc(ACount);
    end;

    if ACount = 0 then
    begin
      Write('Something wrong: ');
      WriteFailed('no valid COFF data.');
    end
    else
    begin
      Writeln;
      Write('Done: ');
      WriteSuccess(IntToStr(ACount) + ' entries');
    end;
  end;
end;

procedure DumpELFImage(AImage: TRawElfImage);
var
  Sym: TImageSymbol;
  Section: TElfSectionHeader;
  AddrVA: UInt64;
  Flags, AName: string;
  ACount: Integer;
begin
  DumpImageInfo(AImage);

  if MapPath <> '' then
  begin
    if AImage.HeaderPresent then
    begin
      Writeln;
      Writeln('Generate MAP: ', MapPath);
      if MakeDebugMap(ParamStr(1), MapPath, AImage.DwarfDebugInfo, AImage.EntryPoint) then
        WriteSuccess('done.')
      else
        WriteFailed('failed.');
    end
    else
      WriteFailed('Can not create MAP file. Programm header missing.');
    Exit;
  end;

  DumpDwarf(AImage);

  if AImage.Symbols.Count > 0 then
  begin
    Writeln;
    Writeln('Dump symbols.');
    Line;
    if ShowRawOffset or not AImage.HeaderPresent then
      Write(RawHeader);
    if AImage.HeaderPresent then
      Write(VaHeader);
    Writeln(SizeHdr, AccessHeader);
    Line;

    ACount := 0;
    for Sym in AImage.Symbols do
    begin
      if Sym.DisplayName = '' then
        Continue;
      if not (ELF32_ST_TYPE(Sym.Hdr.st_info) in [STT_OBJECT, STT_FUNC]) then
        Continue;
      if not AImage.SectionAtIndex(Sym.Hdr.st_shndx, Section) then
        Continue;
      if not (Section.Hdr.sh_type in [SHT_PROGBITS, SHT_DYNAMIC]) then
        Continue;
      if Section.Hdr.sh_flags = 0 then
        Continue;

      AddrVA := Sym.Hdr.st_value;
      if not AImage.HeaderPresent then
        Inc(AddrVA, Section.Hdr.sh_offset);

      Flags := '...|';
      if SHF_ALLOC and Section.Hdr.sh_flags <> 0 then
        Flags[1] := 'R';
      if SHF_WRITE and Section.Hdr.sh_flags <> 0 then
        Flags[2] := 'W';
      if SHF_EXECINSTR and Section.Hdr.sh_flags <> 0 then
        Flags[3] := 'E'
      else
        if not ShowVariables then
          Continue;

      if DemangleNames then
        AName := DemangleName(Sym.DisplayName, Sym.Executable)
      else
        AName := Sym.DisplayName;

      if AImage.HeaderPresent and ShowRawOffset then
        DumpUInt64(AImage.VaToRaw(AddrVA), 8);
      DumpUInt64(AddrVA, IfThen(AImage.HeaderPresent, 10, 8));

      DumpUInt64(Sym.Hdr.st_size, 6);
      Writeln(Flags, AName);

      Inc(ACount);
    end;

    if ACount = 0 then
    begin
      Write('Something wrong: ');
      WriteFailed('no valid symbol data.');
    end
    else
    begin
      Writeln;
      Write('Done: ');
      WriteSuccess(IntToStr(ACount) + ' entries');
    end;
  end;
end;

procedure DumpCOFFImage(AImage: TRawCoffImage);
var
  Sym: TCoffFunction;
  Section: TCoffSectionHeader;
  Flags, AName: string;
  ACount: Integer;
begin
  DumpImageInfo(AImage);

  if MapPath <> '' then
  begin
    WriteFailed('Can not create MAP file.');
    Exit;
  end;

  DumpDwarf(AImage);

  if AImage.CoffDebugInfo.CoffStrings.Count > 0 then
  begin
    Writeln;
    Writeln('Dump COFF.');
    Line;
    Writeln(RawHeader, AccessHeader);
    Line;

    ACount := 0;
    for Sym in AImage.CoffDebugInfo.CoffStrings do
    begin
      if Sym.DisplayName = '' then
        Continue;

      if not AImage.SectionAtIndex(Sym.SectionIndex, Section) then
        Continue;

      Flags := '...|';
      if Section.Characteristics and IMAGE_SCN_MEM_READ <> 0 then
        Flags[1] := 'R';
      if Section.Characteristics and IMAGE_SCN_MEM_WRITE <> 0 then
        Flags[2] := 'W';
      if Section.Characteristics and IMAGE_SCN_MEM_EXECUTE <> 0 then
        Flags[3] := 'E'
      else
        if not ShowVariables then
          Continue;

      if DemangleNames then
        AName := DemangleName(Sym.DisplayName, Sym.Executable)
      else
        AName := Sym.DisplayName;

      DumpUInt64(Section.PointerToRawData, 8);
      Writeln(Flags, AName);

      Inc(ACount);
    end;

    if ACount = 0 then
    begin
      Write('Something wrong: ');
      WriteFailed('no valid COFF data.');
    end
    else
    begin
      Writeln;
      Write('Done: ');
      WriteSuccess(IntToStr(ACount) + ' entries');
    end;
  end;
end;

procedure WaitKey;
begin
  if GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) <> FILE_TYPE_DISK then
  begin
    Writeln;
    SystemPause('Press any key to continue...');
  end;
end;

var
  Pe: TRawPEImage;
  Elf: TRawElfImage;
  Coff: TRawCoffImage;
  NeedShowHelp: Boolean;
begin
  try
    ExitCode := 0;

    ShowHeader;

    if ParamCount = 0 then
    begin
      ShowHelp;
      WaitKey;
      Finished(1);
    end;

    NeedShowHelp := False;
    if FindCmdLineSwitch('?', SwitchChars, True) then
      NeedShowHelp := True;

    if FindCmdLineSwitch('h', SwitchChars, True) then
      NeedShowHelp := True;

    if FindCmdLineSwitch('help', SwitchChars, True) then
      NeedShowHelp := True;

    if NeedShowHelp then
    begin
      ShowHelp;
      Line;
    end;

    DemangleNames := FindCmdLineSwitch('d', SwitchChars, True);
    ShowRawOffset := FindCmdLineSwitch('r', SwitchChars, True);
    ShowVariables := FindCmdLineSwitch('n', SwitchChars, True);
    IncludeUnitName := FindCmdLineSwitch('u', SwitchChars, True);
    ShowProfiler := FindCmdLineSwitch('p', SwitchChars, True);
    FindAndExtractCmdParamValue('m=', MapPath, SwitchChars);

    TRawPEImage.DisableLoadStrings := True;
    TDwarfDebugInfo.BeforeLoadCallback := procedure(ADwarfDebugInfo: TDwarfDebugInfo)
    begin
      ADwarfDebugInfo.AppendNoAddrVADie := ADwarfDebugInfo.Image.IsObjectFile;
      ADwarfDebugInfo.AppendUnitName := IncludeUnitName;
    end;

    Write('Open: ', ParamStr(1), '... ');
    ProfileImageElapsed := 0;
    case CheckFileType(ParamStr(1)) of
      0: // PE
      begin
        Pe := TRawPEImage.Create(ParamStr(1), False);
        try
          ProfileImageElapsed := Pe.Elapsed;
          WriteSuccess('done.');
          DumpPEImage(Pe);
        finally
          Pe.Free;
        end;
      end;
      1: // ELF
      begin
        Elf := TRawElfImage.Create(ParamStr(1), False);
        try
          ProfileImageElapsed := Elf.Elapsed;
          WriteSuccess('done.');
          DumpELFImage(Elf);
        finally
          Elf.Free;
        end;
      end;
      2: // COFF
      begin
        Coff := TRawCoffImage.Create(ParamStr(1), False);
        try
          ProfileImageElapsed := Coff.Elapsed;
          WriteSuccess('done.');
          DumpCOFFImage(Coff);
        finally
          Coff.Free;
        end;
      end;
    else
      WriteFailed('error. Unknown file type.');
      WaitKey;
      Finished(3);
    end;

    if ShowProfiler then
    begin
      Writeln;
      Writeln('Profiler:');
      Writeln('Total unit elapsed: ', ProfileUnitElapsed, ' msec');
      Writeln('Total lines elapsed: ', ProfileLinesElapsed, ' msec');
      Writeln('Total elapsed: ', ProfileLinesElapsed + ProfileUnitElapsed, ' msec');
      Writeln('Total image open elapsed: ', ProfileImageElapsed, ' msec');
    end;

  except
    on E: Exception do
    begin
      WriteFailed(E.ClassName + ': ' + E.Message);
      WaitKey;
      Finished(7);
    end;
  end;

  WaitKey;
end.
