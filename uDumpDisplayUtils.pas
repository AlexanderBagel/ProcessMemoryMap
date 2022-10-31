////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uDumpDisplayUtils.pas
//  * Purpose   : Вспомогательный модуль для отображения содержимого
//  *           : памяти в свойствах региона и размапленных структур
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2022.
//  * Version   : 1.2.16
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uDumpDisplayUtils;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.DateUtils,
  System.StrUtils,
  Generics.Collections,
  Classes,
  PsAPI,
  uUtils,
  MemoryMap.Core,
  MemoryMap.Symbols,
  MemoryMap.Utils,
  RawScanner.Core,
  RawScanner.SymbolStorage,
  distorm,
  mnemonics;

  // описывает IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
  {$MESSAGE 'IMAGE_LOAD_CONFIG_DIRECTORY'}
  
  // добавить tagSOleTlsData из "E:\Windows Sources\XPSP1\NT\com\ole32\ih\tls.h"
  // она мапится на TEB::ReservedForOle
  // подробнее тут https://dennisbabkin.com/blog/?t=things-you-thought-you-knew-how-to-get-com-concurrency-model-for-current-thread
  
  // Process Parameters (32) под Xp кривой
  // EnvironmentSize в конце соответствует началу блока данных из CurrentDirectory.DosPath = [20290]

  function DumpMemory(Process: THandle; Address: Pointer; nSize: Integer = 0): string;
  function DumpMemoryFromBuff(Process: THandle; Address: Pointer;
    RawBuff: TMemoryDump; nSize: Integer): string;
  procedure DumpMemoryFromBuffWithCheckRawData(var OutString: string;
    Process: THandle; Address: Pointer; RawBuff: TMemoryDump; Cursor: NativeUInt);
  function DumpPEB32(Process: THandle; Address: Pointer): string;
  function DumpPEB64(Process: THandle; Address: Pointer): string;
  function DumpPEHeader(Process: THandle; Address: Pointer): string;
  function DumpThread64(Process: THandle; Address: Pointer): string;
  function DumpThread32(Process: THandle; Address: Pointer): string;
  function DumpKUserSharedData(Process: THandle; Address: Pointer): string;
  function DumpProcessParameters32(Process: THandle; Address: Pointer): string;
  function DumpProcessParameters64(Process: THandle; Address: Pointer): string;
  function DumpOleTlsData32(Process: THandle; Address: Pointer; IsWow64: Boolean): string;
  function DumpOleTlsData64(Process: THandle; Address: Pointer): string;
//  function DumpLoaderData(Process: THandle; Address: Pointer): string;
//  function DumpActivationContext(Process: THandle; Address: Pointer; SystemCtx: Boolean): string;

type
  TKnownHint = TDictionary<string, ULONG_PTR>;

  TDasmMode = (dmAuto, dmX86, dmX64);

  function Disassembly(Process: THandle; Address: Pointer;
    AMode: TDasmMode; KnownHint: TKnownHint; out Dasm64Mode: Boolean;
    nSize: Integer = 0): string;
  function DisassemblyFromBuff(Process: THandle; RawBuff: TMemoryDump;
    Symbols: TSymbols; Address, AllocationBase: Pointer;
    const ModuleName: string; Is64: Boolean; nSize: NativeUInt;
    KnownHint: TKnownHint): string;

const
  EmptyHeader =
    '----------------------------------------------------------------------------------------------------------';

implementation

uses
  RawScanner.ActivationContext;

// Добавить гиперссылки
// {\field{\*\fldinst HYPERLINK "http://www.microsoft.com"}{\fldrslt Microsoft}}

const
  MemoryDumpHeader =
    '-------------------------------------------- Memory dump -------------------------------------------------';
  PEBHeader32 =
    '---------------------------------- Process Environment Block (x32) ---------------------------------------';
  PEBHeader64 =
    '---------------------------------- Process Environment Block (x64) ---------------------------------------';
  TIB32_Header =
    '---------------------------------------------- NT_TIB32 --------------------------------------------------';
  TEB32_Header =
    '----------------------------------------------- TEB32 ----------------------------------------------------';
  TIB64_Header =
    '---------------------------------------------- NT_TIB64 --------------------------------------------------';
  TEB64_Header =
    '----------------------------------------------- TEB64 ----------------------------------------------------';
  PEHeader =
    '------------------------------------------ IMAGE_DOS_HEADER ----------------------------------------------';
  NT_HEADERS =
    '------------------------------------------ IMAGE_NT_HEADERS ----------------------------------------------';
  FILE_HEADER =
    '------------------------------------------ IMAGE_FILE_HEADER ---------------------------------------------';
  OPTIONAL_HEADER32 =
    '--------------------------------------- IMAGE_OPTIONAL_HEADER32 ------------------------------------------';
  OPTIONAL_HEADER64 =
    '--------------------------------------- IMAGE_OPTIONAL_HEADER64 ------------------------------------------';
  DATA_DIRECTORY =
    '----------------------------------------- IMAGE_DATA_DIRECTORY -------------------------------------------';
  SECTION_HEADERS =
    '---------------------------------------- IMAGE_SECTION_HEADERS -------------------------------------------';
  KUSER =
    '------------------------------------------ KUSER_SHARED_DATA ---------------------------------------------';
  PROCESSPARAMS32 =
    '--------------------------------------- Process Parameters (32) ------------------------------------------';
  PROCESSPARAMS64 =
    '--------------------------------------- Process Parameters (64) ------------------------------------------';
  DisasmDumpHeader =
    '------------------------------------------ Disassemby dump -----------------------------------------------';
  OLE_TLS_DATA32 =
    '----------------------------------------- OLE_TLS_DATA (32) ----------------------------------------------';
  OLE_TLS_DATA64 =
    '----------------------------------------- OLE_TLS_DATA (64) ----------------------------------------------';
  LDR_DATA32 =
    '------------------------------------------ PEB_LDR_DATA32 ------------------------------------------------';
  LDR_DATA64 =
    '------------------------------------------ PEB_LDR_DATA64 ------------------------------------------------';
  LDR_DATA_TABLE_ENTRY32 =
    '-------------------------------------- LDR_DATA_TABLE_ENTRY32 --------------------------------------------';
  LDR_DATA_TABLE_ENTRY64 =
    '-------------------------------------- LDR_DATA_TABLE_ENTRY64 --------------------------------------------';
  ACTX_PROCESS =
    '------------------------------------- PROCESS ACTIVATION CONTEXT -----------------------------------------';
  ACTX_SYSTEM =
    '------------------------------------- SYSTEM ACTIVATION CONTEXT ------------------------------------------';
  ACTX_TOC_HEADER =
    '---------------------------------- ACTIVATION_CONTEXT_DATA_TOC_HEADER ------------------------------------';
  ACTX_TOC_HEADER_ENTRY =
    '----------------------------------- ACTIVATION_CONTEXT_DATA_TOC_ENTRY ------------------------------------';
  ACTX_EXTOC_HEADER =
    '------------------------------ ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER -------------------------------';
  ACTX_EXTOC_HEADER_ENTRY =
    '------------------------------ ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_ENTRY --------------------------------';
  ACTX_ASSEMBLY_ROSTER_HEADER =
    '---------------------------- ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER ------------------------------';
  ACTX_ASSEMBLY_ROSTER_ENTRY =
    '----------------------------- ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY ------------------------------';
  ACTX_STRING_HEADER =
    '------------------------------- ACTIVATION_CONTEXT_STRING_SECTION_HEADER ---------------------------------';
  ACTX_STRING_ENTRY =
    '-------------------------------- ACTIVATION_CONTEXT_STRING_SECTION_ENTRY ---------------------------------';

type
  TDataType = (dtByte, dtWord, dtDword,
    dtInt64, dtGUID, dtString, dtAnsiString, dtBuff, dtUnicodeString32,
    dtUnicodeString64);

  Pointer32 = DWORD;

function GET_WString(w: _WString): string;
begin
  Result := string(PAnsiChar(@w.p[0]));
end;

function DecodeResultToStr(Value: TDecodeResult): string;
begin
  case Value of
    DECRES_SUCCESS: Result := 'DECRES_SUCCESS';
    DECRES_MEMORYERR: Result := 'DECRES_MEMORYERR';
    DECRES_INPUTERR: Result := 'DECRES_INPUTERR';
  else
    Result := 'DECRES_NONE';
  end;
end;

function IsLonghornOrHigher: Boolean;
begin
  Result := Win32MajorVersion >= 6;
end;

function IsW2003OrHigher: Boolean;
begin
  Result := IsLonghornOrHigher;
  if not Result then
    Result := (Win32MajorVersion = 5) and (Win32MinorVersion >= 2);
end;

function IsXPOrHigher: Boolean;
begin
  Result := IsW2003OrHigher;
  if not Result then
    Result := (Win32MajorVersion = 5) and (Win32MinorVersion >= 1);
end;

function ByteToHexStr(Base: NativeUInt; Data: Pointer;
  Len: Integer; const Comment: string = ''): string;
var
  I, PartOctets: Integer;
  Octets: NativeUInt;
  DumpData: string;
  CommentAdded: Boolean;
begin
  if Len = 0 then Exit;
  I := 0;
  Octets := Base;
  PartOctets := 0;
  Result := '';
  CommentAdded := False;
  while I < Len do
  begin
    case PartOctets of
      0: Result := Result + UInt64ToStr(Octets) + ' ';
      9: Result := Result + '| ';
      18:
      begin
        Inc(Octets, 16);
        PartOctets := -1;
        if Comment <> '' then
        begin
          if CommentAdded then
            Result := Result + sLineBreak
          else
          begin
            Result := Result + '    ' + Comment + sLineBreak;
            CommentAdded := True;
          end;
        end
        else
          Result := Result + '    ' + DumpData + sLineBreak;
        DumpData := '';
      end;
    else
      begin
        Result := Result + Format('%s ', [IntToHex(TByteArray(Data^)[I], 2)]);
        if TByteArray(Data^)[I] in [$19..$FF] then
          DumpData := DumpData + Char(AnsiChar(TByteArray(Data^)[I]))
        else
          DumpData := DumpData + '.';
        Inc(I);
      end;
    end;
    Inc(PartOctets);
  end;
  if PartOctets <> 0 then
  begin
    PartOctets := (16 - Length(DumpData)) * 3;
    if PartOctets >= 24 then Inc(PartOctets, 2);
    Inc(PartOctets, 4);
    if Comment <> '' then
    begin
      if not CommentAdded then
        Result := Result + StringOfChar(' ', PartOctets) + Comment;
    end
    else
      Result := Result + StringOfChar(' ', PartOctets) + DumpData;
  end;
end;

function AsmToHexStr(Base: NativeUInt; Data: Pointer;
  Len: Integer): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Len - 1 do
    Result := Result + IntToHex(TByteArray(Data^)[I], 2) + ' ';
  Result := Result + StringOfChar(' ', (14 - Len) * 3);
end;

procedure AddString(var OutValue: string; const NewString, SubComment: string); overload;
var
  Line: string;
  sLineBreakOffset, SubCommentOffset: Integer;
begin
  if SubComment = '' then
    OutValue := OutValue + NewString + sLineBreak
  else
  begin
    sLineBreakOffset := Pos(#13, NewString);
    if sLineBreakOffset = 0 then
    begin
      SubCommentOffset := 106 - Length(NewString);
      Line := NewString + StringOfChar(' ', SubCommentOffset) + ' // ' + SubComment;
    end
    else
    begin
      SubCommentOffset := 107 - sLineBreakOffset;
      Line := StuffString(NewString, sLineBreakOffset, 0,
        StringOfChar(' ', SubCommentOffset) + ' // ' + SubComment);
    end;
    OutValue := OutValue + Line + sLineBreak;
  end;
end;

procedure AddString(var OutValue: string; const NewString: string); overload;
begin
  AddString(OutValue, NewString, '');
end;

var
  CurerntAddr: Pointer;
  MaxSize: NativeUInt;

procedure AddString(var OutValue: string; const Comment: string; Address: Pointer;
  DataType: TDataType; Size: Integer; var Cursor: NativeUInt;
  const SubComment: string = ''); overload;
var
  UString: string;
  AString: AnsiString;
begin
  UString := '';
  case DataType of
    dtByte: UString := IntToHex(PByte(Address)^, 1);
    dtWord: UString := IntToHex(PWord(Address)^, 1);
    dtDword: UString := IntToHex(PDWORD(Address)^, 1);
    dtInt64: UString := IntToHex(PInt64(Address)^, 1);
    dtGUID: UString := GUIDToString(PGUID(Address)^);
    dtString:
    begin
      SetLength(UString, Size div 2);
      Move(PByte(Address)^, UString[1], Size);
      UString := '"' + PChar(UString) + '"';
    end;
    dtAnsiString:
    begin
      SetLength(AString, Size);
      Move(PByte(Address)^, AString[1], Size);
      UString := '"' + string(PAnsiChar(AString)) + '"';
    end;
  end;
  if UString = '' then
    AddString(OutValue, ByteToHexStr(NativeUInt(CurerntAddr) + Cursor,
      Address, Size, Comment), SubComment)
  else
    AddString(OutValue, ByteToHexStr(NativeUInt(CurerntAddr) + Cursor,
      Address, Size, Comment + ' = ' + UString), SubComment);
  Inc(Cursor, Size);
  if Cursor >= MaxSize then
    Abort;
end;

procedure AddString(var OutValue: string; const Comment: string; Address: Pointer;
  DataType: TDataType; var Cursor: NativeUInt;
  const SubComment: string = ''); overload;
begin
  case DataType of
    dtByte: AddString(OutValue, Comment, Address, DataType, 1, Cursor, SubComment);
    dtWord: AddString(OutValue, Comment, Address, DataType, 2, Cursor, SubComment);
    dtDword: AddString(OutValue, Comment, Address, DataType, 4, Cursor, SubComment);
    dtInt64: AddString(OutValue, Comment, Address, DataType, 8, Cursor, SubComment);
    dtGUID: AddString(OutValue, Comment, Address, DataType, 16, Cursor, SubComment);
    dtUnicodeString32: AddString(OutValue, Comment, Address, DataType, 8, Cursor, SubComment);
    dtUnicodeString64: AddString(OutValue, Comment, Address, DataType, 16, Cursor, SubComment);
  end;
end;

function DumpMemory(Process: THandle; Address: Pointer; nSize: Integer): string;
var
  Buff: TMemoryDump;
  RegionSize: NativeUInt;
  Data: TSymbolData;
begin
  Result := '';
  if nSize = 0 then
  begin
    MaxSize := 4096;
    // смотрим, известен ли размер страницы?
    if SymbolStorage.GetDataAtAddr(UInt64(Address), Data) then
      case Data.DataType of
        // если известен, запрашиваем столько, сколько требуется
        sdtCtxProcess, sdtCtxSystem:
          MaxSize := Data.Ctx.TotalSize
      end;
  end
  else
    MaxSize := nSize;
  SetLength(Buff, MaxSize);
  if not ReadProcessData(Process, Address, @Buff[0],
    MaxSize, RegionSize, rcReadAllwais) then Exit;
  Result := DumpMemoryFromBuff(Process, Address, Buff, MaxSize);
end;

function DumpMemoryFromBuff(Process: THandle; Address: Pointer;
  RawBuff: TMemoryDump; nSize: Integer): string;
begin
  if Length(RawBuff) > nSize then
    SetLength(RawBuff, nSize);
  CurerntAddr := Address;
  DumpMemoryFromBuffWithCheckRawData(Result, Process, Address, RawBuff, 0);
end;

function PebBitFieldToStr(Value: Byte): string;

  procedure AddToResult(const Value: string);
  begin
    if Result = '' then
      Result := Value
    else
      Result := Result + ', ' + Value;
  end;

begin
  if Value and 1 <> 0 then AddToResult('ImageUsesLargePages');
  if Value and 2 <> 0 then AddToResult('IsProtectedProcess');
  if Value and 4 <> 0 then AddToResult('IsLegacyProcess');
  if Value and 8 <> 0 then AddToResult('IsImageDynamicallyRelocated');
  if Value and 16 <> 0 then AddToResult('SkipPatchingUser32Forwarders');
  if Value and 32 <> 0 then AddToResult('IsPackagedProcess');
  if Value and 64 <> 0 then AddToResult('IsAppContainer');
  Result := 'BitField [' + Result + ']';
end;

function PebTracingFlagsToStr(Value: Byte): string;

  procedure AddToResult(const Value: string);
  begin
    if Result = '' then
      Result := Value
    else
      Result := Result + ', ' + Value;
  end;

begin
  if Value and 1 <> 0 then AddToResult('HeapTracingEnabled');
  if Value and 2 <> 0 then AddToResult('CritSecTracingEnabled');
  if Value and 4 <> 0 then AddToResult('LibLoaderTracingEnabled');
  Result := 'TracingFlags [' + Result + ']';
end;

function ExtractUnicodeString32(Process: THandle; const Buff: TMemoryDump;
  Cursor: NativeUInt): string;
var
  Address: Pointer;
  Size, Dummy: NativeUInt;
begin
  Result := '';
  if Cursor >= MaxSize - 8 then Exit;
  Size := PWord(@Buff[Cursor])^;
  Address := Pointer(PDWORD(@Buff[Cursor + 4])^);
  if Size > 0 then
  begin
    SetLength(Result, Size div 2);
    ReadProcessData(Process, Address, @Result[1],
      Size, Dummy, rcReadAllwais);
  end;
  Result := '[' + IntToHex(ULONG_PTR(Address), 1) + '] "' + PChar(Result) + '"';
end;

function ExtractUnicodeString64(Process: THandle; const Buff: TMemoryDump;
  Cursor: NativeUInt): string;
var
  Address: Pointer;
  Size, Dummy: NativeUInt;
begin
  Result := '';
  if Cursor >= MaxSize - 16 then Exit;
  Size := PDWORD(@Buff[Cursor])^;
  Address := @Buff[Cursor + 8];
  Address := Pointer(Address^);
  if Size > 0 then
  begin
    SetLength(Result, Size div 2);
    ReadProcessData(Process, Address, @Result[1],
      Size, Dummy, rcReadAllwais);
  end;
  Result := '[' + IntToHex(ULONG_PTR(Address), 1) + '] "' + PChar(Result) + '"';
end;

function ExtractPPVoidData32(Process: THandle; Address: Pointer): string;
var
  Data: Pointer;
  Size, Dummy: NativeUInt;
begin
  Size := 4;
  Address := Pointer(PDWORD(Address)^);
  if Address = nil then Exit('[NULL] "NULL"');
  Data := nil;
  if not ReadProcessData(Process, Address, @Data,
    Size, Dummy, rcReadAllwais) then
    Exit('[' + IntToHex(ULONG_PTR(Address), 1) + ']');
  if Data = nil then
    Result := '[' + IntToHex(ULONG_PTR(Address), 1) + '] "NULL"'
  else
    Result := '[' + IntToHex(ULONG_PTR(Address), 1) + '] "' +
      IntToHex(ULONG_PTR(Data), 1) + '"';
end;

function ExtractPPVoidData64(Process: THandle; Address: Pointer): string;
var
  Data: Pointer;
  Size, Dummy: NativeUInt;
begin
  Size := 8;
  Address := Pointer(Address^);
  if Address = nil then Exit('[NULL] "NULL"');
  if not ReadProcessData(Process, Address, @Data,
    Size, Dummy, rcReadAllwais) then
    Exit('[' + IntToHex(ULONG_PTR(Address), 1) + ']');
  if Data = nil then
    Result := '[' + IntToHex(ULONG_PTR(Address), 1) + '] "NULL"'
  else
    Result := '[' + IntToHex(ULONG_PTR(Address), 1) + '] "' +
      IntToHex(ULONG_PTR(Data), 1) + '"';
end;

function CrossProcessFlagsToStr(Value: ULONG): string;

  procedure AddToResult(const Value: string);
  begin
    if Result = '' then
      Result := Value
    else
      Result := Result + '|' + Value;
  end;

begin
  Result := '';
  if Value and 1 <> 0 then AddToResult('ProcessInJob');
  if Value and 2 <> 0 then AddToResult('ProcessInitializing');
  if Value and 4 <> 0 then AddToResult('ProcessUsingVEH');
  if Value and 8 <> 0 then AddToResult('ProcessUsingVCH');
end;

function DumpPEB32(Process: THandle; Address: Pointer): string;
var
  Buff: TMemoryDump;
  Dummy, Cursor: NativeUInt;
  ValueBuff: DWORD;
begin
  Result := '';
  CurerntAddr := Address;
  MaxSize := 4096;
  SetLength(Buff, MaxSize);
  if not ReadProcessData(Process, Address, @Buff[0],
    MaxSize, Dummy, rcReadAllwais) then Exit;
  Cursor := 0;
  AddString(Result, PEBHeader32);
  AddString(Result, 'InheritedAddressSpace', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'ReadImageFileExecOptions', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'BeingDebugged', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, PebBitFieldTostr(Buff[Cursor]), @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'Mutant', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ImageBaseAddress', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'LoaderData', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ProcessParameters', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'SubSystemData', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ProcessHeap', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'FastPebLock', @Buff[Cursor], dtDword, Cursor);

  if IsLonghornOrHigher then
  begin
    AddString(Result, 'AtlThunkSListPtr', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'IFEOKey', @Buff[Cursor], dtDword, Cursor);
    ValueBuff := PULONG(@Buff[Cursor])^;
    AddString(Result, 'CrossProcessFlags', @Buff[Cursor], dtDword, Cursor,
      CrossProcessFlagsToStr(ValueBuff));
    AddString(Result, 'UserSharedInfoPtr', @Buff[Cursor], dtDword, Cursor);
  end
  else
    if IsW2003OrHigher then
    begin
      AddString(Result, 'AtlThunkSListPtr', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'SparePtr2', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'EnvironmentUpdateCount', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'KernelCallbackTable', @Buff[Cursor], dtDword, Cursor);
    end
    else
    begin
      AddString(Result, 'FastPebLockRoutine', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'FastPebUnlockRoutine', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'EnvironmentUpdateCount', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'KernelCallbackTable', @Buff[Cursor], dtDword, Cursor);
    end;

  AddString(Result, 'SystemReserved', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'AtlThunkSListPtr32', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ApiSetMap', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TlsExpansionCounter', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TlsBitmap', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TlsBitmapBits[0]', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TlsBitmapBits[1]', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ReadOnlySharedMemoryBase', @Buff[Cursor], dtDword, Cursor);

  if IsLonghornOrHigher then
    AddString(Result, 'HotpatchInformation', @Buff[Cursor], dtDword, Cursor)
  else
    AddString(Result, 'ReadOnlySharedMemoryHeap', @Buff[Cursor], dtDword, Cursor);

  AddString(Result, 'ReadOnlyStaticServerData = ' + ExtractPPVoidData32(Process, @Buff[Cursor]),
    @Buff[Cursor], dtBuff, 4, Cursor);
  AddString(Result, 'AnsiCodePageData', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'OemCodePageData', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'UnicodeCaseTableData', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'KeNumberOfProcessors', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NtGlobalFlag', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
  AddString(Result, 'CriticalSectionTimeout', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'HeapSegmentReserve', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'HeapSegmentCommit', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'HeapDeCommitTotalFreeThreshold', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'HeapDeCommitFreeBlockThreshold', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NumberOfHeaps', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'MaximumNumberOfHeaps', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ProcessHeaps = ' + ExtractPPVoidData32(Process, @Buff[Cursor]),
    @Buff[Cursor], dtBuff, 4, Cursor);
  AddString(Result, 'GdiSharedHandleTable', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ProcessStarterHelper', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'GdiDCAttributeList', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'LoaderLock', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NtMajorVersion', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NtMinorVersion', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NtBuildNumber', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'NtCSDVersion', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'PlatformId', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Subsystem', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'MajorSubsystemVersion', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'MinorSubsystemVersion', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'AffinityMask', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'GdiHandleBuffer', @Buff[Cursor], dtBuff, 136, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'PostProcessInitRoutine', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TlsExpansionBitmap', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'TlsExpansionBitmapBits', @Buff[Cursor], dtBuff, 128, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'SessionId', @Buff[Cursor], dtDword, Cursor);

  if IsXPOrHigher then
  begin
    AddString(Result, 'AppCompatFlags', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'AppCompatFlagsUser', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'pShimData', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'AppCompatInfo', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'CSDVersion = ' + ExtractUnicodeString32(Process, Buff, Cursor),
      @Buff[Cursor], dtUnicodeString32, Cursor);
    AddString(Result, 'ActivationContextData', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'ProcessAssemblyStorageMap', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'SystemDefaultActivationContextData', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'SystemAssemblyStorageMap', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'MinimumStackCommit', @Buff[Cursor], dtDword, Cursor);
  end;

  if IsW2003OrHigher then
  begin
    AddString(Result, 'FlsCallback = ' + ExtractPPVoidData32(Process, @Buff[Cursor]),
      @Buff[Cursor], dtBuff, 4, Cursor);
    AddString(Result, 'FlsListHead.FLink', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'FlsListHead.BLink', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'FlsBitmap', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, EmptyHeader);
    AddString(Result, 'FlsBitmapBits[0]', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'FlsBitmapBits[1]', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'FlsBitmapBits[2]', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'FlsBitmapBits[3]', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, EmptyHeader);
    AddString(Result, 'FlsHighIndex', @Buff[Cursor], dtDword, Cursor);
  end;

  if IsLonghornOrHigher then
  begin
    AddString(Result, 'WerRegistrationData', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'WerShipAssertPtr', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'pContextData', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'pImageHeaderHash', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, PebTracingFlagsToStr(Buff[Cursor]), @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
    AddString(Result, 'CsrServerReadOnlySharedMemoryBase', @Buff[Cursor], dtInt64, Cursor);
  end;

  DumpMemoryFromBuffWithCheckRawData(Result, Process, Address, Buff, Cursor);
end;

function DumpPEB64(Process: THandle; Address: Pointer): string;
var
  Buff: TMemoryDump;
  RegionSize, Cursor: NativeUInt;
  ValueBuff: DWORD;
begin
  Result := '';
  CurerntAddr := Address;
  MaxSize := 4096;
  SetLength(Buff, MaxSize);
  if not ReadProcessData(Process, Address, @Buff[0],
    MaxSize, RegionSize, rcReadAllwais) then Exit;
  Cursor := 0;
  AddString(Result, PEBHeader64);
  AddString(Result, 'InheritedAddressSpace', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'ReadImageFileExecOptions', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'BeingDebugged', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, PebBitFieldTostr(Buff[Cursor]), @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
  AddString(Result, 'Mutant', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ImageBaseAddress', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'LoaderData', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ProcessParameters', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'SubSystemData', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ProcessHeap', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'FastPebLock', @Buff[Cursor], dtInt64, Cursor);

  if IsLonghornOrHigher then
  begin
    AddString(Result, 'AtlThunkSListPtr', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'IFEOKey', @Buff[Cursor], dtInt64, Cursor);
    ValueBuff := PULONG(@Buff[Cursor])^;
    AddString(Result, 'CrossProcessFlags', @Buff[Cursor], dtDword, Cursor,
      CrossProcessFlagsToStr(ValueBuff));
    AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
    AddString(Result, 'UserSharedInfoPtr', @Buff[Cursor], dtInt64, Cursor);
  end
  else
    if IsW2003OrHigher then
    begin
      AddString(Result, 'AtlThunkSListPtr', @Buff[Cursor], dtInt64, Cursor);
      AddString(Result, 'SparePtr2', @Buff[Cursor], dtInt64, Cursor);
      AddString(Result, 'EnvironmentUpdateCount', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
      AddString(Result, 'KernelCallbackTable', @Buff[Cursor], dtInt64, Cursor);
    end
    else
    begin
      AddString(Result, 'FastPebLockRoutine', @Buff[Cursor], dtInt64, Cursor);
      AddString(Result, 'FastPebUnlockRoutine', @Buff[Cursor], dtInt64, Cursor);
      AddString(Result, 'EnvironmentUpdateCount', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
      AddString(Result, 'KernelCallbackTable', @Buff[Cursor], dtInt64, Cursor);
    end;

  AddString(Result, 'SystemReserved', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'AtlThunkSListPtr32', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ApiSetMap', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'TlsExpansionCounter', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
  AddString(Result, 'TlsBitmap', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'TlsBitmapBits[0]', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TlsBitmapBits[1]', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ReadOnlySharedMemoryBase', @Buff[Cursor], dtInt64, Cursor);

  if IsLonghornOrHigher then
    AddString(Result, 'HotpatchInformation', @Buff[Cursor], dtInt64, Cursor)
  else
    AddString(Result, 'ReadOnlySharedMemoryHeap', @Buff[Cursor], dtInt64, Cursor);

  AddString(Result, 'ReadOnlyStaticServerData = ' + ExtractPPVoidData64(Process, @Buff[Cursor]),
    @Buff[Cursor], dtBuff, 8, Cursor);
  AddString(Result, 'AnsiCodePageData', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'OemCodePageData', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'UnicodeCaseTableData', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'KeNumberOfProcessors', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NtGlobalFlag', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CriticalSectionTimeout', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'HeapSegmentReserve', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'HeapSegmentCommit', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'HeapDeCommitTotalFreeThreshold', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'HeapDeCommitFreeBlockThreshold', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'NumberOfHeaps', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'MaximumNumberOfHeaps', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ProcessHeaps = ' + ExtractPPVoidData64(Process, @Buff[Cursor]),
    @Buff[Cursor], dtBuff, 8, Cursor);
  AddString(Result, 'GdiSharedHandleTable', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ProcessStarterHelper', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'GdiDCAttributeList', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
  AddString(Result, 'LoaderLock', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'NtMajorVersion', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NtMinorVersion', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NtBuildNumber', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'NtCSDVersion', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'PlatformId', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Subsystem', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'MajorSubsystemVersion', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'MinorSubsystemVersion', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
  AddString(Result, 'AffinityMask', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'GdiHandleBuffer', @Buff[Cursor], dtBuff, 240, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'PostProcessInitRoutine', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'TlsExpansionBitmap', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'TlsExpansionBitmapBits', @Buff[Cursor], dtBuff, 128, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'SessionId', @Buff[Cursor], dtDword, Cursor);

  if IsXPOrHigher then
  begin
    AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
    AddString(Result, 'AppCompatFlags', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'AppCompatFlagsUser', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'pShimData', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'AppCompatInfo', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'CSDVersion = ' + ExtractUnicodeString64(Process, Buff, Cursor),
      @Buff[Cursor], dtUnicodeString64, Cursor);
    AddString(Result, 'ActivationContextData', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'ProcessAssemblyStorageMap', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'SystemDefaultActivationContextData', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'SystemAssemblyStorageMap', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'MinimumStackCommit', @Buff[Cursor], dtInt64, Cursor);
  end;

  if IsW2003OrHigher then
  begin
    AddString(Result, 'FlsCallback = ' + ExtractPPVoidData64(Process, @Buff[Cursor]),
      @Buff[Cursor], dtBuff, 8, Cursor);
    AddString(Result, 'FlsListHead.FLink', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'FlsListHead.BLink', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'FlsBitmap', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, EmptyHeader);
    AddString(Result, 'FlsBitmapBits[0]', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'FlsBitmapBits[1]', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'FlsBitmapBits[2]', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'FlsBitmapBits[3]', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, EmptyHeader);
    AddString(Result, 'FlsHighIndex', @Buff[Cursor], dtDword, Cursor);
  end;

  if IsLonghornOrHigher then
  begin
    AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
    AddString(Result, 'WerRegistrationData', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'WerShipAssertPtr', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'pContextData', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'pImageHeaderHash', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, PebTracingFlagsToStr(Buff[Cursor]), @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
    AddString(Result, 'CsrServerReadOnlySharedMemoryBase', @Buff[Cursor], dtInt64, Cursor);
  end;

  DumpMemoryFromBuffWithCheckRawData(Result, Process, Address, Buff, Cursor);
end;

function FileHeaderMachineToStr(Value: Word): string;
begin
  case Value of
    IMAGE_FILE_MACHINE_I386: Result := 'IMAGE_FILE_MACHINE_I386';
    IMAGE_FILE_MACHINE_R3000: Result := 'IMAGE_FILE_MACHINE_R3000';
    IMAGE_FILE_MACHINE_R4000: Result := 'IMAGE_FILE_MACHINE_R4000';
    IMAGE_FILE_MACHINE_R10000: Result := 'IMAGE_FILE_MACHINE_R10000';
    IMAGE_FILE_MACHINE_ALPHA: Result := 'IMAGE_FILE_MACHINE_ALPHA';
    IMAGE_FILE_MACHINE_POWERPC: Result := 'IMAGE_FILE_MACHINE_POWERPC';
    IMAGE_FILE_MACHINE_IA64: Result := 'IMAGE_FILE_MACHINE_IA64';
    IMAGE_FILE_MACHINE_ALPHA64: Result := 'IMAGE_FILE_MACHINE_ALPHA64';
    IMAGE_FILE_MACHINE_AMD64: Result := 'IMAGE_FILE_MACHINE_AMD64';
  else
    Result := 'IMAGE_FILE_MACHINE_UNKNOWN';
  end;
end;

function FileHeaderTimeStampToStr(Value: DWORD): string;
var
  D: TDateTime;
begin
  D := EncodeDateTime(1970, 1, 1, 0, 0, 0, 0);
  D := IncSecond(D, Value);
  Result := DateTimeToStr(D);
end;

function FileHeaderCharacteristicsToStr(Value: Word): string;

  procedure AddResult(const Value: string);
  begin
    if Result = '' then
      Result := Value
    else
      Result := Result + '|' + Value;
  end;

begin
  Result := '';
  if Value and IMAGE_FILE_RELOCS_STRIPPED <> 0 then
    AddResult('RELOCS_STRIPPED');
  if Value and IMAGE_FILE_EXECUTABLE_IMAGE <> 0 then
    AddResult('EXECUTABLE_IMAGE');
  if Value and IMAGE_FILE_LINE_NUMS_STRIPPED <> 0 then
    AddResult('LINE_NUMS_STRIPPED');
  if Value and IMAGE_FILE_LOCAL_SYMS_STRIPPED <> 0 then
    AddResult('LOCAL_SYMS_STRIPPED');
  if Value and IMAGE_FILE_AGGRESIVE_WS_TRIM <> 0 then
    AddResult('AGGRESIVE_WS_TRIM');
  if Value and IMAGE_FILE_LARGE_ADDRESS_AWARE <> 0 then
    AddResult('LARGE_ADDRESS_AWARE');
  if Value and IMAGE_FILE_BYTES_REVERSED_LO <> 0 then
    AddResult('BYTES_REVERSED_LO');
  if Value and IMAGE_FILE_32BIT_MACHINE <> 0 then
    AddResult('32BIT_MACHINE');
  if Value and IMAGE_FILE_DEBUG_STRIPPED <> 0 then
    AddResult('DEBUG_STRIPPED');
  if Value and IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP <> 0 then
    AddResult('REMOVABLE_RUN_FROM_SWAP');
  if Value and IMAGE_FILE_NET_RUN_FROM_SWAP <> 0 then
    AddResult('NET_RUN_FROM_SWAP');
  if Value and IMAGE_FILE_SYSTEM <> 0 then
    AddResult('SYSTEM');
  if Value and IMAGE_FILE_DLL <> 0 then
    AddResult('DLL');
  if Value and IMAGE_FILE_UP_SYSTEM_ONLY <> 0 then
    AddResult('UP_SYSTEM_ONLY');
  if Value and IMAGE_FILE_BYTES_REVERSED_HI <> 0 then
    AddResult('BYTES_REVERSED_HI');
end;

function OptionalHeaderMagicToStr(Value: Word): string;
begin
  case Value of
    IMAGE_NT_OPTIONAL_HDR32_MAGIC: Result := 'IMAGE_NT_OPTIONAL_HDR32_MAGIC';
    IMAGE_NT_OPTIONAL_HDR64_MAGIC: Result := 'IMAGE_NT_OPTIONAL_HDR64_MAGIC';
    IMAGE_ROM_OPTIONAL_HDR_MAGIC: Result := 'IMAGE_ROM_OPTIONAL_HDR_MAGIC';
  else
    Result := '';
  end;
end;

function OptionalHeaderSubsystemToStr(Value: Word): string;
const
  SubsystemsString: array [0..8] of string = (
    'IMAGE_SUBSYSTEM_UNKNOWN',
    'IMAGE_SUBSYSTEM_NATIVE',
    'IMAGE_SUBSYSTEM_WINDOWS_GUI',
    'IMAGE_SUBSYSTEM_WINDOWS_CUI',
    '',
    'IMAGE_SUBSYSTEM_OS2_CUI',
    '',
    'IMAGE_SUBSYSTEM_POSIX_CUI',
    'IMAGE_SUBSYSTEM_RESERVED8');
begin
  if Value in [0..3, 5, 7, 8] then
    Result := SubsystemsString[Value]
  else
    Result := SubsystemsString[0];
end;

function SectionCharacteristicsToStr(Value: DWORD): string;

  procedure AddResult(const Value: string);
  begin
    if Result = '' then
      Result := Value
    else
      Result := Result + '|' + Value;
  end;

begin
  Result := '';
  if Value and IMAGE_SCN_CNT_CODE <> 0 then
    AddResult('CNT_CODE');
  if Value and IMAGE_SCN_CNT_INITIALIZED_DATA <> 0 then
    AddResult('CNT_INITIALIZED_DATA');
  if Value and IMAGE_SCN_CNT_UNINITIALIZED_DATA <> 0 then
    AddResult('CNT_UNINITIALIZED_DATA');
  if Value and IMAGE_SCN_LNK_INFO <> 0 then
    AddResult('LNK_INFO');
  if Value and IMAGE_SCN_LNK_REMOVE <> 0 then
    AddResult('LNK_REMOVE');
  if Value and IMAGE_SCN_LNK_COMDAT <> 0 then
    AddResult('LNK_COMDAT');
  if Value and IMAGE_SCN_MEM_FARDATA <> 0 then
    AddResult('MEM_FARDATA');
  if Value and IMAGE_SCN_MEM_PURGEABLE <> 0 then
    AddResult('MEM_PURGEABLE');
  if Value and IMAGE_SCN_MEM_16BIT <> 0 then
    AddResult('MEM_16BIT');
  if Value and IMAGE_SCN_MEM_LOCKED <> 0 then
    AddResult('MEM_LOCKED');
  if Value and IMAGE_SCN_MEM_PRELOAD <> 0 then
    AddResult('MEM_PRELOAD');
  if Value and IMAGE_SCN_ALIGN_1BYTES <> 0 then
    AddResult('ALIGN_1BYTES');
  if Value and IMAGE_SCN_ALIGN_2BYTES <> 0 then
    AddResult('ALIGN_2BYTES');
  if Value and IMAGE_SCN_ALIGN_4BYTES <> 0 then
    AddResult('ALIGN_4BYTES');
  if Value and IMAGE_SCN_ALIGN_8BYTES <> 0 then
    AddResult('ALIGN_8BYTES');
  if Value and IMAGE_SCN_ALIGN_16BYTES <> 0 then
    AddResult('ALIGN_16BYTES');
  if Value and IMAGE_SCN_ALIGN_32BYTES <> 0 then
    AddResult('ALIGN_32BYTES');
  if Value and IMAGE_SCN_ALIGN_64BYTES <> 0 then
    AddResult('ALIGN_64BYTES');
  if Value and IMAGE_SCN_LNK_NRELOC_OVFL <> 0 then
    AddResult('LNK_NRELOC_OVFL');
  if Value and IMAGE_SCN_MEM_DISCARDABLE <> 0 then
    AddResult('MEM_DISCARDABLE');
  if Value and IMAGE_SCN_MEM_NOT_CACHED <> 0 then
    AddResult('MEM_NOT_CACHED');
  if Value and IMAGE_SCN_MEM_NOT_PAGED <> 0 then
    AddResult('MEM_NOT_PAGED');
  if Value and IMAGE_SCN_MEM_SHARED <> 0 then
    AddResult('MEM_SHARED');
  if Value and IMAGE_SCN_MEM_EXECUTE <> 0 then
    AddResult('MEM_EXECUTE');
  if Value and IMAGE_SCN_MEM_READ <> 0 then
    AddResult('MEM_READ');
  if Value and IMAGE_SCN_MEM_WRITE <> 0 then
    AddResult('MEM_WRITE');
end;

function DumpPEHeader(Process: THandle; Address: Pointer): string;
const
  DataDirectoriesName: array [0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1] of string =
    ('Export', 'Import', 'Resource', 'Exception', 'Security', 'BaseReloc',
    'Debug', 'Copyright', 'GlobalPTR', 'TLS', 'Load config', 'Bound import',
    'Iat', 'Delay import', 'COM', 'Reserved');
var
  Buff: TMemoryDump;
  RegionSize, Cursor: NativeUInt;
  ValueBuff: DWORD;
  Optional32: Boolean;
  I: Integer;
  NumberOfSections: Word;

  procedure DumpDataDirectory(Index: Integer);
  begin
    AddString(Result, DataDirectoriesName[Index] +
      ' Directory Address', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, DataDirectoriesName[Index] +
      ' Directory Size', @Buff[Cursor], dtDword, Cursor);
  end;

  procedure DumpSection;
  begin
    AddString(Result, 'Name', @Buff[Cursor], dtAnsiString, IMAGE_SIZEOF_SHORT_NAME, Cursor);
    AddString(Result, 'VirtualSize', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'VirtualAddress', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'SizeOfRawData', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'PointerToRawData', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'PointerToRelocations', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'PointerToLinenumbers', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'NumberOfRelocations', @Buff[Cursor], dtWord, Cursor);
    AddString(Result, 'NumberOfLinenumbers', @Buff[Cursor], dtWord, Cursor);
    ValueBuff := PDWORD(@Buff[Cursor])^;
    AddString(Result, 'Characteristics', @Buff[Cursor], dtDword, Cursor,
      SectionCharacteristicsToStr(ValueBuff));
  end;

begin
  Result := '';
  CurerntAddr := Address;
  MaxSize := 4096;
  SetLength(Buff, MaxSize);
  if not ReadProcessData(Process, Address, @Buff[0],
    MaxSize, RegionSize, rcReadAllwais) then Exit;
  Cursor := 0;

  // IMAGE_DOS_HEADER
  AddString(Result, PEHeader);
  AddString(Result, 'e_magic', @Buff[Cursor], dtAnsiString, 2, Cursor, 'Magic number');
  AddString(Result, 'e_cblp', @Buff[Cursor], dtWord, Cursor, 'Bytes on last page of file');
  AddString(Result, 'e_cp', @Buff[Cursor], dtWord, Cursor, 'Pages in file');
  AddString(Result, 'e_crlc', @Buff[Cursor], dtWord, Cursor, 'Relocations');
  AddString(Result, 'e_cparhdr', @Buff[Cursor], dtWord, Cursor, 'Size of header in paragraphs');
  AddString(Result, 'e_minalloc', @Buff[Cursor], dtWord, Cursor, 'Minimum extra paragraphs needed');
  AddString(Result, 'e_maxalloc', @Buff[Cursor], dtWord, Cursor, 'Maximum extra paragraphs needed');
  AddString(Result, 'e_ss', @Buff[Cursor], dtWord, Cursor, 'Initial (relative) SS value');
  AddString(Result, 'e_sp', @Buff[Cursor], dtWord, Cursor, 'Initial SP value');
  AddString(Result, 'e_csum', @Buff[Cursor], dtWord, Cursor, 'Checksum');
  AddString(Result, 'e_ip', @Buff[Cursor], dtWord, Cursor, 'Initial IP value');
  AddString(Result, 'e_cs', @Buff[Cursor], dtWord, Cursor, 'Initial (relative) CS value');
  AddString(Result, 'e_lfarlc', @Buff[Cursor], dtWord, Cursor, 'File address of relocation table');
  AddString(Result, 'e_ovno', @Buff[Cursor], dtWord, Cursor, 'Overlay number');
  AddString(Result, 'e_res', @Buff[Cursor], dtBuff, 8, Cursor, 'Reserved words');
  AddString(Result, 'e_oemid', @Buff[Cursor], dtWord, Cursor, 'OEM identifier (for e_oeminfo)');
  AddString(Result, 'e_oeminfo', @Buff[Cursor], dtWord, Cursor, 'OEM information; e_oemid specific');
  AddString(Result, 'e_res2', @Buff[Cursor], dtBuff, 20, Cursor, 'Reserved words');
  ValueBuff := PLongInt(@Buff[Cursor])^;
  AddString(Result, '_lfanew', @Buff[Cursor], dtDword, Cursor, 'File address of new exe header');

  AddString(Result, EmptyHeader);
  AddString(Result, ByteToHexStr(ULONG_PTR(Address) + Cursor, @Buff[Cursor],
    ValueBuff - SizeOf(TImageDosHeader)));


  // IMAGE_NT_HEADERS
  Cursor := ValueBuff;
  AddString(Result, NT_HEADERS);
  AddString(Result, 'Signature', @Buff[Cursor], dtAnsiString, 4, Cursor);

  // IMAGE_FILE_HEADER
  AddString(Result, FILE_HEADER);
  ValueBuff := PWord(@Buff[Cursor])^;
  AddString(Result, 'Machine', @Buff[Cursor], dtWord, Cursor,
    FileHeaderMachineToStr(ValueBuff));
  NumberOfSections := PWord(@Buff[Cursor])^;
  AddString(Result, 'NumberOfSections', @Buff[Cursor], dtWord, Cursor);
  ValueBuff := PDWORD(@Buff[Cursor])^;
  AddString(Result, 'TimeDateStamp', @Buff[Cursor], dtDword, Cursor,
    FileHeaderTimeStampToStr(ValueBuff));
  AddString(Result, 'PointerToSymbolTable', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NumberOfSymbols', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'SizeOfOptionalHeader', @Buff[Cursor], dtWord, Cursor);
  ValueBuff := PWord(@Buff[Cursor])^;
  AddString(Result, 'Characteristics', @Buff[Cursor], dtWord, Cursor,
    FileHeaderCharacteristicsToStr(ValueBuff));

  // IMAGE_OPTIONAL_HEADER_XX
  ValueBuff := PWord(@Buff[Cursor])^;
  Optional32 := ValueBuff = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  if Optional32 then
    AddString(Result, OPTIONAL_HEADER32)
  else
    AddString(Result, OPTIONAL_HEADER64);
  AddString(Result, 'Magic', @Buff[Cursor], dtWord, Cursor,
    OptionalHeaderMagicToStr(ValueBuff));
  AddString(Result, 'MajorLinkerVersion', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'MinorLinkerVersion', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'SizeOfCode', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'SizeOfInitializedData', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'SizeOfUninitializedData', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'AddressOfEntryPoint', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'BaseOfCode', @Buff[Cursor], dtDword, Cursor);
  if Optional32 then
  begin
    AddString(Result, 'BaseOfData', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'ImageBase', @Buff[Cursor], dtDword, Cursor);
  end
  else
    AddString(Result, 'ImageBase', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'SectionAlignment', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'FileAlignment', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'MajorOperatingSystemVersion', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'MinorOperatingSystemVersion', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'MajorImageVersion', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'MinorImageVersion', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'MajorSubsystemVersion', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'MinorSubsystemVersion', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'Win32VersionValue', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'SizeOfImage', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'SizeOfHeaders', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CheckSum', @Buff[Cursor], dtDword, Cursor);
  ValueBuff := PWord(@Buff[Cursor])^;
  AddString(Result, 'Subsystem', @Buff[Cursor], dtWord, Cursor,
    OptionalHeaderSubsystemToStr(ValueBuff));
  AddString(Result, 'DllCharacteristics', @Buff[Cursor], dtWord, Cursor);
  if Optional32 then
  begin
    AddString(Result, 'SizeOfStackReserve', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'SizeOfStackCommit', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'SizeOfHeapReserve', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'SizeOfHeapCommit', @Buff[Cursor], dtDword, Cursor);
  end
  else
  begin
    AddString(Result, 'SizeOfStackReserve', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'SizeOfStackCommit', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'SizeOfHeapReserve', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'SizeOfHeapCommit', @Buff[Cursor], dtInt64, Cursor);
  end;
  AddString(Result, 'LoaderFlags', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NumberOfRvaAndSizes', @Buff[Cursor], dtDword, Cursor);

  // IMAGE_DATA_DIRECTORY
  AddString(Result, DATA_DIRECTORY);
  for I := 0 to IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1 do
    DumpDataDirectory(I);

  // IMAGE_SECTION_HEADERS
  AddString(Result, SECTION_HEADERS);
  for I := 0 to NumberOfSections - 1 do
  begin
    if I > 0 then
      AddString(Result, EmptyHeader);
    DumpSection;
  end;

  // Остальные данные
  DumpMemoryFromBuffWithCheckRawData(Result, Process, Address, Buff, Cursor);
end;

function SameTebFlagsToStr(Value: Word): string;
const
  SameTebFlags: array [0..11] of string = (
    'SafeThunkCall', 'InDebugPrint', 'HasFiberData', 'SkipThreadAttach',
    'WerInShipAssertCode', 'RanProcessInit', 'ClonedThread', 'SuppressDebugMsg',
    'DisableUserStackWalk', 'RtlExceptionAttached', 'InitialThread', 'SessionAware');

  procedure AddResult(const Value: string);
  begin
    if Result = '' then
      Result := Value
    else
      Result := Result + '|' + Value;
  end;

var
  I: Integer;
begin
  Result := '';
  for I := 0 to 11 do
    if Value and (1 shl I) <> 0 then
      AddResult(SameTebFlags[I]);
end;

function DumpThread64(Process: THandle; Address: Pointer): string;
var
  Buff: TMemoryDump;
  Size, RegionSize, Cursor: NativeUInt;
  ValueBuff: DWORD;
begin
  Result := '';
  CurerntAddr := Address;
  Size := 8192;
  SetLength(Buff, Size);
  if not ReadProcessData(Process, Address, @Buff[0],
    Size, RegionSize, rcReadAllwais) then Exit;
  Cursor := 0;
  AddString(Result, TIB64_Header);
  AddString(Result, 'ExceptionList', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'StackBase', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'StackLimit', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'SubSystemTib', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'FiberData', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ArbitraryUserPointer', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'Self', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, TEB64_Header);
  Assert(Cursor = $38);
  AddString(Result, 'EnvironmentPointer', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ClientId.UniqueProcess', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ClientId.UniqueThread', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ActiveRpcHandle', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ThreadLocalStoragePointer', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ProcessEnvironmentBlock', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'LastErrorValue', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CountOfOwnedCriticalSections', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CsrClientThread', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'Win32ThreadInfo', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'User32Reserved', @Buff[Cursor], dtBuff, 26 * SizeOf(ULONG), Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'UserReserved', @Buff[Cursor], dtBuff, 5 * SizeOf(ULONG), Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'WOW32Reserved', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'CurrentLocale', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'FpSoftwareStatusRegister', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'SystemReserved1', @Buff[Cursor], dtBuff, 54 * SizeOf(Pointer), Cursor);
  AddString(Result, EmptyHeader);
  Assert(Cursor = $2C0);
  AddString(Result, 'ExceptionCode', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);

  if IsLonghornOrHigher then
  begin
    AddString(Result, 'ActivationContextStackPointer', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, EmptyHeader);
    AddString(Result, 'SpareBytes', @Buff[Cursor], dtBuff, $30 - 3 * SizeOf(Pointer), Cursor);
    AddString(Result, EmptyHeader);
    AddString(Result, 'TxFsContext', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
  end
  else
    if IsW2003OrHigher then
    begin
      AddString(Result, 'ActivationContextStackPointer', @Buff[Cursor], dtInt64, Cursor);
      AddString(Result, EmptyHeader);
      AddString(Result, 'SpareBytes', @Buff[Cursor], dtBuff, $34 - 3 * SizeOf(Pointer), Cursor);
      AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
      AddString(Result, EmptyHeader);
    end
    else
    begin
      AddString(Result, 'ActivationContextStack.Flags', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'ActivationContextStack.NextCookieSequenceNumber', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'ActivationContextStack.ActiveFrame', @Buff[Cursor], dtInt64, Cursor);
      AddString(Result, 'ActivationContextStack.FrameListCache.FLink', @Buff[Cursor], dtInt64, Cursor);
      AddString(Result, 'ActivationContextStack.FrameListCache.BLink', @Buff[Cursor], dtInt64, Cursor);
      AddString(Result, EmptyHeader);
      AddString(Result, 'SpareBytes', @Buff[Cursor], dtBuff, 8, Cursor);
      AddString(Result, EmptyHeader);
    end;

  Assert(Cursor = $2F0);
  AddString(Result, 'GdiTebBatch.Offset', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
  AddString(Result, 'GdiTebBatch.HDC', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'GdiTebBatch.Buffer', @Buff[Cursor], dtBuff, $136 * SizeOf(ULONG), Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'RealClientId.UniqueProcess', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'RealClientId.UniqueThread', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'GdiCachedProcessHandle', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'GdiClientPID', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'GdiClientTID', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'GdiThreadLocalInfo', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'Win32ClientInfo', @Buff[Cursor], dtBuff, 62 * SizeOf(SIZE_T), Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'glDispatchTable', @Buff[Cursor], dtBuff, 233 * SizeOf(PVOID), Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'glReserved1', @Buff[Cursor], dtBuff, 29 * SizeOf(SIZE_T), Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'glReserved2', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'glSectionInfo', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'glSection', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'glTable', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'glCurrentRC', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'glContext', @Buff[Cursor], dtInt64, Cursor);
  Assert(Cursor = $1250);
  AddString(Result, 'LastStatusValue', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);
  AddString(Result, 'StaticUnicodeString = ' + ExtractUnicodeString64(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'StaticUnicodeBuffer', @Buff[Cursor], dtBuff, 261 * SizeOf(WCHAR), Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 6, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'DeallocationStack', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'TlsSlots', @Buff[Cursor], dtBuff, 64 * SizeOf(PVOID), Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'TlsLinks.FLink', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'TlsLinks.BLink', @Buff[Cursor], dtInt64, Cursor);
  Assert(Cursor = $1690);
  AddString(Result, 'Vdm', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ReservedForNtRpc', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'DbgSsReserved[0]', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'DbgSsReserved[1]', @Buff[Cursor], dtInt64, Cursor);

  if IsW2003OrHigher then
    AddString(Result, 'HardErrorMode', @Buff[Cursor], dtDword, Cursor)
  else
    AddString(Result, 'HardErrorsAreDisabled', @Buff[Cursor], dtDword, Cursor);

  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);

  AddString(Result, EmptyHeader);
  if IsLonghornOrHigher then
  begin
    AddString(Result, 'Instrumentation', @Buff[Cursor], dtBuff,
      (13 - SizeOf(TGUID) div SizeOf(Pointer)) * SizeOf(Pointer), Cursor);
    AddString(Result, EmptyHeader);
    AddString(Result, 'ActivityId', @Buff[Cursor], dtGUID, Cursor);
    AddString(Result, 'SubProcessTag', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'EtwLocalData', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'EtwTraceData', @Buff[Cursor], dtInt64, Cursor);
  end
  else
    if IsW2003OrHigher then
    begin
      AddString(Result, 'Instrumentation', @Buff[Cursor], dtBuff,
        14 * SizeOf(Pointer), Cursor);
      AddString(Result, EmptyHeader);
      AddString(Result, 'SubProcessTag', @Buff[Cursor], dtInt64, Cursor);
      AddString(Result, 'EtwLocalData', @Buff[Cursor], dtInt64, Cursor);
    end
    else
    begin
      AddString(Result, 'Instrumentation', @Buff[Cursor], dtBuff,
        16 * SizeOf(Pointer), Cursor);
      AddString(Result, EmptyHeader);
    end;

  AddString(Result, 'WinSockData', @Buff[Cursor], dtInt64, Cursor);

  Assert(Cursor = $1740);
  AddString(Result, 'GdiBatchCount', @Buff[Cursor], dtDword, Cursor);

  if IsLonghornOrHigher then
  begin
    AddString(Result, 'SpareBool0', @Buff[Cursor], dtByte, Cursor);
    AddString(Result, 'SpareBool1', @Buff[Cursor], dtByte, Cursor);
    AddString(Result, 'SpareBool2', @Buff[Cursor], dtByte, Cursor);
  end
  else
  begin
    AddString(Result, 'InDbgPrint', @Buff[Cursor], dtByte, Cursor);
    AddString(Result, 'FreeStackOnTermination', @Buff[Cursor], dtByte, Cursor);
    AddString(Result, 'HasFiberData', @Buff[Cursor], dtByte, Cursor);
  end;

  Assert(Cursor = $1747);
  AddString(Result, 'IdealProcessor', @Buff[Cursor], dtByte, Cursor);

  if IsW2003OrHigher then
    AddString(Result, 'GuaranteedStackBytes', @Buff[Cursor], dtDword, Cursor)
  else
    AddString(Result, 'Spare3', @Buff[Cursor], dtDword, Cursor);

  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);

  AddString(Result, 'ReservedForPerf', @Buff[Cursor], dtInt64, Cursor);
  Assert(Cursor = $1758);
  AddString(Result, 'ReservedForOle', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'WaitingOnLoaderLock', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);

  if IsLonghornOrHigher then
  begin
    AddString(Result, 'SavedPriorityState', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'SoftPatchPtr1', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'ThreadPoolData', @Buff[Cursor], dtInt64, Cursor);
  end
  else
    if IsW2003OrHigher then
    begin
      AddString(Result, 'SparePointer1', @Buff[Cursor], dtInt64, Cursor);
      AddString(Result, 'SoftPatchPtr1', @Buff[Cursor], dtInt64, Cursor);
      AddString(Result, 'SoftPatchPtr2', @Buff[Cursor], dtInt64, Cursor);
    end
    else
    begin
      AddString(Result, 'Wx86Thread.CallBx86Eip', @Buff[Cursor], dtInt64, Cursor);
      AddString(Result, 'Wx86Thread.DeallocationCpu', @Buff[Cursor], dtInt64, Cursor);
      AddString(Result, 'Wx86Thread.UseKnownWx86Dll', @Buff[Cursor], dtByte, Cursor);
      AddString(Result, 'Wx86Thread.OleStubInvoked', @Buff[Cursor], dtByte, Cursor);
      AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 6, Cursor);
    end;

  Assert(Cursor = $1780);
  AddString(Result, 'TlsExpansionSlots = ' + ExtractPPVoidData64(Process, @Buff[Cursor]),
    @Buff[Cursor], dtBuff, 8, Cursor);

  AddString(Result, 'DeallocationBStore', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'BStoreLimit', @Buff[Cursor], dtInt64, Cursor);

  AddString(Result, 'ImpersonationLocale', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'IsImpersonating', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NlsCache', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'pShimData', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'HeapVirtualAffinity', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);

  AddString(Result, 'CurrentTransactionHandle', @Buff[Cursor], dtInt64, Cursor);
  Assert(Cursor = $17C0);
  AddString(Result, 'ActiveFrame', @Buff[Cursor], dtInt64, Cursor);

  if IsW2003OrHigher then
    AddString(Result, 'FlsData', @Buff[Cursor], dtInt64, Cursor);

  if IsLonghornOrHigher then
  begin
    AddString(Result, 'PreferredLanguages', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'UserPrefLanguages', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'MergedPrefLanguages', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'MuiImpersonation', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'CrossTebFlags', @Buff[Cursor], dtWord, Cursor);
    ValueBuff := PDWORD(@Buff[Cursor])^;
    AddString(Result, 'SameTebFlags', @Buff[Cursor], dtWord, Cursor,
      SameTebFlagsToStr(ValueBuff));
    AddString(Result, 'TxnScopeEnterCallback', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'TxnScopeExitCallback', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'TxnScopeContext', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'LockCount', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'ProcessRundown', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'LastSwitchTime', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'TotalSwitchOutTime', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'WaitReasonBitMap', @Buff[Cursor], dtInt64, Cursor);
  end
  else
  begin
    AddString(Result, 'SafeThunkCall', @Buff[Cursor], dtByte, Cursor);
    AddString(Result, 'BooleanSpare', @Buff[Cursor], dtBuff, 3, Cursor);
  end;

  AddString(Result, MemoryDumpHeader);
  AddString(Result, ByteToHexStr(ULONG_PTR(Address) + Cursor, @Buff[Cursor], Size - Cursor));
end;

function DumpThread32(Process: THandle; Address: Pointer): string;
var
  Buff: TMemoryDump;
  RegionSize, Cursor: NativeUInt;
  ValueBuff: DWORD;
begin
  Result := '';
  CurerntAddr := Address;
  MaxSize := 4096;
  SetLength(Buff, MaxSize);
  if not ReadProcessData(Process, Address, @Buff[0],
    MaxSize, RegionSize, rcReadAllwais) then Exit;
  Cursor := 0;
  AddString(Result, TIB32_Header);
  AddString(Result, 'ExceptionList', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'StackBase', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'StackLimit', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'SubSystemTib', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'FiberData', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ArbitraryUserPointer', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Self', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, TEB32_Header);
  Assert(Cursor = $1C);
  AddString(Result, 'EnvironmentPointer', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ClientId.UniqueProcess', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ClientId.UniqueThread', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ActiveRpcHandle', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ThreadLocalStoragePointer', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ProcessEnvironmentBlock', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'LastErrorValue', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CountOfOwnedCriticalSections', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CsrClientThread', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Win32ThreadInfo', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'User32Reserved', @Buff[Cursor], dtBuff, 104, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'UserReserved', @Buff[Cursor], dtBuff, 20, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'WOW32Reserved', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CurrentLocale', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'FpSoftwareStatusRegister', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'SystemReserved1', @Buff[Cursor], dtBuff, 216, Cursor);
  AddString(Result, EmptyHeader);
  Assert(Cursor = $1A4);
  AddString(Result, 'ExceptionCode', @Buff[Cursor], dtDword, Cursor);

  if IsLonghornOrHigher then
  begin
    AddString(Result, 'ActivationContextStackPointer', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, EmptyHeader);
    AddString(Result, 'SpareBytes', @Buff[Cursor], dtBuff, $30 - 3 * SizeOf(Pointer32), Cursor);
    AddString(Result, EmptyHeader);
    AddString(Result, 'TxFsContext', @Buff[Cursor], dtDword, Cursor);
  end
  else
    if IsW2003OrHigher then
    begin
      AddString(Result, 'ActivationContextStackPointer', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, EmptyHeader);
      AddString(Result, 'SpareBytes', @Buff[Cursor], dtBuff, $34 - 3 * SizeOf(Pointer32), Cursor);
      AddString(Result, EmptyHeader);
    end
    else
    begin
      AddString(Result, 'ActivationContextStack.Flags', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'ActivationContextStack.NextCookieSequenceNumber', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'ActivationContextStack.ActiveFrame', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'ActivationContextStack.FrameListCache.FLink', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'ActivationContextStack.FrameListCache.BLink', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, EmptyHeader);
      AddString(Result, 'SpareBytes', @Buff[Cursor], dtBuff, 24, Cursor);
      AddString(Result, EmptyHeader);
    end;

  Assert(Cursor = $1D4);
  AddString(Result, 'GdiTebBatch.Offset', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'GdiTebBatch.HDC', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'GdiTebBatch.Buffer', @Buff[Cursor], dtBuff, $136 * SizeOf(ULONG), Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'RealClientId.UniqueProcess', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'RealClientId.UniqueThread', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'GdiCachedProcessHandle', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'GdiClientPID', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'GdiClientTID', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'GdiThreadLocalInfo', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'Win32ClientInfo', @Buff[Cursor], dtBuff, 248, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'glDispatchTable', @Buff[Cursor], dtBuff, 932, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'glReserved1', @Buff[Cursor], dtBuff, 116, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'glReserved2', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'glSectionInfo', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'glSection', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'glTable', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'glCurrentRC', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'glContext', @Buff[Cursor], dtDword, Cursor);
  Assert(Cursor = $BF4);
  AddString(Result, 'LastStatusValue', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'StaticUnicodeString = ' + ExtractUnicodeString32(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'StaticUnicodeBuffer', @Buff[Cursor], dtBuff, 524, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'DeallocationStack', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'TlsSlots', @Buff[Cursor], dtBuff, 256, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'TlsLinks.FLink', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TlsLinks.BLink', @Buff[Cursor], dtDword, Cursor);
  Assert(Cursor = $F18);
  AddString(Result, 'Vdm', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ReservedForNtRpc', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'DbgSsReserved', @Buff[Cursor], dtInt64, Cursor);

  if IsW2003OrHigher then
    AddString(Result, 'HardErrorMode', @Buff[Cursor], dtDword, Cursor)
  else
    AddString(Result, 'HardErrorsAreDisabled', @Buff[Cursor], dtDword, Cursor);

  AddString(Result, EmptyHeader);
  if IsLonghornOrHigher then
  begin
    AddString(Result, 'Instrumentation', @Buff[Cursor], dtBuff,
      (13 - SizeOf(TGUID) div SizeOf(Pointer32)) * SizeOf(Pointer32), Cursor);
    AddString(Result, EmptyHeader);
    AddString(Result, 'ActivityId', @Buff[Cursor], dtGUID, Cursor);
    AddString(Result, 'SubProcessTag', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'EtwLocalData', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'EtwTraceData', @Buff[Cursor], dtDword, Cursor);
  end
  else
    if IsW2003OrHigher then
    begin
      AddString(Result, 'Instrumentation', @Buff[Cursor], dtBuff,
        14 * SizeOf(Pointer32), Cursor);
      AddString(Result, EmptyHeader);
      AddString(Result, 'SubProcessTag', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'EtwLocalData', @Buff[Cursor], dtDword, Cursor);
    end
    else
    begin
      AddString(Result, 'Instrumentation', @Buff[Cursor], dtBuff,
        16 * SizeOf(Pointer32), Cursor);
      AddString(Result, EmptyHeader);
    end;

  AddString(Result, 'WinSockData', @Buff[Cursor], dtDword, Cursor);

  Assert(Cursor = $F70);
  AddString(Result, 'GdiBatchCount', @Buff[Cursor], dtDword, Cursor);

  if IsLonghornOrHigher then
  begin
    AddString(Result, 'SpareBool0', @Buff[Cursor], dtByte, Cursor);
    AddString(Result, 'SpareBool1', @Buff[Cursor], dtByte, Cursor);
    AddString(Result, 'SpareBool2', @Buff[Cursor], dtByte, Cursor);
  end
  else
  begin
    AddString(Result, 'InDbgPrint', @Buff[Cursor], dtByte, Cursor);
    AddString(Result, 'FreeStackOnTermination', @Buff[Cursor], dtByte, Cursor);
    AddString(Result, 'HasFiberData', @Buff[Cursor], dtByte, Cursor);
  end;

  AddString(Result, 'IdealProcessor', @Buff[Cursor], dtByte, Cursor);

  if IsW2003OrHigher then
    AddString(Result, 'GuaranteedStackBytes', @Buff[Cursor], dtDword, Cursor)
  else
    AddString(Result, 'Spare3', @Buff[Cursor], dtDword, Cursor);

  AddString(Result, 'ReservedForPerf', @Buff[Cursor], dtDword, Cursor);
  Assert(Cursor = $F80);
  AddString(Result, 'ReservedForOle', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'WaitingOnLoaderLock', @Buff[Cursor], dtDword, Cursor);

  if IsLonghornOrHigher then
  begin
    AddString(Result, 'SavedPriorityState', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'SoftPatchPtr1', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'ThreadPoolData', @Buff[Cursor], dtDword, Cursor);
  end
  else
    if IsW2003OrHigher then
    begin
      AddString(Result, 'SparePointer1', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'SoftPatchPtr1', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'SoftPatchPtr2', @Buff[Cursor], dtDword, Cursor);
    end
    else
    begin
      AddString(Result, 'Wx86Thread.CallBx86Eip', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'Wx86Thread.DeallocationCpu', @Buff[Cursor], dtDword, Cursor);
      AddString(Result, 'Wx86Thread.UseKnownWx86Dll', @Buff[Cursor], dtByte, Cursor);
      AddString(Result, 'Wx86Thread.OleStubInvoked', @Buff[Cursor], dtByte, Cursor);
      AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 2, Cursor);
    end;

  Assert(Cursor = $F94);
  AddString(Result, 'TlsExpansionSlots = ' + ExtractPPVoidData32(Process, @Buff[Cursor]),
    @Buff[Cursor], dtBuff, 4, Cursor);

  AddString(Result, 'ImpersonationLocale', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'IsImpersonating', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NlsCache', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'pShimData', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'HeapVirtualAffinity', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CurrentTransactionHandle', @Buff[Cursor], dtDword, Cursor);
  Assert(Cursor = $FB0);
  AddString(Result, 'ActiveFrame', @Buff[Cursor], dtDword, Cursor);

  if IsW2003OrHigher then
    AddString(Result, 'FlsData', @Buff[Cursor], dtDword, Cursor);

  if IsLonghornOrHigher then
  begin
    AddString(Result, 'PreferredLanguages', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'UserPrefLanguages', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'MergedPrefLanguages', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'MuiImpersonation', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'CrossTebFlags', @Buff[Cursor], dtWord, Cursor);
    ValueBuff := PDWORD(@Buff[Cursor])^;
    AddString(Result, 'SameTebFlags', @Buff[Cursor], dtWord, Cursor,
      SameTebFlagsToStr(ValueBuff));
    AddString(Result, 'TxnScopeEnterCallback', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'TxnScopeExitCallback', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'TxnScopeContext', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'LockCount', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'ProcessRundown', @Buff[Cursor], dtDword, Cursor);
    AddString(Result, 'LastSwitchTime', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'TotalSwitchOutTime', @Buff[Cursor], dtInt64, Cursor);
    AddString(Result, 'WaitReasonBitMap', @Buff[Cursor], dtInt64, Cursor);
  end
  else
  begin
    AddString(Result, 'SafeThunkCall', @Buff[Cursor], dtByte, Cursor);
    AddString(Result, 'BooleanSpare', @Buff[Cursor], dtBuff, 3, Cursor);
  end;

  DumpMemoryFromBuffWithCheckRawData(Result, Process, Address, Buff, Cursor);
end;

procedure DumpKSystemTime(var OutValue: string; const Description: string;
  Address: Pointer; var Cursor: NativeUInt);
begin
  AddString(OutValue, Description + '.LowPart', Address, dtDword, Cursor);
  Address := PByte(Address) + 4;
  AddString(OutValue, Description + '.High1Time', Address, dtDword, Cursor);
  Address := PByte(Address) + 4;
  AddString(OutValue, Description + '.High2Time', Address, dtDword, Cursor);
end;

function NtProductTypeToStr(Value: DWORD): string;
begin
  case Value of
    VER_NT_WORKSTATION: Result := 'VER_NT_WORKSTATION';
    VER_NT_DOMAIN_CONTROLLER: Result := 'VER_NT_DOMAIN_CONTROLLER';
    VER_NT_SERVER: Result := 'VER_NT_SERVER';
  else
    Result := '';
  end;
end;

procedure DumpProcessorFeatures(var OutValue: string;
  Address: PByte; var Cursor: NativeUInt);
const
  MaxFeaturesCount = 64;
  KnownFeaturesCount = 28;
  FeaturesStrings: array [0..KnownFeaturesCount - 1] of string =
    (
      'PF_FLOATING_POINT_PRECISION_ERRATA',
      'PF_FLOATING_POINT_EMULATED',
      'PF_COMPARE_EXCHANGE_DOUBLE',
      'PF_MMX_INSTRUCTIONS_AVAILABLE',
      'PF_PPC_MOVEMEM_64BIT_OK',
      'PF_ALPHA_BYTE_INSTRUCTIONS',
      'PF_XMMI_INSTRUCTIONS_AVAILABLE',
      'PF_3DNOW_INSTRUCTIONS_AVAILABLE',
      'PF_RDTSC_INSTRUCTION_AVAILABLE',
      'PF_PAE_ENABLED',
      'PF_XMMI64_INSTRUCTIONS_AVAILABLE',
      'PF_SSE_DAZ_MODE_AVAILABLE',
      'PF_NX_ENABLED',
      'PF_SSE3_INSTRUCTIONS_AVAILABLE',
      'PF_COMPARE_EXCHANGE128',
      'PF_COMPARE64_EXCHANGE128',
      'PF_CHANNELS_ENABLED',
      'PF_XSAVE_ENABLED',
      'PF_ARM_VFP_32_REGISTERS_AVAILABLE',
      'PF_ARM_NEON_INSTRUCTIONS_AVAILABLE',
      'PF_SECOND_LEVEL_ADDRESS_TRANSLATION',
      'PF_VIRT_FIRMWARE_ENABLED',
      'PF_RDWRFSGSBASE_AVAILABLE',
      'PF_FASTFAIL_AVAILABLE',
      'PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE',
      'PF_ARM_64BIT_LOADSTORE_ATOMIC',
      'PF_ARM_EXTERNAL_CACHE_AVAILABLE',
      'PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE'
    );
var
  I: Integer;
begin
  AddString(OutValue, EmptyHeader);
  for I := 0 to KnownFeaturesCount - 1 do
  begin
    AddString(OutValue, 'ProcessorFeatures[' + FeaturesStrings[I] + ']',
      Address, dtByte, Cursor);
    Inc(Address);
  end;
  AddString(OutValue, EmptyHeader);
  AddString(OutValue, 'Unknown Processor Features', Address, dtBuff,
    MaxFeaturesCount - KnownFeaturesCount, Cursor);
  AddString(OutValue, EmptyHeader);
end;

function AlternativeArchitectureTypeToStr(Value: DWORD): string;
begin
  case Value of
    0: Result := 'StandardDesign';
    1: Result := 'NEC98x86';
    2: Result := 'EndAlternatives';
  else
    Result := '';
  end;
end;

function MitigationPoliciesToStr(Value: DWORD): string;

  procedure AddResult(const Value: string);
  begin
    if Result = '' then
      Result := Value
    else
      Result := Result + '|' + Value;
  end;

begin
  Result := '';
  (*
    union
    {
        UCHAR MitigationPolicies;
        struct
        {
            UCHAR NXSupportPolicy : 2;
            UCHAR SEHValidationPolicy : 2;
            UCHAR CurDirDevicesSkippedForDlls : 2;
            UCHAR Reserved : 2;
        };
    };
  *)
  if Value and 3 <> 0 then AddResult('NXSupportPolicy');
  if Value and $C <> 0 then AddResult('SEHValidationPolicy');
  if Value and $30 <> 0 then AddResult('CurDirDevicesSkippedForDlls');
end;

function DbgFlagToStr(Value: DWORD): string;

  procedure AddResult(const Value: string);
  begin
    if Result = '' then
      Result := Value
    else
      Result := Result + '|' + Value;
  end;

const
  FlagName: array [0..10] of string = (
    'DbgErrorPortPresent',
    'DbgElevationEnabled',
    'DbgVirtEnabled',
    'DbgInstallerDetectEnabled',
    'DbgLkgEnabled',
    'DbgDynProcessorEnabled',
    'DbgConsoleBrokerEnabled',
    'DbgSecureBootEnabled',
    'DbgMultiSessionSku',
    'DbgMultiUsersInSessionSku',
    'DbgStateSeparationEnabled'
  );

begin
  Result := '';
  for var I := 0 to 10 do
    if Value and (1 shl I) <> 0 then
      AddResult(FlagName[I]);
end;

function DumpKUserSharedData(Process: THandle; Address: Pointer): string;
var
  Buff: TMemoryDump;
  RegionSize, Cursor: NativeUInt;
  ValueBuff: DWORD;
begin
  // validated on Windows 11
  Result := '';
  CurerntAddr := Address;
  MaxSize := 4096;
  SetLength(Buff, MaxSize);
  if not ReadProcessData(Process, Address, @Buff[0],
    MaxSize, RegionSize, rcReadAllwais) then Exit;
  Cursor := 0;
  AddString(Result, KUSER);
  AddString(Result, 'TickCountLowDeprecated', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TickCountMultiplier', @Buff[Cursor], dtDword, Cursor);
  DumpKSystemTime(Result, 'InterruptTime', Buff, Cursor);
  DumpKSystemTime(Result, 'SystemTime', Buff, Cursor);
  DumpKSystemTime(Result, 'TimeZoneBias', Buff, Cursor);
  AddString(Result, 'ImageNumberLow', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'ImageNumberHigh', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'NtSystemRoot', @Buff[Cursor], dtString, 520, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'MaxStackTraceDepth', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CryptoExponent', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TimeZoneId', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'LargePageMinimum', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'AitSamplingValue', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'AppCompatFlag', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'RNGSeedVersion', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'GlobalValidationRunlevel', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TimeZoneBiasStamp', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NtBuildNumber', @Buff[Cursor], dtDword, Cursor);
  ValueBuff := PDWORD(@Buff[Cursor])^;
  AddString(Result, 'NtProductType', @Buff[Cursor], dtDword, Cursor,
    NtProductTypeToStr(ValueBuff));
  AddString(Result, 'ProductTypeIsValid', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'Reserved0', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'NativeProcessorArchitecture', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'NtMajorVersion', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NtMinorVersion', @Buff[Cursor], dtDword, Cursor);
  DumpProcessorFeatures(Result, @Buff[Cursor], Cursor);
  AddString(Result, 'Reserved1', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Reserved3', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TimeSlip', @Buff[Cursor], dtDword, Cursor);
  ValueBuff := PDWORD(@Buff[Cursor])^;
  AddString(Result, 'AlternativeArchitecture', @Buff[Cursor], dtDword,
    Cursor, AlternativeArchitectureTypeToStr(ValueBuff));
  AddString(Result, 'BootId', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'SystemExpirationDate', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'SuiteMask', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'KdDebuggerEnabled', @Buff[Cursor], dtByte, Cursor);
  ValueBuff := PByte(@Buff[Cursor])^;
  AddString(Result, 'MitigationPolicies', @Buff[Cursor], dtByte, Cursor,
    MitigationPoliciesToStr(ValueBuff));
  AddString(Result, 'CyclesPerYield', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'ActiveConsoleId', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'DismountCount', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ComPlusPackage', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'LastSystemRITEventTickCount', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NumberOfPhysicalPages', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'SafeBootMode', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'VirtualizationFlags', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'Reserved12', @Buff[Cursor], dtWord, Cursor);
  ValueBuff := PDWORD(@Buff[Cursor])^;
  AddString(Result, 'SharedDataFlags', @Buff[Cursor], dtDword, Cursor,
    DbgFlagToStr(ValueBuff));
  AddString(Result, 'DataFlagsPad', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TestRetInstruction', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'QpcFrequency', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'SystemCall', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Reserved2', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'SystemCallPad', @Buff[Cursor], dtBuff, 16, Cursor);
  AddString(Result, EmptyHeader);
  DumpKSystemTime(Result, 'TickCount', Buff, Cursor);
  AddString(Result, 'TickCountPad', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Cookie', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CookiePad', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ConsoleSessionForegroundProcessId', @Buff[Cursor], dtInt64, Cursor);

  AddString(Result, EmptyHeader);
  //AddString(Result, 'Wow64SharedInformation', @Buff[Cursor], dtBuff, 64, Cursor);
  AddString(Result, 'TimeUpdateLock', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'BaselineSystemTimeQpc', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'BaselineInterruptTimeQpc', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'QpcSystemTimeIncrement', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'QpcInterruptTimeIncrement', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'QpcSystemTimeIncrementShift', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'QpcInterruptTimeIncrementShift', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'UnparkedProcessorCount', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'EnclaveFeatureMask', @Buff[Cursor], dtBuff, 16, Cursor);
  AddString(Result, 'TelemetryCoverageRound', @Buff[Cursor], dtDword, Cursor);

  AddString(Result, EmptyHeader);
  AddString(Result, 'UserModeGlobalLogger', @Buff[Cursor], dtBuff, 32, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'ImageFileExecutionOptions', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'LangGenerationCount', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Reserved4', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'InterruptTimeBias', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'QpcBias', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ActiveProcessorCount', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ActiveGroupCount', @Buff[Cursor], dtWord, Cursor);
//  AddString(Result, 'Reserved9', @Buff[Cursor], dtWord, Cursor);
//  AddString(Result, 'AitSamplingValue', @Buff[Cursor], dtDword, Cursor);
//  AddString(Result, 'AppCompatFlag', @Buff[Cursor], dtDword, Cursor);
//  AddString(Result, 'SystemDllNativeRelocation', @Buff[Cursor], dtInt64, Cursor);
//  AddString(Result, 'SystemDllWowRelocation', @Buff[Cursor], dtDword, Cursor);

  DumpMemoryFromBuffWithCheckRawData(Result, Process, Address, Buff, Cursor);
end;

procedure DumpRTL_DRIVE_LETTER_CURDIR32(var OutValue: string; const Description: string;
  Buff: TMemoryDump; var Cursor: NativeUInt; Process: THandle);
begin
  AddString(OutValue, Description + '.Flags', @Buff[Cursor], dtWord, Cursor);
  AddString(OutValue, Description + '.Length', @Buff[Cursor], dtWord, Cursor);
  AddString(OutValue, Description + '.TimeStamp', @Buff[Cursor], dtDword, Cursor);
  AddString(OutValue, Description + '.DosPath = ' +
    ExtractUnicodeString32(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(OutValue, EmptyHeader);
end;

function DumpProcessParameters32(Process: THandle; Address: Pointer): string;
const
  RTL_MAX_DRIVE_LETTERS = 32;
var
  Buff: TMemoryDump;
  RegionSize, Cursor: NativeUInt;
  I: Integer;
begin
  Result := '';
  CurerntAddr := Address;
  MaxSize := 4096;
  SetLength(Buff, MaxSize);
  if not ReadProcessData(Process, Address, @Buff[0],
    MaxSize, RegionSize, rcReadAllwais) then Exit;
  Cursor := 0;
  AddString(Result, PROCESSPARAMS32);
  AddString(Result, 'MaximumLength', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Length', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Flags', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'DebugFlags', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ConsoleHandle', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ConsoleFlags', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'StandartInput', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'StandartOutput', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'StandartError', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CurrentDirectory.DosPath = ' + ExtractUnicodeString32(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(Result, 'CurrentDirectory.Handle', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'DllPath = ' + ExtractUnicodeString32(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(Result, 'ImagePathName = ' + ExtractUnicodeString32(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(Result, 'CommandLine = ' + ExtractUnicodeString32(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(Result, 'Environmment', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'StartingX', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'StartingY', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CountX', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CountY', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CountCharsX', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CountCharsY', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'FillAttribute', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'WindowFlags', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ShowWindowFlags', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'WindowTitle = ' + ExtractUnicodeString32(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(Result, 'DesktopInfo = ' + ExtractUnicodeString32(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(Result, 'ShellInfo = ' + ExtractUnicodeString32(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(Result, 'RuntimeData = ' + ExtractUnicodeString32(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString32, Cursor);

  AddString(Result, EmptyHeader);
  for I := 0 to RTL_MAX_DRIVE_LETTERS - 1 do
    DumpRTL_DRIVE_LETTER_CURDIR32(Result,
      'DLCurrentDirectory' + IntToStr(I + 1), Buff, Cursor, Process);

  AddString(Result, 'EnvironmentSize', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'EnvironmentVersion', @Buff[Cursor], dtDword, Cursor);

  DumpMemoryFromBuffWithCheckRawData(Result, Process, Address, Buff, Cursor);
end;

procedure DumpRTL_DRIVE_LETTER_CURDIR64(var OutValue: string; const Description: string;
  Buff: TMemoryDump; var Cursor: NativeUInt; Process: THandle);
begin
  AddString(OutValue, Description + '.Flags', @Buff[Cursor], dtWord, Cursor);
  AddString(OutValue, Description + '.Length', @Buff[Cursor], dtWord, Cursor);
  AddString(OutValue, Description + '.TimeStamp', @Buff[Cursor], dtDword, Cursor);
  AddString(OutValue, Description + '.DosPath = ' +
    ExtractUnicodeString64(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(OutValue, EmptyHeader);
end;

function DumpProcessParameters64(Process: THandle; Address: Pointer): string;
const
  RTL_MAX_DRIVE_LETTERS = 32;
var
  Buff: TMemoryDump;
  RegionSize, Cursor: NativeUInt;
  I: Integer;
begin
  Result := '';
  CurerntAddr := Address;
  MaxSize := 4096;
  SetLength(Buff, MaxSize);
  if not ReadProcessData(Process, Address, @Buff[0],
    MaxSize, RegionSize, rcReadAllwais) then Exit;
  Cursor := 0;
  AddString(Result, PROCESSPARAMS64);
  AddString(Result, 'MaximumLength', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Length', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Flags', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'DebugFlags', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ConsoleHandle', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ConsoleFlags', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);

  AddString(Result, 'StandartInput', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'StandartOutput', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'StandartError', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'CurrentDirectory.DosPath = ' + ExtractUnicodeString64(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(Result, 'CurrentDirectory.Handle', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'DllPath = ' + ExtractUnicodeString64(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(Result, 'ImagePathName = ' + ExtractUnicodeString64(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(Result, 'CommandLine = ' + ExtractUnicodeString64(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(Result, 'Environmment', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'StartingX', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'StartingY', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CountX', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CountY', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CountCharsX', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CountCharsY', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'FillAttribute', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'WindowFlags', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ShowWindowFlags', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 4, Cursor);

  AddString(Result, 'WindowTitle = ' + ExtractUnicodeString64(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(Result, 'DesktopInfo = ' + ExtractUnicodeString64(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(Result, 'ShellInfo = ' + ExtractUnicodeString64(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(Result, 'RuntimeData = ' + ExtractUnicodeString64(Process, Buff, Cursor),
    @Buff[Cursor], dtUnicodeString64, Cursor);

  AddString(Result, EmptyHeader);
  for I := 0 to RTL_MAX_DRIVE_LETTERS - 1 do
    DumpRTL_DRIVE_LETTER_CURDIR64(Result,
      'DLCurrentDirectory' + IntToStr(I + 1), Buff, Cursor, Process);

  AddString(Result, 'EnvironmentSize', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'EnvironmentVersion', @Buff[Cursor], dtInt64, Cursor);

  DumpMemoryFromBuffWithCheckRawData(Result, Process, Address, Buff, Cursor);
end;

function GetOleTlsFlag(Value: DWORD): string;
const
    OLETLS_LOCALTID             = $01;   // This TID is in the current process.
    OLETLS_UUIDINITIALIZED      = $02;   // This Logical thread is init'd.
    OLETLS_INTHREADDETACH       = $04;   // This is in thread detach. Needed
                                         // due to NT's special thread detach
                                         // rules.
    OLETLS_CHANNELTHREADINITIALZED = $08;// This channel has been init'd
    OLETLS_WOWTHREAD            = $10;   // This thread is a 16-bit WOW thread.
    OLETLS_THREADUNINITIALIZING = $20;   // This thread is in CoUninitialize.
    OLETLS_DISABLE_OLE1DDE      = $40;   // This thread can't use a DDE window.
    OLETLS_APARTMENTTHREADED    = $80;   // This is an STA apartment thread
    OLETLS_MULTITHREADED        = $100;  // This is an MTA apartment thread
    OLETLS_IMPERSONATING        = $200;  // This thread is impersonating
    OLETLS_DISABLE_EVENTLOGGER  = $400;  // Prevent recursion in event logger
    OLETLS_INNEUTRALAPT         = $800;  // This thread is in the NTA
    OLETLS_DISPATCHTHREAD       = $1000; // This is a dispatch thread
    OLETLS_HOSTTHREAD           = $2000; // This is a host thread
    OLETLS_ALLOWCOINIT          = $4000; // This thread allows inits
    OLETLS_PENDINGUNINIT        = $8000; // This thread has pending uninit
    OLETLS_FIRSTMTAINIT         = $10000;// First thread to attempt an MTA init
    OLETLS_FIRSTNTAINIT         = $20000;// First thread to attempt an NTA init
    OLETLS_APTINITIALIZING      = $40000; // Apartment Object is initializing

  procedure AddToResult(const Value: string);
  begin
    if Result = '' then
      Result := Value
    else
      Result := Result + '|' + Value;
  end;

begin
  if Value and OLETLS_LOCALTID <> 0 then AddToResult('LOCALTID');
  if Value and OLETLS_UUIDINITIALIZED <> 0 then AddToResult('UUIDINITIALIZED');
  if Value and OLETLS_INTHREADDETACH <> 0 then AddToResult('INTHREADDETACH');
  if Value and OLETLS_CHANNELTHREADINITIALZED <> 0 then AddToResult('CHANNELTHREADINITIALZED');
  if Value and OLETLS_WOWTHREAD <> 0 then AddToResult('WOWTHREAD');
  if Value and OLETLS_THREADUNINITIALIZING <> 0 then AddToResult('THREADUNINITIALIZING');
  if Value and OLETLS_DISABLE_OLE1DDE <> 0 then AddToResult('DISABLE_OLE1DDE');
  if Value and OLETLS_APARTMENTTHREADED <> 0 then AddToResult('APARTMENTTHREADED');
  if Value and OLETLS_MULTITHREADED <> 0 then AddToResult('MULTITHREADED');
  if Value and OLETLS_IMPERSONATING <> 0 then AddToResult('IMPERSONATING');
  if Value and OLETLS_DISABLE_EVENTLOGGER <> 0 then AddToResult('DISABLE_EVENTLOGGER');
  if Value and OLETLS_INNEUTRALAPT <> 0 then AddToResult('INNEUTRALAPT');
  if Value and OLETLS_DISPATCHTHREAD <> 0 then AddToResult('DISPATCHTHREAD');
  if Value and OLETLS_HOSTTHREAD <> 0 then AddToResult('HOSTTHREAD');
  if Value and OLETLS_ALLOWCOINIT <> 0 then AddToResult('ALLOWCOINIT');
  if Value and OLETLS_PENDINGUNINIT <> 0 then AddToResult('PENDINGUNINIT');
  if Value and OLETLS_FIRSTMTAINIT <> 0 then AddToResult('FIRSTMTAINIT');
  if Value and OLETLS_FIRSTNTAINIT <> 0 then AddToResult('FIRSTNTAINIT');
  if Value and OLETLS_APTINITIALIZING <> 0 then AddToResult('APTINITIALIZING');
end;

function DumpOleTlsData32(Process: THandle;
  Address: Pointer; IsWow64: Boolean): string;
var
  Buff: TMemoryDump;
  RegionSize, Cursor: NativeUInt;
begin
  Result := '';
  CurerntAddr := Address;
  MaxSize := 4096;
  SetLength(Buff, MaxSize);
  if not ReadProcessData(Process, Address, @Buff[0],
    MaxSize, RegionSize, rcReadAllwais) then Exit;

  Cursor := 0;
  AddString(Result, OLE_TLS_DATA32);
  AddString(Result, 'pvThreadBase', @Buff[Cursor], dtDword, Cursor, 'per thread base pointer');
  AddString(Result, 'pSmAllocator', @Buff[Cursor], dtDword, Cursor, 'per thread docfile allocator');

  AddString(Result, 'dwApartmentID', @Buff[Cursor], dtDword, Cursor, 'Per thread "process ID"');
  Assert(Cursor = 12);
  AddString(Result, 'dwFlags', @Buff[Cursor], dtDword, Cursor, GetOleTlsFlag(PDWORD(@Buff[Cursor])^));

  AddString(Result, 'TlsMapIndex', @Buff[Cursor], dtDword, Cursor, 'index in the global TLSMap');
  AddString(Result, 'ppTlsSlot', @Buff[Cursor], dtDword, Cursor, 'Back pointer to the thread tls slot');
  AddString(Result, 'cComInits', @Buff[Cursor], dtDword, Cursor, 'number of per-thread inits');
  AddString(Result, 'cOleInits', @Buff[Cursor], dtDword, Cursor, 'number of per-thread OLE inits');

  AddString(Result, 'cCalls', @Buff[Cursor], dtDword, Cursor, 'number of outstanding calls');
  AddString(Result, 'pCallInfo', @Buff[Cursor], dtDword, Cursor, 'channel call info');
  AddString(Result, 'pFreeAsyncCall', @Buff[Cursor], dtDword, Cursor, 'ptr to available call object for this thread');
  AddString(Result, 'pFreeClientCall', @Buff[Cursor], dtDword, Cursor, 'ptr to available call object for this thread');

  AddString(Result, 'pObjServer', @Buff[Cursor], dtDword, Cursor, 'Activation Server Object for this apartment');
  AddString(Result, 'dwTIDCaller', @Buff[Cursor], dtDword, Cursor, 'TID of current calling app');
  AddString(Result, 'pCurrentCtx', @Buff[Cursor], dtDword, Cursor, 'Current context');

  AddString(Result, 'pEmptyCtx', @Buff[Cursor], dtDword, Cursor, 'Empty context');

  AddString(Result, 'pNativeCtx', @Buff[Cursor], dtDword, Cursor, 'Native context');
  AddString(Result, 'ContextId', @Buff[Cursor], dtInt64, Cursor, 'Uniquely identifies the current context');
  AddString(Result, 'pNativeApt', @Buff[Cursor], dtDword, Cursor, 'Native apartment for the thread');
  AddString(Result, 'pCallContext', @Buff[Cursor], dtDword, Cursor, 'call context object');
  AddString(Result, 'pCtxCall', @Buff[Cursor], dtDword, Cursor, 'Context call object');

  AddString(Result, 'pPS', @Buff[Cursor], dtDword, Cursor, 'Policy set');
  AddString(Result, 'pvPendingCallsFront', @Buff[Cursor], dtDword, Cursor, 'Per Apt pending async calls');
  AddString(Result, 'pvPendingCallsBack', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'pCallCtrl', @Buff[Cursor], dtDword, Cursor, 'call control for RPC for this apartment');

{$REGION ' это уже все плывет, оставляю как напоминалку '}

//  AddString(Result, 'pTopSCS', @Buff[Cursor], dtDword, Cursor, 'top server-side callctrl state');
//  AddString(Result, 'pMsgFilter', @Buff[Cursor], dtDword, Cursor, 'temp storage for App MsgFilter');
//  AddString(Result, 'hwndSTA', @Buff[Cursor], dtDword, Cursor, 'STA server window same as poxid->hServerSTA');
//
//  AddString(Result, 'cORPCNestingLevel', @Buff[Cursor], dtDword, Cursor, 'call nesting level (DBG only)');
//
//  AddString(Result, 'cDebugData', @Buff[Cursor], dtDword, Cursor, 'count of bytes of debug data in call');
//
//  AddString(Result, 'LogicalThreadId', @Buff[Cursor], dtDword, Cursor, 'current logical thread id');
//
//  AddString(Result, 'hThread', @Buff[Cursor], dtDword, Cursor, 'Thread handle used for cancel');
//  AddString(Result, 'hRevert', @Buff[Cursor], dtDword, Cursor, 'Token before first impersonate');
//  AddString(Result, 'pAsyncRelease', @Buff[Cursor], dtDword, Cursor, 'Controlling unknown for async release');
//
//  AddString(Result, '... DDE data');
//  AddString(Result, 'hwndDdeServer', @Buff[Cursor], dtDword, Cursor, 'Per thread Common DDE server');
//
//  AddString(Result, 'hwndDdeClient', @Buff[Cursor], dtDword, Cursor, 'Per thread Common DDE client');
//  AddString(Result, 'cServeDdeObjects', @Buff[Cursor], dtDword, Cursor, 'non-zero if objects DDE should serve');
//
//  AddString(Result, '... ClassCache data');
//  AddString(Result, 'pSTALSvrsFront', @Buff[Cursor], dtDword, Cursor, 'Chain of LServers registers in this thread if STA');
//
//  AddString(Result, '... upper layer data');
//  AddString(Result, 'hwndClip', @Buff[Cursor], dtDword, Cursor, 'Clipboard window');
//  {$MESSAGE 'Проверить на реализации DragDrop шеловской'}
//  AddString(Result, 'pDataObjClip', @Buff[Cursor], dtDword, Cursor, 'Current Clipboard DataObject');
//  AddString(Result, 'dwClipSeqNum', @Buff[Cursor], dtDword, Cursor, 'Clipboard Sequence # for the above DataObject');
//  AddString(Result, 'fIsClipWrapper', @Buff[Cursor], dtDword, Cursor, 'Did we hand out the wrapper Clipboard DataObject?');
//  AddString(Result, 'punkState', @Buff[Cursor], dtDword, Cursor, 'Per thread "state" object');
//
//  AddString(Result, '... cancel data');
//  AddString(Result, 'cCallCancellation', @Buff[Cursor], dtDword, Cursor, 'count of CoEnableCallCancellation');
//
//  AddString(Result, '... async sends data');
//  AddString(Result, 'cAsyncSends', @Buff[Cursor], dtDword, Cursor, 'count of async sends outstanding');
//
//  AddString(Result, 'pAsyncCallList', @Buff[Cursor], dtDword, Cursor, 'async calls outstanding');
//  AddString(Result, 'pSurrogateList', @Buff[Cursor], dtDword, Cursor, 'Objects in the surrogate');
//
//  AddString(Result, 'lockEntry', @Buff[Cursor], dtDword, Cursor, 'Locks currently held by the thread');
//  AddString(Result, 'CallEntry', @Buff[Cursor], dtDword, Cursor, 'client-side call chain for this thread');
//
//  AddString(Result, 'pContextStack', @Buff[Cursor], dtDword, Cursor, 'Context stack node for SWC');
//
//  AddString(Result, 'pFirstSpyReg', @Buff[Cursor], dtDword, Cursor, 'First registered IInitializeSpy');
//  AddString(Result, 'pFirstFreeSpyReg', @Buff[Cursor], dtDword, Cursor, 'First available spy registration');
//  AddString(Result, 'dwMaxSpy', @Buff[Cursor], dtDword, Cursor, 'First free IInitializeSpy cookie');
//
//  // только для ч86
//  if IsWow64 then
//    AddString(Result, 'punkStateWx86', @Buff[Cursor], dtDword, Cursor, 'Per thread "state" object for Wx86');
//
//  AddString(Result, 'pDragCursors', @Buff[Cursor], dtDword, Cursor, 'Per thread drag cursor table');
//
//  AddString(Result, 'punkError', @Buff[Cursor], dtDword, Cursor, 'Per thread error object');
//  AddString(Result, 'cbErrorData', @Buff[Cursor], dtDword, Cursor, 'Maximum size of error data');
//
//  AddString(Result, 'punkActiveXSafetyProvider', @Buff[Cursor], dtDword, Cursor);
{$ENDREGION}

  DumpMemoryFromBuffWithCheckRawData(Result, Process, Address, Buff, Cursor);
end;

function DumpOleTlsData64(Process: THandle; Address: Pointer): string;
var
  Buff: TMemoryDump;
  RegionSize, Cursor: NativeUInt;
begin
  Result := '';
  CurerntAddr := Address;
  MaxSize := 4096;
  SetLength(Buff, MaxSize);
  if not ReadProcessData(Process, Address, @Buff[0],
    MaxSize, RegionSize, rcReadAllwais) then Exit;

  Cursor := 0;
  AddString(Result, OLE_TLS_DATA64);
  AddString(Result, 'pvThreadBase', @Buff[Cursor], dtInt64, Cursor, 'per thread base pointer');
  AddString(Result, 'pSmAllocator', @Buff[Cursor], dtInt64, Cursor, 'per thread docfile allocator');

  AddString(Result, 'dwApartmentID', @Buff[Cursor], dtDword, Cursor, 'Per thread "process ID"');
  Assert(Cursor = 20);
  AddString(Result, 'dwFlags', @Buff[Cursor], dtDword, Cursor, GetOleTlsFlag(PDWORD(@Buff[Cursor])^));

  AddString(Result, 'TlsMapIndex', @Buff[Cursor], dtDword, Cursor, 'index in the global TLSMap');
  AddString(Result, 'ppTlsSlot', @Buff[Cursor], dtInt64, Cursor, 'Back pointer to the thread tls slot');
  AddString(Result, 'cComInits', @Buff[Cursor], dtDword, Cursor, 'number of per-thread inits');
  AddString(Result, 'cOleInits', @Buff[Cursor], dtDword, Cursor, 'number of per-thread OLE inits');

  AddString(Result, 'cCalls', @Buff[Cursor], dtDword, Cursor, 'number of outstanding calls');
  AddString(Result, 'pCallInfo', @Buff[Cursor], dtInt64, Cursor, 'channel call info');
  AddString(Result, 'pFreeAsyncCall', @Buff[Cursor], dtInt64, Cursor, 'ptr to available call object for this thread');
  AddString(Result, 'pFreeClientCall', @Buff[Cursor], dtInt64, Cursor, 'ptr to available call object for this thread');

  AddString(Result, 'pObjServer', @Buff[Cursor], dtInt64, Cursor, 'Activation Server Object for this apartment');
  AddString(Result, 'dwTIDCaller', @Buff[Cursor], dtDword, Cursor, 'TID of current calling app');
  AddString(Result, 'pCurrentCtx', @Buff[Cursor], dtInt64, Cursor, 'Current context');

  AddString(Result, 'pEmptyCtx', @Buff[Cursor], dtDword, Cursor, 'Empty context');

  AddString(Result, 'pNativeCtx', @Buff[Cursor], dtInt64, Cursor, 'Native context');
  AddString(Result, 'ContextId', @Buff[Cursor], dtInt64, Cursor, 'Uniquely identifies the current context');
  AddString(Result, 'pNativeApt', @Buff[Cursor], dtInt64, Cursor, 'Native apartment for the thread');
  AddString(Result, 'pCallContext', @Buff[Cursor], dtInt64, Cursor, 'call context object');
  AddString(Result, 'pCtxCall', @Buff[Cursor], dtInt64, Cursor, 'Context call object');

  AddString(Result, 'pPS', @Buff[Cursor], dtInt64, Cursor, 'Policy set');
  AddString(Result, 'pvPendingCallsFront', @Buff[Cursor], dtInt64, Cursor, 'Per Apt pending async calls');
  AddString(Result, 'pvPendingCallsBack', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'pCallCtrl', @Buff[Cursor], dtInt64, Cursor, 'call control for RPC for this apartment');

  DumpMemoryFromBuffWithCheckRawData(Result, Process, Address, Buff, Cursor);
end;

procedure DumpLoaderData(
  var OutString: string; Process: THandle;
  DataType: TSymbolDataType; Address: Pointer;
  Buff: TMemoryDump; var Cursor: NativeUInt);

  function GetLinkTo32(Value: NativeUInt): string;
  begin
    Result := EmptyStr;
    if PDWORD(@Buff[Cursor])^ <> 0 then
      Result := 'link to: ' + IntToHex(PDWORD(@Buff[Cursor])^ - Value, 1);
  end;

  function GetLinkTo64(Value: NativeUInt): string;
  begin
    Result := EmptyStr;
    if PUINT64(@Buff[Cursor])^ <> 0 then
      Result := 'link to: ' + IntToHex(PUINT64(@Buff[Cursor])^ - Value, 1);
  end;

var
  Len: DWORD;
begin
  case DataType of
    sdtLdrData32:
    begin
      AddString(OutString, LDR_DATA32);
      Len := PDWORD(@Buff[Cursor])^;
      AddString(OutString, 'Length', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'Initialized', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'SsHandle', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'InLoadOrderModuleList.FLink', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'InLoadOrderModuleList.BLink', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'InMemoryOrderModuleList.FLink', @Buff[Cursor],
        dtDword, Cursor, GetLinkTo32(8));
      AddString(OutString, 'InMemoryOrderModuleList.BLink', @Buff[Cursor],
        dtDword, Cursor, GetLinkTo32(8));
      AddString(OutString, 'InInitializationOrderModuleList.FLink', @Buff[Cursor],
        dtDword, Cursor, GetLinkTo32(16));
      AddString(OutString, 'InInitializationOrderModuleList.BLink', @Buff[Cursor],
        dtDword, Cursor, GetLinkTo32(16));
      AddString(OutString, 'EntryInProgress', @Buff[Cursor], dtDword, Cursor);
      if Len > Cursor then
        AddString(OutString, 'Unknown', @Buff[Cursor], dtBuff, Len - Cursor, Cursor);
    end;
    sdtLdrEntry32:
    begin
      AddString(OutString, LDR_DATA_TABLE_ENTRY32);
      AddString(OutString, 'InLoadOrderLinks.FLink', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'InLoadOrderLinks.BLink', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'InMemoryOrderLinks.FLink', @Buff[Cursor],
        dtDword, Cursor, GetLinkTo32(8));
      AddString(OutString, 'InMemoryOrderLinks.BLink', @Buff[Cursor],
        dtDword, Cursor, GetLinkTo32(8));
      AddString(OutString, 'InInitializationOrderLinks.FLink', @Buff[Cursor],
        dtDword, Cursor, GetLinkTo32(16));
      AddString(OutString, 'InInitializationOrderLinks.BLink', @Buff[Cursor],
        dtDword, Cursor, GetLinkTo32(16));
      AddString(OutString, 'DllBase', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'EntryPoint', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'SizeOfImage', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'FullDllName = ' + ExtractUnicodeString32(Process, Buff, Cursor),
        @Buff[Cursor], dtUnicodeString32, Cursor);
      AddString(OutString, 'BaseDllName = ' + ExtractUnicodeString32(Process, Buff, Cursor),
        @Buff[Cursor], dtUnicodeString32, Cursor);
      AddString(OutString, 'Flags', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'LoadCount', @Buff[Cursor], dtWord, Cursor);
      AddString(OutString, 'TlsIndex', @Buff[Cursor], dtWord, Cursor);
      AddString(OutString, 'HashLinks.FLink', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'HashLinks.BLink', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'SectionPointer', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'CheckSum', @Buff[Cursor], dtDword, Cursor);
    end;
    sdtLdrData64:
    begin
      AddString(OutString, LDR_DATA64);
      Len := PDWORD(@Buff[Cursor])^;
      AddString(OutString, 'Length', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'Initialized', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'SsHandle', @Buff[Cursor], dtInt64, Cursor);
      AddString(OutString, 'InLoadOrderModuleList.FLink', @Buff[Cursor], dtInt64, Cursor);
      AddString(OutString, 'InLoadOrderModuleList.BLink', @Buff[Cursor], dtInt64, Cursor);
      AddString(OutString, 'InMemoryOrderModuleList.FLink', @Buff[Cursor],
        dtInt64, Cursor, GetLinkTo64(16));
      AddString(OutString, 'InMemoryOrderModuleList.BLink', @Buff[Cursor],
        dtInt64, Cursor, GetLinkTo64(16));
      AddString(OutString, 'InInitializationOrderModuleList.FLink', @Buff[Cursor],
        dtInt64, Cursor, GetLinkTo64(32));
      AddString(OutString, 'InInitializationOrderModuleList.BLink', @Buff[Cursor],
        dtInt64, Cursor, GetLinkTo64(32));
      AddString(OutString, 'EntryInProgress', @Buff[Cursor], dtInt64, Cursor);
      if Len > Cursor then
        AddString(OutString, 'Unknown', @Buff[Cursor], dtBuff, Len - Cursor, Cursor);
    end;
    sdtLdrEntry64:
    begin
      AddString(OutString, LDR_DATA_TABLE_ENTRY64);
      AddString(OutString, 'InLoadOrderLinks.FLink', @Buff[Cursor], dtInt64, Cursor);
      AddString(OutString, 'InLoadOrderLinks.BLink', @Buff[Cursor], dtInt64, Cursor);
      AddString(OutString, 'InMemoryOrderLinks.FLink', @Buff[Cursor],
        dtInt64, Cursor, GetLinkTo64(16));
      AddString(OutString, 'InMemoryOrderLinks.BLink', @Buff[Cursor],
        dtInt64, Cursor, GetLinkTo64(16));
      AddString(OutString, 'InInitializationOrderLinks.FLink', @Buff[Cursor],
        dtInt64, Cursor, GetLinkTo64(32));
      AddString(OutString, 'InInitializationOrderLinks.BLink', @Buff[Cursor],
        dtInt64, Cursor, GetLinkTo64(32));
      AddString(OutString, 'DllBase', @Buff[Cursor], dtInt64, Cursor);
      AddString(OutString, 'EntryPoint', @Buff[Cursor], dtInt64, Cursor);
      AddString(OutString, 'SizeOfImage', @Buff[Cursor], dtInt64, Cursor);
      AddString(OutString, 'FullDllName = ' + ExtractUnicodeString64(Process, Buff, Cursor),
        @Buff[Cursor], dtUnicodeString64, Cursor);
      AddString(OutString, 'BaseDllName = ' + ExtractUnicodeString64(Process, Buff, Cursor),
        @Buff[Cursor], dtUnicodeString64, Cursor);
      AddString(OutString, 'Flags', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'LoadCount', @Buff[Cursor], dtWord, Cursor);
      AddString(OutString, 'TlsIndex', @Buff[Cursor], dtWord, Cursor);
      AddString(OutString, 'HashLinks.FLink', @Buff[Cursor], dtInt64, Cursor);
      AddString(OutString, 'HashLinks.BLink', @Buff[Cursor], dtInt64, Cursor);
      AddString(OutString, 'SectionPointer', @Buff[Cursor], dtInt64, Cursor);
      AddString(OutString, 'CheckSum', @Buff[Cursor], dtDword, Cursor);
    end;
  end;
end;

procedure DumpActivationContext(
  var OutString: string; Process: THandle;
  const Data: TSymbolData; Address: Pointer;
  Buff: TMemoryDump; var Cursor: NativeUInt);

  function GetOffset: string;
  var
    Value: DWORD;
  begin
    Value := PDWORD(@Buff[Cursor])^;
    if Value = 0 then Exit;
    if Data.DataType in [sdtCtxProcess, sdtCtxSystem] then
      Inc(Value, UInt64(Address))
    else
      Inc(Value, Data.Ctx.ContextVA);
    Result := 'jmp to: ' + IntToHex(Value, 1);
  end;

  procedure ReadCtxString(const Value: string);
  var
    uStr: string;
    StrVA: ULONG64;
    Len,
    RegionSize: NativeUInt;
  begin
    if Cursor >= MaxSize - 4 then Exit;
    Len := PDWORD(@Buff[Cursor + 4])^;
    if Len = 0 then
      uStr := EmptyStr
    else
    begin
      StrVA := Data.Ctx.ContextVA + PDWORD(@Buff[Cursor])^;
      SetLength(uStr, Len div 2);
      if not ReadProcessData(Process, Pointer(StrVA), @uStr[1],
        Len, RegionSize, rcReadAllwais) then
        uStr := EmptyStr
    end;
    AddString(OutString, Value + 'Offset', @Buff[Cursor], dtDword, Cursor, uStr);
    AddString(OutString, Value + 'Length', @Buff[Cursor], dtDword, Cursor);
  end;

  function IdToStr: string;
  var
    Value: DWORD;
  begin
    Value := PDWORD(@Buff[Cursor])^;
    case Value of
      ACTIVATION_CONTEXT_SECTION_ASSEMBLY_INFORMATION: Result := 'ASSEMBLY_INFORMATION';
      ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION: Result := 'DLL_REDIRECTION';
      ACTIVATION_CONTEXT_SECTION_WINDOW_CLASS_REDIRECTION: Result := 'WINDOW_CLASS_REDIRECTION';
      ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION: Result := 'COM_SERVER_REDIRECTION';
      ACTIVATION_CONTEXT_SECTION_COM_INTERFACE_REDIRECTION: Result := 'COM_INTERFACE_REDIRECTION';
      ACTIVATION_CONTEXT_SECTION_COM_TYPE_LIBRARY_REDIRECTION: Result := 'COM_TYPE_LIBRARY_REDIRECTION';
      ACTIVATION_CONTEXT_SECTION_COM_PROGID_REDIRECTION: Result := 'COM_PROGID_REDIRECTION';
      ACTIVATION_CONTEXT_SECTION_GLOBAL_OBJECT_RENAME_TABLE: Result := 'GLOBAL_OBJECT_RENAME_TABLE';
      ACTIVATION_CONTEXT_SECTION_CLR_SURROGATES: Result := 'CLR_SURROGATES';
      ACTIVATION_CONTEXT_SECTION_APPLICATION_SETTINGS: Result := 'APPLICATION_SETTINGS';
      ACTIVATION_CONTEXT_SECTION_COMPATIBILITY_INFO: Result := 'COMPATIBILITY_INFO';
      ACTIVATION_CONTEXT_SECTION_WINRT_ACTIVATABLE_CLASSES: Result := 'WINRT_ACTIVATABLE_CLASSES';
    else
      Result := 'Unknown: ' + IntToStr(Value);
    end;
  end;

var
  FlagStr: string;
begin
  case Data.DataType of
    sdtCtxProcess, sdtCtxSystem:
    begin
      if Data.DataType = sdtCtxSystem then
        AddString(OutString, ACTX_SYSTEM)
      else
        AddString(OutString, ACTX_PROCESS);
      AddString(OutString, 'Magic', @Buff[Cursor], dtDword, Cursor, 'Actx');
      AddString(OutString, 'HeaderSize', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'FormatVersion', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'TotalSize', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'DefaultTocOffset', @Buff[Cursor], dtDword, Cursor, GetOffset);
      AddString(OutString, 'ExtendedTocOffset', @Buff[Cursor], dtDword, Cursor, GetOffset);
      AddString(OutString, 'AssemblyRosterOffset', @Buff[Cursor], dtDword, Cursor, GetOffset);
      AddString(OutString, 'Flags', @Buff[Cursor], dtDword, Cursor);
    end;
    sdtCtxToc:
    begin
      AddString(OutString, ACTX_TOC_HEADER);
      AddString(OutString, 'HeaderSize', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'EntryCount', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'FirstEntryOffset', @Buff[Cursor], dtDword, Cursor, GetOffset);
      AddString(OutString, 'Flags', @Buff[Cursor], dtDword, Cursor);
    end;
    sdtCtxTocEntry:
    begin
      AddString(OutString, ACTX_TOC_HEADER_ENTRY);
      AddString(OutString, 'Id', @Buff[Cursor], dtDword, Cursor, IdToStr);
      AddString(OutString, 'Offset', @Buff[Cursor], dtDword, Cursor, GetOffset);
      AddString(OutString, 'Length', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'Format', @Buff[Cursor], dtDword, Cursor);
    end;
    sdtCtxExtToc:
    begin
      AddString(OutString, ACTX_EXTOC_HEADER);
      AddString(OutString, 'ExtensionGuid', @Buff[Cursor], dtGUID, Cursor);
      AddString(OutString, 'TocOffset', @Buff[Cursor], dtDword, Cursor, GetOffset);
      AddString(OutString, 'Length', @Buff[Cursor], dtDword, Cursor);
    end;
    sdtCtxExtTocEntry:
    begin
      AddString(OutString, ACTX_EXTOC_HEADER_ENTRY);
      AddString(OutString, 'Id', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'Offset', @Buff[Cursor], dtDword, Cursor, GetOffset);
      AddString(OutString, 'Length', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'Format', @Buff[Cursor], dtDword, Cursor);
    end;
    sdtCtxAssemblyRoster:
    begin
      AddString(OutString, ACTX_ASSEMBLY_ROSTER_HEADER);
      AddString(OutString, 'HeaderSize', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'HashAlgorithm', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'EntryCount', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'FirstEntryOffset', @Buff[Cursor], dtDword, Cursor, GetOffset);
      AddString(OutString, 'AssemblyInformationSectionOffset', @Buff[Cursor], dtDword, Cursor, GetOffset);
    end;
    sdtCtxAssemblyRosterEntry:
    begin
      AddString(OutString, ACTX_ASSEMBLY_ROSTER_ENTRY);
      case PDWORD(@Buff[Cursor])^ of
        ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY_INVALID: FlagStr := 'Reserved';
        ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY_ROOT: FlagStr := 'Root';
      else
        FlagStr := EmptyStr;
      end;
      AddString(OutString, 'Flags', @Buff[Cursor], dtDword, Cursor, FlagStr);
      AddString(OutString, 'PseudoKey', @Buff[Cursor], dtDword, Cursor);
      ReadCtxString('AssemblyName');
      AddString(OutString, 'AssemblyInformationOffset', @Buff[Cursor], dtDword, Cursor, GetOffset);
      AddString(OutString, 'AssemblyInformationLength', @Buff[Cursor], dtDword, Cursor);
    end;
    sdtCtxStrSecHeader:
    begin
      AddString(OutString, ACTX_STRING_HEADER);
      AddString(OutString, 'Magic', @Buff[Cursor], dtDword, Cursor, 'SsHd');
      AddString(OutString, 'HeaderSize', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'FormatVersion', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'DataFormatVersion', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'Flags', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'ElementCount', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'ElementListOffset', @Buff[Cursor], dtDword, Cursor, GetOffset);
      AddString(OutString, 'HashAlgorithm', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'SearchStructureOffset', @Buff[Cursor], dtDword, Cursor, GetOffset);
      AddString(OutString, 'UserDataOffset', @Buff[Cursor], dtDword, Cursor, GetOffset);
      AddString(OutString, 'UserDataSize', @Buff[Cursor], dtDword, Cursor);
    end;
    sdtCtxStrSecEntry:
    begin
      AddString(OutString, ACTX_STRING_ENTRY);
      AddString(OutString, 'PseudoKey', @Buff[Cursor], dtDword, Cursor);
      ReadCtxString('Key');
//      AddString(OutString, 'KeyOffset', @Buff[Cursor], dtDword, Cursor);
//      AddString(OutString, 'KeyLength', @Buff[Cursor], dtDword, Cursor);
      //ReadCtxString(EmptyStr);
      AddString(OutString, 'Offset', @Buff[Cursor], dtDword, Cursor, GetOffset);
      AddString(OutString, 'Length', @Buff[Cursor], dtDword, Cursor);
      AddString(OutString, 'AssemblyRosterIndex', @Buff[Cursor], dtDword, Cursor);
    end;
  end;
end;

procedure DumpMemoryFromBuffWithCheckRawData(var OutString: string;
  Process: THandle; Address: Pointer; RawBuff: TMemoryDump; Cursor: NativeUInt);
var
  UnknownSize: ULONG_PTR;
  DataList: TList<TSymbolData>;
  ptrData: TSymbolData;
begin
  MaxSize := Length(RawBuff);

  // проверка всех известных данных, полученых от RawScanner-а
  DataList := SymbolStorage.GetKnownAddrList(ULONG_PTR(Address) + Cursor, MaxSize - Cursor);
  while DataList.Count > 0 do
  begin
    ptrData := DataList.List[0];
    DataList.Delete(0);

    // проверка рассинхронизации (на всякий случай)
    if ptrData.AddrVA < Cursor then
      Continue;

    // первым делом заполняем неизвестные области памяти дампом
    UnknownSize := ptrData.AddrVA - (ULONG_PTR(Address) + Cursor);
    if UnknownSize > 0 then
    begin
      AddString(OutString, MemoryDumpHeader);
      AddString(OutString, ByteToHexStr(ULONG_PTR(Address) + Cursor, @RawBuff[Cursor], UnknownSize));
      Inc(Cursor, UnknownSize);
    end;

    // дальше вызываем обработчик под каждый конкретный тип блока
    try
      case ptrData.DataType of
        sdtLdrData32..sdtLdrEntry64:
          DumpLoaderData(OutString, Process, ptrData.DataType, Address, RawBuff, Cursor);
        sdtCtxProcess..sdtCtxStrSecEntry:
          DumpActivationContext(OutString, Process, ptrData, Address, RawBuff, Cursor);
      end;
    except
      on E: EAbort do  // вывод структуры может попасть в конец страницы
        OutString := OutString + '...no more data';
    end;
  end;

  // ну и в завершение выводим все что остается
  if Cursor < MaxSize then
  begin
    AddString(OutString, MemoryDumpHeader);
    AddString(OutString, ByteToHexStr(ULONG_PTR(Address) + Cursor, @RawBuff[Cursor], MaxSize - Cursor));
  end;
end;

// = Модули дизассеблирования, нужно вынести в отдельный модуль ================

function Disassembly(Process: THandle; Address: Pointer;
  AMode: TDasmMode; KnownHint: TKnownHint; out Dasm64Mode: Boolean;
  nSize: Integer): string;
var
  Buff: TMemoryDump;
  Size, RegionSize: NativeUInt;
  Symbols: TSymbols;
  dwLength: DWORD;
  MBI: TMemoryBasicInformation;
  OwnerName: array [0..MAX_PATH - 1] of Char;
  Path: string;
begin
  Result := '';
  if nSize = 0 then
    Size := 4096
  else
    Size := nSize;
  SetLength(Buff, Size);
  if not ReadProcessData(Process, Address, @Buff[0],
    Size, RegionSize, rcReadAllwais) then Exit;

  dwLength := SizeOf(TMemoryBasicInformation);
  if VirtualQueryEx(Process,
     Address, MBI, dwLength) <> dwLength then Exit;

  case AMode of
    dmAuto: Dasm64Mode := MemoryMapCore.Process64;
    dmX86: Dasm64Mode := False;
  else
    Dasm64Mode := True;
  end;

  if GetMappedFileName(Process, MBI.AllocationBase,
    @OwnerName[0], MAX_PATH) > 0 then
  begin
    Path := NormalizePath(string(OwnerName));
    if AMode = dmAuto then
      CheckPEImage(Process, MBI.AllocationBase, Dasm64Mode);
    Symbols := TSymbols.Create(Process);
    try
      Result := DisassemblyFromBuff(Process, Buff, Symbols,
        Address, MBI.AllocationBase, Path, Dasm64Mode, Size, KnownHint);
    finally
      Symbols.Free;
    end;
  end
  else
    Result :=
      DisassemblyFromBuff(Process, Buff, nil,
        Address, MBI.AllocationBase, '', Dasm64Mode, Size, KnownHint);
end;

function DisassemblyFromBuff(Process: THandle; RawBuff: TMemoryDump;
  Symbols: TSymbols; Address, AllocationBase: Pointer;
  const ModuleName: string; Is64: Boolean; nSize: NativeUInt;
  KnownHint: TKnownHint): string;

  function HexUpperCase(const Value: string): string;
  begin
    Result := UpperCase(Value);
    Result := StringReplace(Result, '0X', '0x', [rfReplaceAll]);
  end;

type
  TInsructionType = (itOther, itNop, itInt, itRet, itCall,
    itJmp, itMov, itUndefined, itBreak);
  TCallType = (ctUnknown, ctAddress, ctRipOffset, ctPointer4, ctPointer8);

var
  AddrMask: UInt64;

  function GetInstructionType(Value: TDInst): TInsructionType;
  begin
    Result := itOther;
    case _InstructionType(Value.opcode) of
      I_NOP, I_FNOP: Result := itNop;
      I_INT, I_INT1, I_INT3, I_INTO, I_IN, I_OUT: Result := itInt;
      I_RET, I_RETF, I_IRET: Result := itRet;
      I_CALL, I_CALL_FAR: Result := itCall;
      I_JA, I_JAE, I_JB, I_JBE, I_JCXZ, I_JECXZ, I_JG, I_JGE,
      I_JL, I_JLE, I_JMP, I_JMP_FAR, I_JNO, I_JNP, I_JNS, I_JNZ,
      I_JO, I_JP, I_JRCXZ, I_JS, I_JZ: Result := itJmp;
      I_MOV: Result := itMov;
      I_UNDEFINED: Result := itUndefined;
      I_RDMSR, I_WRMSR, I_CLI, I_STI, I_HLT:
        Result := itBreak;
    end;
  end;

  function GetCallType(const Value: string; Inst: TDInst;
    out Address: Int64): TCallType;
  var
    I: Integer;
  begin
    Result := ctUnknown;
    I := Inst.opsNo;
    while I >= 0  do
    begin
      case _OperandType(Inst.ops[I]._type) of
        O_PC:
        begin
          {$OVERFLOWCHECKS OFF}
          Address := Int64((Inst.addr + Inst.size + UInt64(Inst.imm.sqword)) and AddrMask);
          {$OVERFLOWCHECKS ON}
          Exit(ctAddress);
        end;
        O_DISP, O_SMEM:
        begin
          Address := Int64(Inst.disp and AddrMask);
          if Inst.flags and FLAG_RIP_RELATIVE <> 0 then
            Exit(ctRipOffset)
          else
            case Inst.dispSize of
              64: Exit(ctPointer8);
              32: Exit(ctPointer4);
            end;
        end;
      end;
      Dec(I);
    end;
  end;

  function GetCallHint(CallAddr: Int64): string;
  var
    MBI: TMemoryBasicInformation;
    dwLength: Cardinal;
    OwnerName: array [0..MAX_PATH - 1] of Char;
    Path: string;
  begin
    Result := EmptyStr;
    if CallAddr <> 0 then
    begin
      Result := MemoryMapCore.DebugMapData.GetDescriptionAtAddr(ULONG_PTR(CallAddr));
      if Result = EmptyStr then
      begin
        if Symbols <> nil then
        begin
          dwLength := SizeOf(TMemoryBasicInformation);
          if VirtualQueryEx(Process,
             Pointer(CallAddr), MBI, dwLength) <> dwLength then Exit;
          if Symbols.BaseAddress = ULONG_PTR(MBI.AllocationBase) then
            Result := Symbols.GetDescriptionAtAddr(ULONG_PTR(CallAddr))
          else
          begin
            if not CheckPEImage(Process, MBI.AllocationBase) then Exit;
            if GetMappedFileName(Process, MBI.AllocationBase,
              @OwnerName[0], MAX_PATH) = 0 then Exit;
            Path := NormalizePath(string(OwnerName));
            Result := Symbols.GetDescriptionAtAddr2(
              ULONG_PTR(CallAddr), ULONG_PTR(MBI.AllocationBase), Path);
            if Result = EmptyStr then
              Result := ExtractFileName(Path) + '+' +
                IntToHex(ULONG_PTR(CallAddr) - ULONG_PTR(MBI.AllocationBase));
          end;
        end;
      end;

      if (Result <> EmptyStr) and Assigned(KnownHint) then
        KnownHint.AddOrSetValue(Result, CallAddr);

      if Result <> EmptyStr then
        Result := ' // ' + Result;
    end;
  end;

var
  Cursor: NativeUInt;
  I: Integer;
  ci: TCodeInfo;
  DecodedInst: array [0..14] of TDInst;
  usedInstructionsCount: UInt32;
  decodedInstruction: TDecodedInst;
  Line, mnemonic, HintStr: string;
  LastInsruction, CurrentInstruction: TInsructionType;
  CallType: TCallType;
  CallAddr: Int64;
  OffsetAddr: Uint64;
  Size, RegionSize: NativeUInt;
begin
  Result := '';
  Cursor := 0;
  LastInsruction := itOther;
  AddString(Result, DisasmDumpHeader);
  if Symbols <> nil then
    Symbols.Init(ULONG_PTR(AllocationBase), ModuleName);
  try
    while Cursor < nSize do
    begin
      ZeroMemory(@ci, SizeOf(TCodeInfo));
      ci.codeOffset := UInt64(Address) + Cursor;
      if Is64 then
      begin
        AddrMask := UInt64(-1);
        ci.dt := Decode64Bits;
      end
      else
      begin
        AddrMask := UInt32(-1);
        ci.dt := Decode32Bits;
      end;
      ci.addrMask := AddrMask;
      ci.code := @RawBuff[Cursor];
      ci.features := DF_USE_ADDR_MASK;
      ci.codeLen := nSize - Cursor;

      if distorm_decompose(
        @ci, @DecodedInst[0], 15, @usedInstructionsCount) = DECRES_INPUTERR then
      begin
        AddString(Result, 'Disassembly input error. Halting!', EmptyStr);
        Break;
      end;

      for I := 0 to usedInstructionsCount - 1 do
      begin

        distorm_format(@ci, @DecodedInst[I], @decodedInstruction);
        mnemonic := HexUpperCase(GET_WString(decodedInstruction.mnemonic));
        CurrentInstruction := GetInstructionType(DecodedInst[I]);
        HintStr := '';
        CallType := ctUnknown;
        case CurrentInstruction of
          itOther:
            if LastInsruction in [itNop, itInt, itRet, itUndefined, itBreak] then
              AddString(Result, '');
          itNop:
            if LastInsruction in [itOther, itInt, itRet, itCall, itJmp, itUndefined, itBreak] then
              AddString(Result, '');
          itInt:
            if LastInsruction in [itOther, itNop, itRet, itCall, itJmp, itUndefined, itBreak] then
              AddString(Result, '');
          itUndefined, itBreak:
            if LastInsruction in [itOther, itNop, itRet, itCall, itJmp] then
              AddString(Result, '');
          itCall, itJmp, itMov:
          begin
            if LastInsruction in [itNop, itInt, itRet, itUndefined, itBreak] then
              AddString(Result, '');
            CallType :=
              GetCallType(GET_WString(decodedInstruction.operands), DecodedInst[I], CallAddr);
            case CallType of
              ctAddress: HintStr := GetCallHint(CallAddr);
              ctRipOffset:
              begin
                {$OVERFLOWCHECKS OFF}
                OffsetAddr :=
                  DecodedInst[I].addr +
                  DecodedInst[I].size + NativeUInt(CallAddr);
                {$OVERFLOWCHECKS ON}
                Size := 8;
                if ReadProcessData(Process, Pointer(OffsetAddr), @CallAddr,
                  Size, RegionSize, rcReadAllwais) then
                  HintStr := GetCallHint(CallAddr);
              end;
              ctPointer4, ctPointer8:
              begin
                if CallType = ctPointer4 then
                  Size := 4
                else
                  Size := 8;
                if ReadProcessData(Process, Pointer(CallAddr), @CallAddr,
                  Size, RegionSize, rcReadAllwais) then
                  HintStr := GetCallHint(CallAddr);
              end;
            end;
          end;
        end;
        LastInsruction := CurrentInstruction;

        Line := MemoryMapCore.DebugMapData.GetDescriptionAtAddr(ULONG_PTR(Address) + Cursor);
        if Line <> EmptyStr then
          AddString(Result, Line)
        else
        begin
          if Symbols <> nil then
          begin
            Line := Symbols.GetDescriptionAtAddr(ULONG_PTR(Address) + Cursor);
            if Line <> EmptyStr then
              AddString(Result, Line);
          end;
        end;

        if (HintStr = EmptyStr) and (CallType = ctRipOffset) then
          HintStr := ' // 0x' + IntToHex(CallAddr, 8)
        else
          // segments
          if not SEGMENT_IS_DEFAULT_OR_NONE(DecodedInst[I].segment) then
            case _RegisterType(SEGMENT_GET(DecodedInst[I].segment)) of
              R_FS: if not Is64 then HintStr := ' // _TEB';
              R_GS: if Is64 then HintStr := ' // _TEB';
            end;

        AddString(Result,
          Format('%s: %s %s %s %s', [
            IntToHex(decodedInstruction.offset, 8),
            AsmToHexStr(ULONG_PTR(Address) + Cursor, @RawBuff[Cursor], decodedInstruction.size),
            mnemonic,
            HexUpperCase(GET_WString(decodedInstruction.operands)),
            HintStr
          ]));
        Inc(Cursor, DecodedInst[I].size);
      end;

    end;
  finally
    if Symbols <> nil then
      Symbols.Release;
  end;
end;

end.
