////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uDumpDisplayUtils.pas
//  * Purpose   : Вспомогательный модуль для отображения содержимого
//  *           : памяти в свойствах региона и размапленных структур
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2015.
//  * Version   : 1.01
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
  PsAPI,
  uUtils,
  MemoryMap.Symbols,
  MemoryMap.Utils,
  distorm;

  function DumpMemory(Process: THandle; Address: Pointer; nSize: Integer = 0): string;
  function DumpMemoryFromBuff(RawBuff: TMemoryDump; Address: Pointer; nSize: Integer): string;
  function DumpPEB32(Process: THandle; Address: Pointer): string;
  function DumpPEB64(Process: THandle; Address: Pointer): string;
  function DumpPEHeader(Process: THandle; Address: Pointer): string;
  function DumpThread64(Process: THandle; Address: Pointer): string;
  function DumpThread32(Process: THandle; Address: Pointer): string;
  function DumpKUserSharedData(Process: THandle; Address: Pointer): string;
  function DumpProcessParameters32(Process: THandle; Address: Pointer): string;
  function DumpProcessParameters64(Process: THandle; Address: Pointer): string;
  function Disassembly(Process: THandle; Address: Pointer;
    Is64: Boolean; nSize: Integer = 0): string;
  function DisassemblyFromBuff(RawBuff: TMemoryDump; Symbols: TSymbols;
    Address, AllocationBase: Pointer; const ModuleName: string;
    Is64: Boolean; nSize: NativeUInt): string;

const
  EmptyHeader =
    '----------------------------------------------------------------------------------------------------------';

implementation

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
type
  TDataType = (dtByte, dtWord, dtDword,
    dtInt64, dtGUID, dtString, dtAnsiString, dtBuff, dtUnicodeString32,
    dtUnicodeString64);

  Pointer32 = DWORD;

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
  Size, RegionSize: NativeUInt;
begin
  Result := '';
  if nSize = 0 then
    Size := 4096
  else
    Size := nSize;
  SetLength(Buff, Size);
  if not ReadProcessData(Process, Address, @Buff[0],
    Size, RegionSize, rcReadAllwais) then Exit;
  Result := DumpMemoryFromBuff(Buff, Address, Size);
end;

function DumpMemoryFromBuff(RawBuff: TMemoryDump; Address: Pointer; nSize: Integer): string;
begin
  AddString(Result, MemoryDumpHeader);
  AddString(Result, ByteToHexStr(ULONG_PTR(Address), @RawBuff[0], nSize));
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

function ExtractUnicodeString32(Process: THandle; Address: Pointer): string;
var
  Size, Dummy: NativeUInt;
begin
  Result := '';
  Size := PWord(Address)^;
  Address := PByte(Address) + 4;
  Address := Pointer(PDWORD(Address)^);
  if Size > 0 then
  begin
    SetLength(Result, Size div 2);
    ReadProcessData(Process, Address, @Result[1],
      Size, Dummy, rcReadAllwais);
  end;
  Result := '[' + IntToHex(ULONG_PTR(Address), 1) + '] "' + PChar(Result) + '"';
end;

function ExtractUnicodeString64(Process: THandle; Address: Pointer): string;
var
  Size, Dummy: NativeUInt;
begin
  Result := '';
  Size := PDWORD(Address)^;
  Address := PByte(Address) + 8;
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
  Buff: array of Byte;
  Size, Dummy, Cursor: NativeUInt;
  ValueBuff: DWORD;
begin
  Result := '';
  CurerntAddr := Address;
  Size := 4096;
  SetLength(Buff, Size);
  if not ReadProcessData(Process, Address, @Buff[0],
    Size, Dummy, rcReadAllwais) then Exit;
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
    AddString(Result, 'CSDVersion = ' + ExtractUnicodeString32(Process, @Buff[Cursor]),
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

  AddString(Result, MemoryDumpHeader);
  AddString(Result, ByteToHexStr(ULONG_PTR(Address) + Cursor, @Buff[Cursor], Size - Cursor));
end;

function DumpPEB64(Process: THandle; Address: Pointer): string;
var
  Buff: array of Byte;
  Size, RegionSize, Cursor: NativeUInt;
  ValueBuff: DWORD;
begin
  Result := '';
  CurerntAddr := Address;
  Size := 4096;
  SetLength(Buff, Size);
  if not ReadProcessData(Process, Address, @Buff[0],
    Size, RegionSize, rcReadAllwais) then Exit;
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
    AddString(Result, 'CSDVersion = ' + ExtractUnicodeString64(Process, @Buff[Cursor]),
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

  AddString(Result, MemoryDumpHeader);
  AddString(Result, ByteToHexStr(ULONG_PTR(Address) + Cursor, @Buff[Cursor], Size - Cursor));
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
  Buff: array of Byte;
  Size, RegionSize, Cursor: NativeUInt;
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
  Size := 4096;
  SetLength(Buff, Size);
  if not ReadProcessData(Process, Address, @Buff[0],
    Size, RegionSize, rcReadAllwais) then Exit;
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
  AddString(Result, MemoryDumpHeader);
  AddString(Result, ByteToHexStr(ULONG_PTR(Address) + Cursor, @Buff[Cursor], Size - Cursor));
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
  Buff: array of Byte;
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
  AddString(Result, 'StaticUnicodeString = ' + ExtractUnicodeString64(Process, @Buff[Cursor]),
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
  AddString(Result, 'ReservedForOle', @Buff[Cursor], dtInt64, Cursor);
  Assert(Cursor = $1760);
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
  Buff: array of Byte;
  Size, RegionSize, Cursor: NativeUInt;
  ValueBuff: DWORD;
begin
  Result := '';
  CurerntAddr := Address;
  Size := 4096;
  SetLength(Buff, Size);
  if not ReadProcessData(Process, Address, @Buff[0],
    Size, RegionSize, rcReadAllwais) then Exit;
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
  AddString(Result, 'StaticUnicodeString = ' + ExtractUnicodeString32(Process, @Buff[Cursor]),
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

  AddString(Result, MemoryDumpHeader);
  AddString(Result, ByteToHexStr(ULONG_PTR(Address) + Cursor, @Buff[Cursor], Size - Cursor));
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

function MitigationPoliciesToStr(Value: Byte): string;

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

function DbgFlagToStr(Value: Byte): string;

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
        ULONG SharedDataFlags;
        struct
        {
            ULONG DbgErrorPortPresent : 1;
            ULONG DbgElevationEnabled : 1;
            ULONG DbgVirtEnabled : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgLkgEnabled : 1;
            ULONG DbgDynProcessorEnabled : 1;
            ULONG DbgConsoleBrokerEnabled : 1;
            ULONG DbgSecureBootEnabled : 1;
            ULONG SpareBits : 24;
        };
    };
  *)
  if Value and 1 <> 0 then AddResult('DbgErrorPortPresent');
  if Value and 2 <> 0 then AddResult('DbgElevationEnabled');
  if Value and 4 <> 0 then AddResult('DbgVirtEnabled');
  if Value and 8 <> 0 then AddResult('DbgInstallerDetectEnabled');
  if Value and 16 <> 0 then AddResult('DbgLkgEnabled');
  if Value and 32 <> 0 then AddResult('DbgDynProcessorEnabled');
  if Value and 64 <> 0 then AddResult('DbgConsoleBrokerEnabled');
  if Value and 128 <> 0 then AddResult('DbgSecureBootEnabled');
end;

function DumpKUserSharedData(Process: THandle; Address: Pointer): string;
var
  Buff: array of Byte;
  Size, RegionSize, Cursor: NativeUInt;
  ValueBuff: DWORD;
begin
  Result := '';
  CurerntAddr := Address;
  Size := 4096;
  SetLength(Buff, Size);
  if not ReadProcessData(Process, Address, @Buff[0],
    Size, RegionSize, rcReadAllwais) then Exit;
  Cursor := 0;
  AddString(Result, KUSER);
  AddString(Result, 'TickCountLowDeprecated', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TickCountMultiplier', @Buff[Cursor], dtDword, Cursor);
  DumpKSystemTime(Result, 'InterruptTime', @Buff[Cursor], Cursor);
  DumpKSystemTime(Result, 'SystemTime', @Buff[Cursor], Cursor);
  DumpKSystemTime(Result, 'TimeZoneBias', @Buff[Cursor], Cursor);
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
  AddString(Result, 'Reserved2', @Buff[Cursor], dtInt64, Cursor);
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
  AddString(Result, 'AltArchitecturePad', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'SystemExpirationDate', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'SuiteMask', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'KdDebuggerEnabled', @Buff[Cursor], dtByte, Cursor);
  ValueBuff := PByte(@Buff[Cursor])^;
  AddString(Result, 'MitigationPolicies', @Buff[Cursor], dtByte, Cursor,
    MitigationPoliciesToStr(ValueBuff));
  AddString(Result, 'Reserved6', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'ActiveConsoleId', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'DismountCount', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ComPlusPackage', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'LastSystemRITEventTickCount', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NumberOfPhysicalPages', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'SafeBootMode', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'Reserved12', Address, dtBuff, 3, Cursor);
  ValueBuff := PDWORD(@Buff[Cursor])^;
  AddString(Result, 'SharedDataFlags', @Buff[Cursor], dtDword, Cursor,
    DbgFlagToStr(ValueBuff));
  AddString(Result, 'DataFlagsPad', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TestRetInstruction', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'QpcFrequency', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'SystemCallPad', @Buff[Cursor], dtBuff, 24, Cursor);
  AddString(Result, EmptyHeader);
  DumpKSystemTime(Result, 'TickCount', @Buff[Cursor], Cursor);
  AddString(Result, 'TickCountPad', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Cookie', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'CookiePad', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ConsoleSessionForegroundProcessId', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'Wow64SharedInformation', @Buff[Cursor], dtBuff, 64, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'UserModeGlobalLogger', @Buff[Cursor], dtBuff, 32, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'ImageFileExecutionOptions', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'LangGenerationCount', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Reserved5', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'InterruptTimeBias', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'TscQpcBias', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ActiveProcessorCount', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ActiveGroupCount', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'Reserved4', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'AitSamplingValue', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'AppCompatFlag', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'SystemDllNativeRelocation', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'SystemDllWowRelocation', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, MemoryDumpHeader);
  AddString(Result, ByteToHexStr(ULONG_PTR(Address) + Cursor, @Buff[Cursor], Size - Cursor));
end;

procedure DumpRTL_DRIVE_LETTER_CURDIR32(var OutValue: string; const Description: string;
  Address: Pointer; var Cursor: NativeUInt; Process: THandle);
begin
  AddString(OutValue, Description + '.Flags', Address, dtWord, Cursor);
  Address := PByte(Address) + 2;
  AddString(OutValue, Description + '.Length', Address, dtWord, Cursor);
  Address := PByte(Address) + 2;
  AddString(OutValue, Description + '.TimeStamp', Address, dtDword, Cursor);
  Address := PByte(Address) + 4;
  AddString(OutValue, Description + '.DosPath = ' +
    ExtractUnicodeString32(Process, Address),
    Address, dtUnicodeString32, Cursor);
  AddString(OutValue, EmptyHeader);
end;

function DumpProcessParameters32(Process: THandle; Address: Pointer): string;
const
  RTL_MAX_DRIVE_LETTERS = 32;
var
  Buff: array of Byte;
  Size, RegionSize, Cursor: NativeUInt;
  I: Integer;
begin
  Result := '';
  CurerntAddr := Address;
  Size := 4096;
  SetLength(Buff, Size);
  if not ReadProcessData(Process, Address, @Buff[0],
    Size, RegionSize, rcReadAllwais) then Exit;
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
  AddString(Result, 'CurrentDirectory.DosPath = ' + ExtractUnicodeString32(Process, @Buff[Cursor]),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(Result, 'CurrentDirectory.Handle', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'DllPath = ' + ExtractUnicodeString32(Process, @Buff[Cursor]),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(Result, 'ImagePathName = ' + ExtractUnicodeString32(Process, @Buff[Cursor]),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(Result, 'CommandLine = ' + ExtractUnicodeString32(Process, @Buff[Cursor]),
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
  AddString(Result, 'WindowTitle = ' + ExtractUnicodeString32(Process, @Buff[Cursor]),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(Result, 'DesktopInfo = ' + ExtractUnicodeString32(Process, @Buff[Cursor]),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(Result, 'ShellInfo = ' + ExtractUnicodeString32(Process, @Buff[Cursor]),
    @Buff[Cursor], dtUnicodeString32, Cursor);
  AddString(Result, 'RuntimeData = ' + ExtractUnicodeString32(Process, @Buff[Cursor]),
    @Buff[Cursor], dtUnicodeString32, Cursor);

  AddString(Result, EmptyHeader);
  for I := 0 to RTL_MAX_DRIVE_LETTERS - 1 do
    DumpRTL_DRIVE_LETTER_CURDIR32(Result,
      'DLCurrentDirectory' + IntToStr(I + 1), @Buff[Cursor], Cursor, Process);

  AddString(Result, 'EnvironmentSize', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'EnvironmentVersion', @Buff[Cursor], dtDword, Cursor);

  AddString(Result, MemoryDumpHeader);
  AddString(Result, ByteToHexStr(ULONG_PTR(Address) + Cursor, @Buff[Cursor], Size - Cursor));
end;

procedure DumpRTL_DRIVE_LETTER_CURDIR64(var OutValue: string; const Description: string;
  Address: Pointer; var Cursor: NativeUInt; Process: THandle);
begin
  AddString(OutValue, Description + '.Flags', Address, dtWord, Cursor);
  Address := PByte(Address) + 2;
  AddString(OutValue, Description + '.Length', Address, dtWord, Cursor);
  Address := PByte(Address) + 2;
  AddString(OutValue, Description + '.TimeStamp', Address, dtDword, Cursor);
  Address := PByte(Address) + 4;
  AddString(OutValue, Description + '.DosPath = ' +
    ExtractUnicodeString64(Process, Address),
    Address, dtUnicodeString64, Cursor);
  AddString(OutValue, EmptyHeader);
end;

function DumpProcessParameters64(Process: THandle; Address: Pointer): string;
const
  RTL_MAX_DRIVE_LETTERS = 32;
var
  Buff: array of Byte;
  Size, RegionSize, Cursor: NativeUInt;
  I: Integer;
begin
  Result := '';
  CurerntAddr := Address;
  Size := 4096;
  SetLength(Buff, Size);
  if not ReadProcessData(Process, Address, @Buff[0],
    Size, RegionSize, rcReadAllwais) then Exit;
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
  AddString(Result, 'CurrentDirectory.DosPath = ' + ExtractUnicodeString64(Process, @Buff[Cursor]),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(Result, 'CurrentDirectory.Handle', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'DllPath = ' + ExtractUnicodeString64(Process, @Buff[Cursor]),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(Result, 'ImagePathName = ' + ExtractUnicodeString64(Process, @Buff[Cursor]),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(Result, 'CommandLine = ' + ExtractUnicodeString64(Process, @Buff[Cursor]),
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

  AddString(Result, 'WindowTitle = ' + ExtractUnicodeString64(Process, @Buff[Cursor]),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(Result, 'DesktopInfo = ' + ExtractUnicodeString64(Process, @Buff[Cursor]),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(Result, 'ShellInfo = ' + ExtractUnicodeString64(Process, @Buff[Cursor]),
    @Buff[Cursor], dtUnicodeString64, Cursor);
  AddString(Result, 'RuntimeData = ' + ExtractUnicodeString64(Process, @Buff[Cursor]),
    @Buff[Cursor], dtUnicodeString64, Cursor);

  AddString(Result, EmptyHeader);
  for I := 0 to RTL_MAX_DRIVE_LETTERS - 1 do
    DumpRTL_DRIVE_LETTER_CURDIR64(Result,
      'DLCurrentDirectory' + IntToStr(I + 1), @Buff[Cursor], Cursor, Process);

  AddString(Result, 'EnvironmentSize', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'EnvironmentVersion', @Buff[Cursor], dtInt64, Cursor);

  AddString(Result, MemoryDumpHeader);
  AddString(Result, ByteToHexStr(ULONG_PTR(Address) + Cursor, @Buff[Cursor], Size - Cursor));
end;

function Disassembly(Process: THandle; Address: Pointer;
  Is64: Boolean; nSize: Integer): string;
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

  if GetMappedFileName(Process, MBI.AllocationBase,
    @OwnerName[0], MAX_PATH) > 0 then
  begin
    Path := NormalizePath(string(OwnerName));
    Symbols := TSymbols.Create(Process);
    try
      Result := DisassemblyFromBuff(Buff, Symbols,
        Address, MBI.AllocationBase, Path, Is64, Size);
    finally
      Symbols.Free;
    end;
  end
  else
    Result := DisassemblyFromBuff(Buff, nil,
      Address, nil, '', Is64, Size);
end;

function DisassemblyFromBuff(RawBuff: TMemoryDump; Symbols: TSymbols;
  Address, AllocationBase: Pointer; const ModuleName: string;
  Is64: Boolean; nSize: NativeUInt): string;

  function HexUpperCase(const Value: string): string;
  begin
    Result := UpperCase(Value);
    Result := StringReplace(Result, '0X', '0x', []);
  end;

type
  TInsructionType = (itOther, itNop, itInt, itRet);

  function GetInstructionType(const Value: string): TInsructionType;
  begin
    Result := itOther;
    if Length(Value) < 3 then Exit;
    if (Value[1] = 'N') and (Value[2] = 'O') and (Value[3] = 'P') then
      Result := itNop;
    if (Value[1] = 'I') and (Value[2] = 'N') and (Value[3] = 'T') then
      Result := itInt;
    if (Value = 'RET') or (Value = 'IRET') or (Value = 'RETF') then
      Result := itRet;
  end;

var
  Cursor: NativeUInt;
  I: Integer;
  DecodedInst: array [0..14] of TDecodedInst;
  usedInstructionsCount: UInt32;
  DecodeType: _DecodeType;
  Line, mnemonic: string;
  LastInsruction, CurrentInstruction: TInsructionType;
begin
  Result := '';
  Cursor := 0;
  LastInsruction := itOther;
  AddString(Result, DisasmDumpHeader);
  if Is64 then
    DecodeType := Decode64Bits
  else
    DecodeType := Decode32Bits;
  if Symbols <> nil then
    Symbols.Init(ULONG_PTR(AllocationBase), ModuleName);
  try
    while Cursor < nSize do
    begin
      if distorm_decode(UInt64(Address) + Cursor, @RawBuff[Cursor], nSize - Cursor,
        DecodeType, @DecodedInst[0], 15, @usedInstructionsCount) <> DECRES_NONE then
      begin
        for I := 0 to usedInstructionsCount - 1 do
        begin

          mnemonic := HexUpperCase(GET_WString(DecodedInst[I].mnemonic));
          CurrentInstruction := GetInstructionType(mnemonic);
          case CurrentInstruction of
            itOther:
              if LastInsruction in [itNop, itInt, itRet] then
                AddString(Result, '');
            itNop:
               if LastInsruction in [itOther, itInt, itRet] then
                AddString(Result, '');
            itInt:
               if LastInsruction in [itOther, itNop, itRet] then
                AddString(Result, '');
          end;
          LastInsruction := CurrentInstruction;

          if Symbols <> nil then
          begin
            Line := Symbols.GetDescriptionAtAddr(ULONG_PTR(Address) + Cursor);
            if Line <> '' then
              AddString(Result, Line);
          end;

          AddString(Result,
            Format('%s: %s %s %s', [
              IntToHex(DecodedInst[I].offset, 8),
              AsmToHexStr(ULONG_PTR(Address) + Cursor, @RawBuff[Cursor], DecodedInst[I].size),
              mnemonic,
              HexUpperCase(GET_WString(DecodedInst[I].operands))
            ]));
          Inc(Cursor, DecodedInst[I].size);
        end;
      end;
    end;
  finally
    if Symbols <> nil then
      Symbols.Release;
  end;
end;


end.
