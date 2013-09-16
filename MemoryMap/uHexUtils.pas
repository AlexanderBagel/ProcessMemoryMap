unit uHexUtils;

interface

uses
  Winapi.Windows,
  System.SysUtils;

  function ByteToHexStr(Base: NativeUInt; Data: Pointer;
    Len: Integer; const Comment: string = ''): string;
  function DumpMemory(Process: THandle; Address: Pointer): string;
  function DumpPEBWow64(Process: THandle; Address: Pointer): string;
  function DumpThreadWow64(Process: THandle; Address: Pointer): string;

implementation

uses
  uUtils;

const
  MemoryDumpHeader =
    '-------------------------------------------- Memory dump -------------------------------------------------';
  PEBHeader =
    '------------------------------------- Process Environment Block ------------------------------------------';
  TEB_Header =
    '-------------------------------------- Thread Environment Block ------------------------------------------';
  EmptyHeader =
    '----------------------------------------------------------------------------------------------------------';
type
  TDataType = (dtByte, dtWord, dtDword,
    dtInt64, dtString, dtAnsiString, dtBuff);

function ByteToHexStr(Base: NativeUInt; Data: Pointer;
  Len: Integer; const Comment: string): string;
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

procedure AddString(var OutValue: string; const NewString: string); overload;
begin
  OutValue := OutValue + NewString + sLineBreak;
end;

var
  CurerntAddr: Pointer;

procedure AddString(var OutValue: string; const Comment: string; Address: Pointer;
  DataType: TDataType; Size: Integer; var Cursor: NativeUInt); overload;
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
    dtString:
    begin
      SetLength(UString, Size div 2);
      Move(PByte(Address)^, UString[1], Size);
    end;
    dtAnsiString:
    begin
      SetLength(AString, Size);
      Move(PByte(Address)^, AString[1], Size);
      UString := string(AString);
    end;
  end;
  if UString = '' then
    AddString(OutValue, ByteToHexStr(NativeUInt(CurerntAddr) + Cursor, Address, Size, Comment))
  else
    AddString(OutValue, ByteToHexStr(NativeUInt(CurerntAddr) + Cursor, Address, Size,
    Comment + ' = ' + UString));
  Inc(Cursor, Size);
end;

procedure AddString(var OutValue: string; const Comment: string; Address: Pointer;
  DataType: TDataType; var Cursor: NativeUInt); overload;
begin
  case DataType of
    dtByte: AddString(OutValue, Comment, Address, DataType, 1, Cursor);
    dtWord: AddString(OutValue, Comment, Address, DataType, 2, Cursor);
    dtDword: AddString(OutValue, Comment, Address, DataType, 4, Cursor);
    dtInt64: AddString(OutValue, Comment, Address, DataType, 8, Cursor);
  end;
end;

function DumpMemory(Process: THandle; Address: Pointer): string;
var
  Buff: array of Byte;
  Size, RegionSize: NativeUInt;
begin
  Result := '';
  Size := 4096;
  SetLength(Buff, Size);
  if not ReadProcessData(Process, Address, @Buff[0],
    Size, RegionSize, rcReadAllwais) then Exit;
  AddString(Result, MemoryDumpHeader);
  AddString(Result, ByteToHexStr(ULONG_PTR(Address), @Buff[0], Size));
end;

function DumpPEBWow64(Process: THandle; Address: Pointer): string;
var
  Buff: array of Byte;
  Size, RegionSize, Cursor: NativeUInt;
begin
  Result := '';
  CurerntAddr := Address;
  Size := 4096;
  SetLength(Buff, Size);
  if not ReadProcessData(Process, Address, @Buff[0],
    Size, RegionSize, rcReadAllwais) then Exit;
  Cursor := 0;
  AddString(Result, PEBHeader);
  AddString(Result, 'InheritedAddressSpace', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'ReadImageFileExecOptions', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'BeingDebugged', @Buff[Cursor], dtByte, Cursor);
  AddString(Result, 'Spare', @Buff[Cursor], dtBuff, 5, Cursor);
  AddString(Result, 'Mutant', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ImageBaseAddress', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'LoaderData', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ProcessParameters', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'SubSystemData', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ProcessHeap', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'FastPebLock', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'FastPebLockRoutine', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'FastPebUnlockRoutine', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'EnvironmentUpdateCount', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'KernelCallbackTable', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'EventLogSection', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'EventLog', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'FreeList', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'TlsExpansionCounter', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'TlsBitmap', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'TlsBitmapBits[0]', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TlsBitmapBits[1]', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ReadOnlySharedMemoryBase', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ReadOnlySharedMemoryHeap', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ReadOnlyStaticServerData', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'InitAnsiCodePageData', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'InitOemCodePageData', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'InitUnicodeCaseTableData', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'KeNumberOfProcessors', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NtGlobalFlag', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Spare2', @Buff[Cursor], dtBuff, 8, Cursor);
  AddString(Result, 'MmCriticalSectionTimeout', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'MmHeapSegmentReserve', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'MmHeapSegmentCommit', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'MmHeapDeCommitTotalFreeThreshold', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'MmHeapDeCommitFreeBlockThreshold', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NumberOfHeaps', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'MaximumNumberOfHeaps', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ProcessHeapsListBuffer', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'GdiSharedHandleTable', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'ProcessStarterHelper', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'GdiDCAttributeList', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'LoaderLock', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'NtMajorVersion', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NtMinorVersion', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'NtBuildNumber', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'NtCSDVersion', @Buff[Cursor], dtWord, Cursor);
  AddString(Result, 'PlatformId', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'Subsystem', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'MajorSubsystemVersion', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'MinorSubsystemVersion', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'AffinityMask', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'GdiHandleBuffer', @Buff[Cursor], dtBuff, 136, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'PostProcessInitRoutine', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'TlsExpansionBitmap', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'TlsExpansionBitmapBits', @Buff[Cursor], dtBuff, 128, Cursor);
  AddString(Result, EmptyHeader);
  AddString(Result, 'SessionId', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'AppCompatFlags', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'CSDVersion', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, MemoryDumpHeader);
  AddString(Result, ByteToHexStr(ULONG_PTR(Address) + Cursor, @Buff[Cursor], Size - Cursor));
end;

function DumpThreadWow64(Process: THandle; Address: Pointer): string;
var
  Buff: array of Byte;
  Size, RegionSize, Cursor: NativeUInt;
begin
  Result := '';
  CurerntAddr := Address;
  Size := 4096;
  SetLength(Buff, Size);
  if not ReadProcessData(Process, Address, @Buff[0],
    Size, RegionSize, rcReadAllwais) then Exit;
  Cursor := 0;
  AddString(Result, TEB_Header);
  AddString(Result, 'SEH Chain', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'StackBase', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'StackLimit', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'SubSystemTib', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'FiberData', @Buff[Cursor], dtDword, Cursor);
  AddString(Result, 'ArbitraryUserPointer', @Buff[Cursor], dtInt64, Cursor);
  AddString(Result, 'Self', @Buff[Cursor], dtInt64, Cursor);
end;


end.
