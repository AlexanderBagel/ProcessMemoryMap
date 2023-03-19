////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.ActivationContext.pas
//  * Purpose   : Модуль для работы с контекстами активации процесса
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.0.11
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.ActivationContext;

interface

  {$I rawscanner.inc}

uses
  Windows,
  SysUtils,
  RawScanner.Types,
  {$IFNDEF DISABLE_LOGGER}
  RawScanner.Logger,
  {$ENDIF}
  RawScanner.SymbolStorage,
  RawScanner.Utils;

const
  // Standard Activation Context section IDs:
  ACTIVATION_CONTEXT_SECTION_ASSEMBLY_INFORMATION         = 1;
  ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION              = 2;
  ACTIVATION_CONTEXT_SECTION_WINDOW_CLASS_REDIRECTION     = 3;
  ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION       = 4;
  ACTIVATION_CONTEXT_SECTION_COM_INTERFACE_REDIRECTION    = 5;
  ACTIVATION_CONTEXT_SECTION_COM_TYPE_LIBRARY_REDIRECTION = 6;
  ACTIVATION_CONTEXT_SECTION_COM_PROGID_REDIRECTION       = 7;
  ACTIVATION_CONTEXT_SECTION_GLOBAL_OBJECT_RENAME_TABLE   = 8;
  ACTIVATION_CONTEXT_SECTION_CLR_SURROGATES               = 9;
  ACTIVATION_CONTEXT_SECTION_APPLICATION_SETTINGS         = 10;
  ACTIVATION_CONTEXT_SECTION_COMPATIBILITY_INFO           = 11;
  ACTIVATION_CONTEXT_SECTION_WINRT_ACTIVATABLE_CLASSES    = 12;

  // Activation Context section format identifiers:
  ACTIVATION_CONTEXT_SECTION_FORMAT_UNKNOWN               = 0;
  ACTIVATION_CONTEXT_SECTION_FORMAT_STRING_TABLE          = 1;
  ACTIVATION_CONTEXT_SECTION_FORMAT_GUID_TABLE            = 2;

  ACTIVATION_CONTEXT_DATA_MAGIC = $78746341; // 'xtcA'
  ACTIVATION_CONTEXT_STRING_SECTION_MAGIC = $64487353; // 'dHsS'
  ACTIVATION_CONTEXT_GUID_SECTION_MAGIC = $64487347; // 'dHsG'

type
  ACTIVATION_CONTEXT_DATA = record
    Magic,
    HeaderSize,
    FormatVersion,      // Windows 11 имеет версию 1!!!
    TotalSize,
    DefaultTocOffset,
    ExtendedTocOffset,
    AssemblyRosterOffset,
    Flags: ULONG;
  end;

  ACTIVATION_CONTEXT_DATA_TOC_HEADER = record
    HeaderSize,
    EntryCount,
    FirstEntryOffset,
    Flags: ULONG;
  end;

  ACTIVATION_CONTEXT_DATA_TOC_ENTRY = record
    Id,
    Offset,             // from ACTIVATION_CONTEXT_DATA base
    Length,             // in bytes
    Format: ULONG;      // ACTIVATION_CONTEXT_SECTION_FORMAT_*
  end;

  ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER = record
    HeaderSize,
    EntryCount,
    FirstEntryOffset,   // from ACTIVATION_CONTEXT_DATA base
    Flags: ULONG;
  end;

  ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_ENTRY = record
    ExtensionGuid: TGUID;
    TocOffset,          // from ACTIVATION_CONTEXT_DATA base
    Length: ULONG;
  end;

  ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER = record
    HeaderSize,
    HashAlgorithm,
    EntryCount,                               // Entry 0 is reserved; this is the number of assemblies plus 1.
    FirstEntryOffset,                         // From ACTIVATION_CONTEXT_DATA base
    AssemblyInformationSectionOffset: ULONG;  // Offset from the ACTIVATION_CONTEXT_DATA base to the
                                              // header of the assembly information string section.  Needed because
                                              // the roster entries contain the offsets from the ACTIVATION_CONTEXT_DATA
                                              // to the assembly information structs, but those structs contain offsets
                                              // from their section base to the strings etc.
  end;

const
  ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY_INVALID = 1;
  ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY_ROOT = 2;

type
  ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY = record
    Flags,
    PseudoKey,                        // case-insentively-hashed assembly name
    AssemblyNameOffset,               // from ACTIVATION_CONTEXT_DATA base
    AssemblyNameLength,               // length in bytes
    AssemblyInformationOffset,        // from ACTIVATION_CONTEXT_DATA base to ACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION
    AssemblyInformationLength: ULONG; // length in bytes
  end;

  //
  //  ActivationContext string sections are organized as follows:
  //
  //  Header
  //  Hash structure (optional)
  //  List of subelements
  //  Variable length data
  //
  //
  //  If you don't recognize the FormatVersion, you should still
  //  be able to navigate to the list of subelements; once there
  //  you can still do a very fast linear search avoiding many
  //  string comparisons if the hash algorithms align.
  //
  //  If you can't even use the hash algorithm, you can still do
  //  string comparisons.
  //

  ACTIVATION_CONTEXT_STRING_SECTION_HEADER = record
    Magic,
    HeaderSize,               // in bytes
    FormatVersion,
    DataFormatVersion,
    Flags,
    ElementCount,
    ElementListOffset,        // offset from section header
    HashAlgorithm,
    SearchStructureOffset,    // offset from section header
    UserDataOffset,           // offset from section header
    UserDataSize: ULONG;      // in bytes
  end;

const
  ACTIVATION_CONTEXT_STRING_SECTION_CASE_INSENSITIVE = 1;
  ACTIVATION_CONTEXT_STRING_SECTION_ENTRIES_IN_PSEUDOKEY_ORDER = 2;

type
  ACTIVATION_CONTEXT_STRING_SECTION_HASH_TABLE = record
    BucketTableEntryCount,
    BucketTableOffset: ULONG; // offset from section header
  end;

  ACTIVATION_CONTEXT_STRING_SECTION_HASH_BUCKET = record
    ChainCount,
    ChainOffset: ULONG;       // offset from section header
  end;

  ACTIVATION_CONTEXT_STRING_SECTION_ENTRY = record
    PseudoKey,
    KeyOffset,                // offset from the section header
    KeyLength,                // in bytes
    Offset,                   // offset from the section header
    Length,                   // in bytes
    AssemblyRosterIndex: ULONG  // 1-based index into the assembly roster for the assembly that
                                // provided this entry.  If the entry is not associated with
                                // an assembly, zero.
  end;

  PACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION = ^ACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION;
  ACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION = packed record
    Size,                                 // size of this structure, in bytes
    Flags,
    EncodedAssemblyIdentityLength,        // in bytes
    EncodedAssemblyIdentityOffset,        // offset from section header base

    ManifestPathType,
    ManifestPathLength,                   // in bytes
    ManifestPathOffset: ULONG;            // offset from section header base
    ManifestLastWriteTime: LARGE_INTEGER;
    PolicyPathType,
    PolicyPathLength,                     // in bytes
    PolicyPathOffset: ULONG;              // offset from section header base
    PolicyLastWriteTime: LARGE_INTEGER;
    MetadataSatelliteRosterIndex,
    Unused2,
    ManifestVersionMajor,
    ManifestVersionMinor,
    PolicyVersionMajor,
    PolicyVersionMinor,
    AssemblyDirectoryNameLength, // in bytes
    AssemblyDirectoryNameOffset, // from section header base
    NumOfFilesInAssembly,
// 2600 stopped here
    LanguageLength, // in bytes
    LanguageOffset: ULONG; // from section header base
  end;

type
  TActivationContext = class
  private const
    WrongHeader = 'Wrong %s (%d) at addr: 0x%.1x';
  private
    FProcess: THandle;
    FContextAddr: ULONG_PTR64;
    FSystemContext: Boolean;
    procedure InitContext;
    procedure LoadAssemblyRoster(AddrVA: ULONG_PTR64);
    procedure LoadCtxString(AddrVA: ULONG_PTR64; TocID: Integer);
    procedure LoadExtendedToc(AddrVA: ULONG_PTR64);
    procedure LoadToc(AddrVA: ULONG_PTR64);
  public
    constructor Create(AProcess: THandle;
      ContextAddr: ULONG_PTR64; ASystemContext: Boolean);
    destructor Destroy; override;
  end;

implementation

procedure Error(const Description: string);
begin
  {$IFNDEF DISABLE_LOGGER}
  RawScannerLogger.Error(llContext, Description);
  {$ENDIF}
end;

{ TActivationContext }

constructor TActivationContext.Create(AProcess: THandle;
  ContextAddr: ULONG_PTR64; ASystemContext: Boolean);
begin
  FProcess := AProcess;
  FContextAddr := ContextAddr;
  FSystemContext := ASystemContext;
  if FContextAddr <> 0 then
    InitContext;
end;

destructor TActivationContext.Destroy;
begin

  inherited;
end;

procedure TActivationContext.InitContext;
var
  ctxData: ACTIVATION_CONTEXT_DATA;
  Item: TSymbolData;
begin
  if not ReadRemoteMemory(FProcess, FContextAddr,
    @ctxData, SizeOf(ACTIVATION_CONTEXT_DATA)) then
  begin
    Error(Format(ReadError, ['ACTIVATION_CONTEXT_DATA',
      FContextAddr, GetLastError, SysErrorMessage(GetLastError)]));
  end;

  if ctxData.Magic <> ACTIVATION_CONTEXT_DATA_MAGIC then
  begin
    Error(Format(WrongHeader,
      ['ACTIVATION_CONTEXT_DATA_MAGIC', ctxData.Magic, FContextAddr]));
    Exit;
  end;

  Item.AddrVA := FContextAddr;
  Item.Ctx.TotalSize := ctxData.TotalSize;
  if FSystemContext then
    Item.DataType := sdtCtxSystem
  else
    Item.DataType := sdtCtxProcess;
  SymbolStorage.Add(Item);

  if ctxData.FormatVersion <> ACTIVATION_CONTEXT_SECTION_FORMAT_STRING_TABLE then
  begin
    Error(Format('Unknown ACTIVATION_CONTEXT_DATA.FormatVersion %d',
      [ctxData.FormatVersion]));
    Exit;
  end;

  if ctxData.DefaultTocOffset <> 0 then
    LoadToc(FContextAddr + ctxData.DefaultTocOffset);
  if ctxData.ExtendedTocOffset <> 0 then
    LoadExtendedToc(FContextAddr + ctxData.ExtendedTocOffset);
  if ctxData.AssemblyRosterOffset <> 0 then
    LoadAssemblyRoster(FContextAddr + ctxData.AssemblyRosterOffset);
end;

procedure TActivationContext.LoadAssemblyRoster(AddrVA: ULONG_PTR64);
var
  Header: ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER;
  Entry: ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY;
  Item: TSymbolData;
  I: Integer;
begin
  if not ReadRemoteMemory(FProcess, AddrVA,
    @Header, SizeOf(ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER)) then
  begin
    Error(Format(ReadError, ['ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER',
      AddrVA, GetLastError, SysErrorMessage(GetLastError)]));
  end;

  Item.AddrVA := AddrVA;
  Item.Ctx.ContextVA := FContextAddr;
  Item.DataType := sdtCtxAssemblyRoster;
  SymbolStorage.Add(Item);

  Item.DataType := sdtCtxAssemblyRosterEntry;
  Item.AddrVA := FContextAddr + Header.FirstEntryOffset;

  // Entry 0 is reserved; this is the number of assemblies plus 1.
  for I := 0 to Header.EntryCount - 1 do
  begin
    if not ReadRemoteMemory(FProcess, Item.AddrVA,
      @Entry, SizeOf(ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY)) then
    begin
      Error(Format(ReadErrorIndex, ['ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY',
        I, Item.AddrVA, GetLastError, SysErrorMessage(GetLastError)]));
    end;

    SymbolStorage.Add(Item);

    Inc(Item.AddrVA, SizeOf(ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY));
  end;
end;

procedure TActivationContext.LoadCtxString(AddrVA: ULONG_PTR64; TocID: Integer);
var
  Header: ACTIVATION_CONTEXT_STRING_SECTION_HEADER;
  Entry: ACTIVATION_CONTEXT_STRING_SECTION_ENTRY;
  Item, InfoSym: TSymbolData;
  I: Integer;
  SectionAddrVA: ULONG_PTR64;
begin
  if not ReadRemoteMemory(FProcess, AddrVA,
    @Header, SizeOf(ACTIVATION_CONTEXT_STRING_SECTION_HEADER)) then
  begin
    Error(Format(ReadError, ['ACTIVATION_CONTEXT_STRING_SECTION_HEADER',
      AddrVA, GetLastError, SysErrorMessage(GetLastError)]));
  end;

  if Header.Magic <> ACTIVATION_CONTEXT_STRING_SECTION_MAGIC then
  begin
    Error(Format(WrongHeader,
      ['ACTIVATION_CONTEXT_STRING_SECTION_HEADER', Header.Magic, AddrVA]));
    Exit;
  end;

  SectionAddrVA := AddrVA;

  Item.AddrVA := AddrVA;
  Item.Ctx.ContextVA := SectionAddrVA;
  Item.DataType := sdtCtxStrSecHeader;
  SymbolStorage.Add(Item);

  Item.DataType := sdtCtxStrSecEntry;
  Item.AddrVA := AddrVA + Header.ElementListOffset;

  for I := 0 to Header.ElementCount - 1 do
  begin
    if not ReadRemoteMemory(FProcess, Item.AddrVA,
      @Entry, SizeOf(ACTIVATION_CONTEXT_STRING_SECTION_ENTRY)) then
    begin
      Error(Format(ReadErrorIndex, ['ACTIVATION_CONTEXT_STRING_SECTION_ENTRY', I,
        Item.AddrVA, GetLastError, SysErrorMessage(GetLastError)]));
    end;

    SymbolStorage.Add(Item);

    InfoSym.AddrVA := Entry.Offset + SectionAddrVA;
    InfoSym.Ctx.ContextVA := SectionAddrVA;
    InfoSym.Ctx.TokID := TocID;
    InfoSym.DataType := sdtCtxStrSecEntryData;
    SymbolStorage.Add(InfoSym);

    Inc(Item.AddrVA, SizeOf(ACTIVATION_CONTEXT_STRING_SECTION_ENTRY));
  end;
end;

procedure TActivationContext.LoadExtendedToc(AddrVA: ULONG_PTR64);
var
  Header: ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER;
  Entry: ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_ENTRY;
  Item: TSymbolData;
  I: Integer;
begin
  if not ReadRemoteMemory(FProcess, AddrVA,
    @Header, SizeOf(ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER)) then
  begin
    Error(Format(ReadError, ['ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER',
      AddrVA, GetLastError, SysErrorMessage(GetLastError)]));
  end;

  Item.AddrVA := AddrVA;
  Item.Ctx.ContextVA := FContextAddr;
  Item.DataType := sdtCtxExtToc;
  SymbolStorage.Add(Item);

  Item.DataType := sdtCtxExtTocEntry;
  Item.AddrVA := FContextAddr + Header.FirstEntryOffset;

  // Entry 0 is reserved; this is the number of assemblies plus 1.
  for I := 0 to Header.EntryCount - 1 do
  begin
    if not ReadRemoteMemory(FProcess, Item.AddrVA,
      @Entry, SizeOf(ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_ENTRY)) then
    begin
      Error(Format(ReadErrorIndex, ['ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_ENTRY', I,
        Item.AddrVA, GetLastError, SysErrorMessage(GetLastError)]));
    end;

    SymbolStorage.Add(Item);

    Inc(Item.AddrVA, SizeOf(ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_ENTRY));
  end;
end;

procedure TActivationContext.LoadToc(AddrVA: ULONG_PTR64);
var
  Header: ACTIVATION_CONTEXT_DATA_TOC_HEADER;
  Entry: ACTIVATION_CONTEXT_DATA_TOC_ENTRY;
  Item: TSymbolData;
  I: Integer;
begin
  if not ReadRemoteMemory(FProcess, AddrVA,
    @Header, SizeOf(ACTIVATION_CONTEXT_DATA_TOC_HEADER)) then
  begin
    Error(Format(ReadError, ['ACTIVATION_CONTEXT_DATA_TOC_HEADER',
      AddrVA, GetLastError, SysErrorMessage(GetLastError)]));
  end;

  Item.AddrVA := AddrVA;
  Item.Ctx.ContextVA := FContextAddr;
  Item.DataType := sdtCtxToc;
  SymbolStorage.Add(Item);

  Item.DataType := sdtCtxTocEntry;
  Item.AddrVA := FContextAddr + Header.FirstEntryOffset;

  // Entry 0 is reserved; this is the number of assemblies plus 1.
  for I := 0 to Header.EntryCount - 1 do
  begin
    if not ReadRemoteMemory(FProcess, Item.AddrVA,
      @Entry, SizeOf(ACTIVATION_CONTEXT_DATA_TOC_ENTRY)) then
    begin
      Error(Format(ReadErrorIndex, ['ACTIVATION_CONTEXT_DATA_TOC_ENTRY', I,
        Item.AddrVA, GetLastError, SysErrorMessage(GetLastError)]));
    end;

    SymbolStorage.Add(Item);

    if Entry.Format = ACTIVATION_CONTEXT_SECTION_FORMAT_STRING_TABLE then
      LoadCtxString(FContextAddr + Entry.Offset, Entry.Id);

    Inc(Item.AddrVA, SizeOf(ACTIVATION_CONTEXT_DATA_TOC_ENTRY));
  end;
end;

end.
