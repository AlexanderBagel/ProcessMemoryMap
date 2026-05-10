////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Resources.pas
//  * Purpose   : Классы для работы с секцией ресурсов
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.2.26
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.Resources;

interface

{$IFDEF FPC}
  {$MODE DELPHI}
  {$IFDEF WINDOWS}
    {$DEFINE MSWINDOWS}
  {$ENDIF}
{$ENDIF}

uses
  {$IFDEF LINUX}
  LCLType,
  Types,
  {$ENDIF}
  {$IFDEF MSWINDOWS}
  Windows,
  {$ENDIF}
  Classes,
  SysUtils,
  StrUtils,
  Generics.Collections,

  RawScanner.Types,
  RawScanner.Elf;

type
  ULONG = Cardinal;
  USHORT = Word;
  LPWSTR = PWideChar;
  LPCWSTR = PWideChar;
  MakeIntResource = LPWSTR;

const
  IMAGE_RESOURCE_NAME_IS_STRING = $80000000;
  IMAGE_RESOURCE_DATA_IS_DIRECTORY = $80000000;
  ID_WORD = $FFFF;
  RES_BINARY_HEADER: array [0..7] of ULONG = (0, $20, ID_WORD, ID_WORD, 0, 0, 0, 0);

  // https://learn.microsoft.com/en-us/windows/win32/menurc/resourceheader
  NSMOVE    = $0010;
  NSPURE    = $0020;
  NSPRELOAD = $0040;
  NSDISCARD = $1000;

  RT_MENUEX = MakeIntResource(15);
  RT_DLGINCLUDE = MakeIntResource(17);
  RT_DIALOGEX = MakeIntResource(18);
  RT_PLUGPLAY = MakeIntResource(19);
  RT_VXD = MakeIntResource(20);

  VS_VERSION_INFO: array [0..15] of WideChar =
    ('V', 'S', '_', 'V', 'E', 'R', 'S', 'I',
     'O', 'N', '_', 'I', 'N', 'F', 'O', #0);
  VS_FFI_SIGNATURE = $FEEF04BD;

type

  //
  // Resource Format.
  //

  //
  // Resource directory consists of two counts, following by a variable length
  // array of directory entries.  The first count is the number of entries at
  // beginning of the array that have actual names associated with each entry.
  // The entries are in ascending order, case insensitive strings.  The second
  // count is the number of entries that immediately follow the named entries.
  // This second count identifies the number of entries that have 16-bit integer
  // Ids as their name.  These entries are also sorted in ascending order.
  //
  // This structure allows fast lookup by either name or number, but for any
  // given resource entry only one form of lookup is supported, not both.
  // This is consistant with the syntax of the .RC file and the .RES file.
  //

  _IMAGE_RESOURCE_DIRECTORY = record
    Characteristics: ULONG;
    TimeDateStamp: ULONG;
    MajorVersion: USHORT;
    MinorVersion: USHORT;
    NumberOfNamedEntries: USHORT;
    NumberOfIdEntries: USHORT;
    //  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
  end;
  TImageResourceDirectory = _IMAGE_RESOURCE_DIRECTORY;

  //
  // Each directory contains the 32-bit Name of the entry and an offset,
  // relative to the beginning of the resource directory of the data associated
  // with this directory entry.  If the name of the entry is an actual text
  // string instead of an integer Id, then the high order bit of the name field
  // is set to one and the low order 31-bits are an offset, relative to the
  // beginning of the resource directory of the string, which is of type
  // IMAGE_RESOURCE_DIRECTORY_STRING.  Otherwise the high bit is clear and the
  // low-order 16-bits are the integer Id that identify this resource directory
  // entry. If the directory entry is yet another resource directory (i.e. a
  // subdirectory), then the high order bit of the offset field will be
  // set to indicate this.  Otherwise the high bit is clear and the offset
  // field points to a resource data entry.
  //

  _IMAGE_RESOURCE_DIRECTORY_ENTRY = record
    Name: ULONG;
    OffsetToData: ULONG;
  end;
  TImageResourceDirectoryEntry = _IMAGE_RESOURCE_DIRECTORY_ENTRY;

  //
  // For resource directory entries that have actual string names, the Name
  // field of the directory entry points to an object of the following type.
  // All of these string objects are stored together after the last resource
  // directory entry and before the first resource data object.  This minimizes
  // the impact of these variable length objects on the alignment of the fixed
  // size directory entry objects.
  //

  _IMAGE_RESOURCE_DIRECTORY_STRING = record
    Length: Word;
    NameString: array [0..0] of Char;
  end;
  TImageResourceDirectoryString = _IMAGE_RESOURCE_DIRECTORY_STRING;

  _IMAGE_RESOURCE_DIRECTORY_STRING_U = record
    Length: Word;
    NameString: array [0..0] of WideChar;
  end;
  TImageResourceDirectoryStringU = _IMAGE_RESOURCE_DIRECTORY_STRING_U;

  _RESADDITIONAL = record
    DataSize: ULONG;
    HeaderSize: ULONG;
    // [Ordinal or Name TYPE]
    // [Ordinal or Name NAME]
    DataVersion: ULONG;
    MemoryFlags: USHORT;
    LanguageId: USHORT;
    Version: ULONG;
    Characteristics: ULONG;
  end;
  TResAdditional = _RESADDITIONAL;

  //
  // Each resource data entry describes a leaf node in the resource directory
  // tree.  It contains an offset, relative to the beginning of the resource
  // directory of the data for the resource, a size field that gives the number
  // of bytes of data at that offset, a CodePage that should be used when
  // decoding code point values within the resource data.  Typically for new
  // applications the code page would be the unicode code page.
  //

  _IMAGE_RESOURCE_DATA_ENTRY = record
    OffsetToData: ULONG;
    Size: ULONG;
    CodePage: ULONG;
    Reserved: ULONG;
  end;
  TImageResourceDataEntry = _IMAGE_RESOURCE_DATA_ENTRY;

  TFpcResourceHeader32 = packed record
    RootPtr: LongWord;
    Count: LongWord;
    UsedHandles: LongWord;
    Handles: LongWord;
  end;

  TFpcResourceHeader64 = packed record
    RootPtr: UInt64;
    Count: LongWord;
    UsedHandles: LongWord;
    Handles: UInt64;
  end;

  TFpcResourceInfoNode32 = packed record
    NameId: LongWord;
    NamedCount: LongWord;
    IdCountOrSize: LongWord;
    SubPtr: LongWord;
  end;

  TFpcResourceInfoNode64 = packed record
    NameId: UInt64;
    NamedCount: LongWord;
    IdCountOrSize: LongWord;
    SubPtr: UInt64;
  end;

  _VS_FIXEDFILEINFO = record
    dwSignature: ULONG;        { e.g. $feef04bd }
    dwStrucVersion: ULONG;     { e.g. $00000042 = "0.42" }
    dwFileVersionMS: ULONG;    { e.g. $00030075 = "3.75" }
    dwFileVersionLS: ULONG;    { e.g. $00000031 = "0.31" }
    dwProductVersionMS: ULONG; { e.g. $00030010 = "3.10" }
    dwProductVersionLS: ULONG; { e.g. $00000031 = "0.31" }
    dwFileFlagsMask: ULONG;    { = $3F for version "0.42" }
    dwFileFlags: ULONG;        { e.g. VFF_DEBUG | VFF_PRERELEASE }
    dwFileOS: ULONG;           { e.g. VOS_DOS_WINDOWS16 }
    dwFileType: ULONG;         { e.g. VFT_DRIVER }
    dwFileSubtype: ULONG;      { e.g. VFT2_DRV_KEYBOARD }
    dwFileDateMS: ULONG;       { e.g. 0 }
    dwFileDateLS: ULONG;       { e.g. 0 }
  end;
  TVSFixedFileInfo = _VS_FIXEDFILEINFO;

  _VERSIONINFOW = record
    TotalSize: Word;
    DataSize: Word;
    _Type: Word;
    szName: array [0..15] of WideChar; // L"VS_VERSION_INFO" + unicode nul
    FixedFileInfo: TVSFixedFileInfo;
  end;
  TVersionInfoW = _VERSIONINFOW;

  _VERBLOCK = record
    wTotLen: Word;
    wValLen: Word;
    wType: Word;
    // WCHAR szKey[1];
  end;
  TVerBlock = _VERBLOCK;

  TResourceType = (rtRoot, rtTypeDirectory, rtNameDirectory, rtLanguageId, rtError);

  TResource = class
  strict private
    FOwner: TResource;
    FChilds: TObjectList<TResource>;
    FName: string;
    FId: ULONG;
    FCodePage: ULONG;
    FData: TMemoryStream;
    FRawAddr: ULONG;
    FResType: TResourceType;
    FTag: NativeUInt;
  protected
    function GetDataStream: TMemoryStream;
  public
    constructor Create(AOwner: TResource; AInitEmptyData: Boolean = False); virtual;
    destructor Destroy; override;
    function DisplayName: string;
    property Childs: TObjectList<TResource> read FChilds;
    property Owner: TResource read FOwner;
    property Name: string read FName write FName;
    property Id: ULONG read FId write FId;
    property CodePage: ULONG read FCodePage write FCodePage;
    property Data: TMemoryStream read FData;
    property RawAddr: ULONG read FRawAddr write FRawAddr;
    property ResType: TResourceType read FResType;
    property Tag: NativeUInt read FTag write FTag;
  end;

  TResourceTree = class
  strict private
    FResTree: TResource;
  public
    constructor Create;
    destructor Destroy; override;
    function FindResource(lpType, lpName: LPCWSTR;
      out AResource: TStream): Boolean; overload;
    function FindResource(lpType, lpName: LPCWSTR; wLanguage: Word;
      out AResource: TStream): Boolean; overload;
    property Resources: TResource read FResTree;
  end;

  TAbstractResourceReader = class
  strict private
    FGate: TAbstractImageGate;
    FStream: TStream;
  protected
    property Gate: TAbstractImageGate read FGate;
    property Stream: TStream read FStream;
  public
    constructor Create(AGate: TAbstractImageGate; AStream: TStream);
    function Load: TResourceTree; virtual; abstract;
  end;

  TPeResourceReader = class(TAbstractResourceReader)
  private
    FSection: TSectionParams;
    procedure ProcessDirectory(AOwner: TResource; ADir: TImageResourceDirectory);
    procedure ProcessEntry(AOwner: TResource; AEntry: TImageResourceDirectoryEntry);
  public
    function Load: TResourceTree; override;
  end;

  TElfResourceReader = class(TAbstractResourceReader)
  private
    FRootTree: TResourceTree;
    FSection: TSectionParams;
    procedure ProcessResInfoNode(AOwner: TResource; ANamedResource: Boolean);
  public
    function Load: TResourceTree; override;
  end;

  TCoffResourceReader = class(TAbstractResourceReader)
  public
    function Load: TResourceTree; override;
  end;

  TBinaryResourceReader = class(TAbstractResourceReader)
  strict private
    FRoot: TResource;
  private
    function GetResource(AOwner: TResource; Id: Word; AName: string): TResource;
    function GetTypeResource(Id: Word; AName: string): TResource;
    function GetNameResource(AOwner: TResource; Id: Word; AName: string): TResource;
    function GetLangResource(AOwner: TResource; Id: Word; AName: string): TResource;
    procedure ReadStringOrID(var Id: Word; var AString: UnicodeString);
    procedure LoadResAdditional;
  public
    function Load: TResourceTree; override;
  end;

  TBinaryResourceWriter = class
  private
    FStream: TStream;
    function GetMemFlag(ARes: TResource): USHORT;
    procedure WriteStringOrID(Id: Word; const AString: UnicodeString);
  public
    procedure SaveToFile(AResTree: TResourceTree; const AFilePath: string);
    procedure SaveToStream(AResTree: TResourceTree; AStream: TStream);
  end;

  TFileVersion = record
    case Integer of
      0: (Version: ULONG);
      1: (HiPart, LowPart: USHORT);
  end;

  TFixedFileInfo = record
    Version: ULONG;
    FileVersionMS: TFileVersion;
    FileVersionLS: TFileVersion;
    ProductVersionMS: TFileVersion;
    ProductVersionLS: TFileVersion;
    FileFlags: ULONG;
    FileOS: ULONG;
    FileType: ULONG;
    FileSubtype: ULONG;
    FileDateMS: ULONG;
    FileDateLS: ULONG;
  end;

  TStringKeyValue = record
    Key, Value: UnicodeString;
  end;

  TStringFileInfo = class
  strict private
    FName: string;
    FItems: TList<TStringKeyValue>;
  public
    constructor Create;
    destructor Destroy; override;
    property Name: string read FName write FName;
    property Items: TList<TStringKeyValue> read FItems;
  end;

  TTranslationItem = record
    LangID, CodePage: Word;
  end;

  TTranslation = class
  strict private
    FName: string;
    FItems: TList<TTranslationItem>;
  public
    constructor Create;
    destructor Destroy; override;
    property Name: string read FName write FName;
    property Items: TList<TTranslationItem> read FItems;
  end;

  TResVersionStream = class
  private const
    strStringFileInfo = 'StringFileInfo';
    strVarFileInfo = 'VarFileInfo';
  private
    FFixedFileInfo: TFixedFileInfo;
    FStrings: TObjectList<TStringFileInfo>;
    FTranslation: TObjectList<TTranslation>;
    function LoadStringFileInfo(AStream: TStream; ASize: Int64): Int64;
    function LoadVarFileInfo(AStream: TStream; ASize: Int64): Int64;
    function LoadVerBlock(AStream: TStream; out AVerBlock: TVerBlock; out
      AKey: UnicodeString): Int64;
    procedure WriteBlockSize(AStream: TStream; APosition: Int64; ASize: Word);
    procedure WriteStringFileInfo(AStream: TStream; AInfo: TStringFileInfo);
    procedure WriteStringKeyValue(AStream: TStream; const AKeyValue: TStringKeyValue);
    procedure WriteTranslationItem(AStream: TStream; ATranslation: TTranslation);
    procedure WriteVerBlock(AStream: TStream; const AVerBlock: TVerBlock; const AKey: string);
  public
    constructor Create;
    destructor Destroy; override;
    function Load(AStream: TStream): Boolean;
    procedure Save(AStream: TStream);
    function FindStringValue(const Key: string): string;
    property FixedFileInfo: TFixedFileInfo read FFixedFileInfo write FFixedFileInfo;
    property StringFileInfo: TObjectList<TStringFileInfo> read FStrings;
    property VarFileInfo: TObjectList<TTranslation> read FTranslation;
  end;

  function GetEntryName(Id: ULONG): string;
  function GetResRoot(ARes: TResource): TResource;
  function GetResType(ARes: TResource): TResource;
  function FindRes(AOwner: TResource; Id: Word; AName: string): TResource;

implementation

function GetEntryName(Id: ULONG): string;
begin
  case Id of
    ULONG(RT_CURSOR): Result := 'Cursor';
    ULONG(RT_BITMAP): Result := 'Bitmap';
    ULONG(RT_ICON): Result := 'Icon';
    ULONG(RT_MENU): Result := 'Menu';
    ULONG(RT_DIALOG): Result := 'Dialog';
    ULONG(RT_STRING): Result := 'String';
    ULONG(RT_FONTDIR): Result := 'Font Dir';
    ULONG(RT_FONT): Result := 'Font';
    ULONG(RT_ACCELERATOR): Result := 'Accelerator';
    ULONG(RT_RCDATA): Result := 'RC Data';
    ULONG(RT_MESSAGETABLE): Result := 'Message Table';
    ULONG(RT_GROUP_CURSOR): Result := 'Group Cursor';
    ULONG(RT_GROUP_ICON): Result := 'Group Icon';
    ULONG(RT_VERSION): Result := 'Version';
    ULONG(RT_DLGINCLUDE): Result := 'Dialog Include';
    ULONG(RT_PLUGPLAY): Result := 'Plug and Play';
    ULONG(RT_VXD): Result := 'VXD';
    ULONG(RT_ANICURSOR): Result := 'Animated Cursor';
    ULONG(RT_ANIICON): Result := 'Animated Icon';
    ULONG(RT_HTML): Result := 'HTML';
    ULONG(RT_MANIFEST): Result := 'Manifest';
  else
    Result := '';
  end;
end;

function GetResRoot(ARes: TResource): TResource;
begin
  Result := ARes;
  if ARes.ResType = rtRoot then Exit;
  while Result.ResType <> rtRoot do
    Result := Result.Owner;
end;

function GetResType(ARes: TResource): TResource;
begin
  Result := ARes;
  if ARes.ResType = rtRoot then Exit;
  while Result.ResType <> rtTypeDirectory do
    Result := Result.Owner;
end;

function FindRes(AOwner: TResource; Id: Word; AName: string): TResource;
var
  Itm: TResource;
begin
  Result := nil;
  if AOwner = nil then Exit;
  for Itm in AOwner.Childs do
  begin
    if AName = '' then
    begin
      if Itm.Id = Id then
        Exit(Itm);
    end
    else
      if Itm.Name = AName then
        Exit(Itm);
  end;
end;

function LoadWideString(AStream: TStream; var AString: UnicodeString): Integer;
var
  CacheLength: Integer;
  AChar: WideChar;
begin
  CacheLength := 255;
  Result := Length(AString);
  SetLength(AString, CacheLength);
  while (AStream.Read(AChar, SizeOf(AChar)) = SizeOf(AChar)) and (AChar <> #0) do
  begin
    Inc(Result);
    if Result > CacheLength then
    begin
      CacheLength := CacheLength shl 1;
      SetLength(AString, CacheLength);
    end;
    AString[Result] := AChar;
  end;
  SetLength(AString, Result);
  Result := Result shl 1 + SizeOf(WideChar);
end;

procedure SaveWideString(AStream: TStream; const AString: UnicodeString);
const
  ZeroChar: Word = 0;
begin
  if AString = '' then Exit;
  AStream.WriteBuffer(AString[1], Length(AString) * SizeOf(WideChar));
  AStream.WriteBuffer(ZeroChar, SizeOf(Word));
end;

function AlignReadStream(AStream: TStream): Integer;
begin
  Result := 3 and (4 - (AStream.Position and 3));
  if Result <> 0 then
    AStream.Seek(Result, soCurrent);
end;

procedure AlignWriteStream(AStream: TStream);
var
  BuffLen: Integer;
  Buff: array of Byte;
begin
  BuffLen := 4 - (AStream.Position and 3);
  if BuffLen = 4 then Exit;
  SetLength(Buff, BuffLen);
  AStream.WriteBuffer(Buff[0], BuffLen);
end;

{ TResource }

constructor TResource.Create(AOwner: TResource; AInitEmptyData: Boolean);
begin
  FOwner := AOwner;
  if Assigned(AOwner) then
  begin
    FOwner.Childs.Add(Self);
    case FOwner.ResType of
      rtRoot: FResType := rtTypeDirectory;
      rtTypeDirectory: FResType := rtNameDirectory;
      rtNameDirectory:
      begin
        FResType := rtLanguageId;
        if AInitEmptyData then GetDataStream;
      end
    else
      FResType := rtError;
    end;
  end;
  FChilds := TObjectList<TResource>.Create(True);
end;

destructor TResource.Destroy;
begin
  FChilds.Free;
  FData.Free;
  inherited;
end;

function TResource.DisplayName: string;
begin
  if (ResType = rtTypeDirectory) and (Name = '') then
  begin
    Result := GetEntryName(Id);
    if Result = '' then
      Result := IntToStr(Id);
  end
  else
    Result := IfThen(Name <> '', Name, IntToStr(Id));
end;

function TResource.GetDataStream: TMemoryStream;
begin
  if FData = nil then
    FData := TMemoryStream.Create;
  Result := FData;
end;

{ TResourceTree }

constructor TResourceTree.Create;
begin
  FResTree := TResource.Create(nil);
end;

destructor TResourceTree.Destroy;
begin
  FResTree.Free;
  inherited;
end;

function TResourceTree.FindResource(lpType, lpName: LPCWSTR;
  out AResource: TStream): Boolean;
begin
  Result := FindResource(lpType, lpName, 0, AResource);
end;

function TResourceTree.FindResource(lpType, lpName: LPCWSTR; wLanguage: Word;
  out AResource: TStream): Boolean;
var
  Res: TResource;
  Id: Word;
  Name: string;

  procedure MakeIdName(AValue: LPWSTR);
  begin
    if NativeUint(AValue) < $1000 then
    begin
      Id := Word(AValue);
      Name := '';
    end
    else
    begin
      Id := 0;
      Name := string(AValue);
    end;
  end;

begin
  Result := False;
  MakeIdName(lpType);
  Res := FindRes(FResTree, Id, Name);
  MakeIdName(lpName);
  Res := FindRes(Res, Id, Name);
  if Res = nil then Exit;
  if wLanguage = 0 then
    AResource := Res.Childs[0].Data
  else
  begin
    Res := FindRes(Res, wLanguage, '');
    if Assigned(Res) then
      AResource :=  Res.Data;
  end;
  Result := Assigned(AResource);
end;

{ TAbstractResourceReader }

constructor TAbstractResourceReader.Create(AGate: TAbstractImageGate;
  AStream: TStream);
begin
  FGate := AGate;
  FStream := AStream;
end;

{ TPeResourceReader }

function TPeResourceReader.Load: TResourceTree;
var
  Ird: TImageResourceDirectory;
begin
  if not Gate.SectionAtName('.rsrc', FSection) then Exit(nil);
  Stream.Position := FSection.AddressRaw;
  Stream.ReadBuffer(Ird, SizeOf(TImageResourceDirectory));
  Result := TResourceTree.Create;
  ProcessDirectory(Result.Resources, Ird);
end;

procedure TPeResourceReader.ProcessDirectory(AOwner: TResource;
  ADir: TImageResourceDirectory);
var
  DirStart: Int64;
  I: Integer;
  Entry: TImageResourceDirectoryEntry;
begin
  DirStart := Stream.Position;
  AOwner.RawAddr := DirStart - SizeOf(TImageResourceDirectory);
  for I := 0 to ADir.NumberOfNamedEntries + ADir.NumberOfIdEntries - 1 do
  begin
    Stream.Position := DirStart + SizeOf(TImageResourceDirectoryEntry) * I;
    Stream.ReadBuffer(Entry, SizeOf(Entry));
    ProcessEntry(AOwner, Entry);
  end;
end;

procedure TPeResourceReader.ProcessEntry(AOwner: TResource;
  AEntry: TImageResourceDirectoryEntry);
var
  EntryName: string;
  EntryId: ULONG;
  EntryNameLength: Word;
  Ird: TImageResourceDirectory;
  Irde: TImageResourceDataEntry;
  Res: TResource;
begin
  if AEntry.Name and IMAGE_RESOURCE_NAME_IS_STRING <> 0 then
  begin
    Stream.Position := FSection.AddressRaw + (AEntry.Name and not IMAGE_RESOURCE_NAME_IS_STRING);
    Stream.ReadBuffer(EntryNameLength, SizeOf(Word));
    SetLength(EntryName, EntryNameLength);
    Stream.ReadBuffer(EntryName[1], EntryNameLength * SizeOf(Char));
    EntryId := 0;
  end
  else
  begin
    EntryName := '';
    EntryId := AEntry.Name;
  end;

  Res := TResource.Create(AOwner);
  Res.Name := EntryName;
  Res.Id := EntryId;

  if AEntry.OffsetToData and IMAGE_RESOURCE_DATA_IS_DIRECTORY <> 0 then
  begin
    Stream.Position := FSection.AddressRaw + (AEntry.OffsetToData and not IMAGE_RESOURCE_DATA_IS_DIRECTORY);
    Stream.ReadBuffer(Ird, SizeOf(TImageResourceDirectory));
    ProcessDirectory(Res, Ird);
  end
  else
  begin
    Stream.Position := FSection.AddressRaw + AEntry.OffsetToData;
    Stream.ReadBuffer(Irde, SizeOf(TImageResourceDataEntry));
    Res.CodePage := Irde.CodePage;
    Res.RawAddr := Gate.RvaToRaw(Irde.OffsetToData);
    Stream.Position := Res.RawAddr;
    Res.GetDataStream.CopyFrom(Stream, Irde.Size);
    Res.Data.Position := 0;
  end;
end;

{ TElfResourceReader }

function TElfResourceReader.Load: TResourceTree;
var
  Hdr32: TFpcResourceHeader32;
  Hdr64: TFpcResourceHeader64;
begin
  if not Gate.SectionAtName('fpc.resources', FSection) then Exit(nil);
  Stream.Position := FSection.AddressRaw;
  if Gate.GetIs64Image then
    Stream.ReadBuffer(Hdr64, SizeOf(TFpcResourceHeader64))
  else
  begin
    Stream.ReadBuffer(Hdr32, SizeOf(TFpcResourceHeader32));
    Hdr64.RootPtr := Hdr32.RootPtr;
    Hdr64.Count := Hdr32.Count;
    Hdr64.UsedHandles := Hdr32.UsedHandles;
    Hdr64.Handles := Hdr32.Handles;
  end;
  Stream.Position := Gate.RvaToRaw(Hdr64.RootPtr);
  ProcessResInfoNode(nil, False);
  Result := FRootTree;
end;

procedure TElfResourceReader.ProcessResInfoNode(AOwner: TResource;
  ANamedResource: Boolean);
var
  EntryNameA: AnsiString;
  EntryNameLength, CacheLength: Integer;
  EntryName: string;
  AChar: AnsiChar;
  EntryId: ULONG;
  Node32: TFpcResourceInfoNode32;
  Node64: TFpcResourceInfoNode64;
  Res: TResource;
  DataPosition: Int64;
  I: Integer;
begin
  if Gate.GetIs64Image then
    Stream.ReadBuffer(Node64, SizeOf(TFpcResourceInfoNode64))
  else
  begin
    Stream.ReadBuffer(Node32, SizeOf(TFpcResourceInfoNode32));
    Node64.NameId := Node32.NameId;
    Node64.NamedCount := Node32.NamedCount;
    Node64.IdCountOrSize := Node32.IdCountOrSize;
    Node64.SubPtr := Node32.SubPtr;
  end;

  DataPosition := Stream.Position;

  if ANamedResource then
  begin
    Stream.Position := Gate.RvaToRaw(Node64.NameId);
    CacheLength := MAX_PATH;
    SetLength(EntryNameA, MAX_PATH);
    EntryNameLength := 0;
    while (Stream.Read(AChar, 1) = 1) and (AChar <> #0) do
    begin
      Inc(EntryNameLength);
      if EntryNameLength > CacheLength then
      begin
        CacheLength := CacheLength shl 1;
        SetLength(EntryNameA, CacheLength);
      end;
      EntryNameA[EntryNameLength] := AChar;
    end;
    SetLength(EntryNameA, EntryNameLength);
    EntryName := string(EntryNameA);
    EntryId := 0;
  end
  else
  begin
    EntryId := Node64.NameId;
    EntryName := '';
  end;

  if AOwner = nil then
  begin
    FRootTree := TResourceTree.Create;
    Res := FRootTree.Resources;
  end
  else
  begin
    Res := TResource.Create(AOwner);
    Res.Name := EntryName;
    Res.Id := EntryId;
  end;

  Stream.Position := Gate.RvaToRaw(Node64.SubPtr);

  if Res.ResType = rtLanguageId then
  begin
    Res.RawAddr := Stream.Position;
    Res.GetDataStream.CopyFrom(Stream, Node64.IdCountOrSize);
    Res.Data.Position := 0;
    Exit;
  end;

  if Gate.GetIs64Image then
    Res.RawAddr := DataPosition - SizeOf(TFpcResourceInfoNode64)
  else
    Res.RawAddr := DataPosition - SizeOf(TFpcResourceInfoNode32);

  for I := 1 to Node64.NamedCount do
    ProcessResInfoNode(Res, True);
  for I := 1 to Node64.IdCountOrSize do
    ProcessResInfoNode(Res, False);

  Stream.Position := DataPosition;
end;

{ TCoffResourceReader }

function TCoffResourceReader.Load: TResourceTree;
begin
  Result := nil;
end;

{ TBinaryResourceReader }

function TBinaryResourceReader.GetLangResource(AOwner: TResource; Id: Word;
  AName: string): TResource;
begin
  Result := GetResource(AOwner, Id, AName);
end;

function TBinaryResourceReader.GetNameResource(AOwner: TResource; Id: Word;
  AName: string): TResource;
begin
  Result := GetResource(AOwner, Id, AName);
end;

function TBinaryResourceReader.GetResource(AOwner: TResource; Id: Word;
  AName: string): TResource;
begin
  Result := FindRes(AOwner, Id, AName);
  if Result = nil then
  begin
    Result := TResource.Create(AOwner);
    Result.Name := AName;
    Result.Id := Id;
  end;
end;

function TBinaryResourceReader.GetTypeResource(Id: Word;
  AName: string): TResource;
begin
  Result := GetResource(FRoot, Id, AName);
end;

function TBinaryResourceReader.Load: TResourceTree;
var
  Header: array [0..7] of ULONG;
begin
  if Stream.Read(Header, SizeOf(Header)) = SizeOf(Header) then
    if not CompareMem(@Header[0], @RES_BINARY_HEADER[0], SizeOf(Header)) then
      Exit(nil);
  Result := TResourceTree.Create;
  FRoot := Result.Resources;
  LoadResAdditional;
end;

procedure TBinaryResourceReader.LoadResAdditional;
var
  TypeStr, NameStr: UnicodeString;
  TypeOrd, NameOrd: Word;
  Additional: TResAdditional;
  Res: TResource;
begin
  while Stream.Position < Stream.Size do
  begin
    Additional := Default(TResAdditional);
    Stream.ReadBuffer(Additional.DataSize, SizeOf(ULONG));
    Stream.ReadBuffer(Additional.HeaderSize, SizeOf(ULONG));
    ReadStringOrID(TypeOrd, TypeStr);
    ReadStringOrID(NameOrd, NameStr);
    AlignReadStream(Stream);
    Stream.ReadBuffer(Additional.DataVersion, SizeOf(TResAdditional) - 2 * SizeOf(ULONG));
    Res := GetTypeResource(TypeOrd, TypeStr);
    Res := GetNameResource(Res, NameOrd, NameStr);
    Res := GetLangResource(Res, Additional.LanguageId, '');
    Res.RawAddr := Stream.Position;
    Res.GetDataStream.CopyFrom(Stream, Additional.DataSize);
    Res.Data.Position := 0;
    AlignReadStream(Stream);
  end;
end;

procedure TBinaryResourceReader.ReadStringOrID(var Id: Word;
  var AString: UnicodeString);
var
  ATag: Word;
begin
  Stream.ReadBuffer(ATag, SizeOf(Word));
  if ATag = ID_WORD then
  begin
    AString := '';
    Stream.ReadBuffer(Id, SizeOf(Word));
  end
  else
  begin
    Id := 0;
    AString := WideChar(ATag);
    LoadWideString(Stream, AString);
  end;
end;

{ TBinaryResourceWriter }

function TBinaryResourceWriter.GetMemFlag(ARes: TResource): USHORT;
begin
  case GetResType(ARes).Id of
    ULONG(RT_ICON),
    ULONG(RT_CURSOR),
    ULONG(RT_FONT),
    ULONG(RT_DIALOG),
    ULONG(RT_MENU),
    ULONG(RT_DLGINCLUDE),
    ULONG(RT_DIALOGEX),
    ULONG(RT_MENUEX),
    ULONG(RT_STRING): Result := NSMOVE or NSPURE or NSDISCARD;
    ULONG(RT_GROUP_ICON),
    ULONG(RT_GROUP_CURSOR): Result := NSMOVE or NSDISCARD;
    ULONG(RT_FONTDIR): Result := NSMOVE or NSPRELOAD;
  else
    Result := NSMOVE or NSPURE;
  end;
end;

procedure TBinaryResourceWriter.SaveToFile(AResTree: TResourceTree;
  const AFilePath: string);
var
  F: TFileStream;
begin
  F := TFileStream.Create(AFilePath, fmCreate);
  try
    SaveToStream(AResTree, F);
  finally
    F.Free;
  end;
end;

procedure TBinaryResourceWriter.SaveToStream(AResTree: TResourceTree;
  AStream: TStream);
var
  ResType, ResName, ResLang: TResource;
  Additional: TResAdditional;
  ResTypeId: ULONG;
begin
  FStream := AStream;
  AStream.WriteBuffer(RES_BINARY_HEADER[0], SizeOf(RES_BINARY_HEADER));
  for ResType in AResTree.Resources.Childs do
    for ResName in ResType.Childs do
      for ResLang in ResName.Childs do
      begin
        Additional := Default(TResAdditional);
        Additional.DataSize := ResLang.Data.Size;
        Additional.HeaderSize := SizeOf(TResAdditional);
        if ResName.Id = 0 then
          Inc(Additional.HeaderSize, (Length(ResName.Name) + 1) * SizeOf(WideChar))
        else
          Inc(Additional.HeaderSize, 4);
        if ResType.Id = 0 then
          Inc(Additional.HeaderSize, (Length(ResType.Name) + 1) * SizeOf(WideChar))
        else
          Inc(Additional.HeaderSize, 4);
        Inc(Additional.HeaderSize, 3 and (4 - (Additional.HeaderSize and 3)));
        Additional.MemoryFlags := GetMemFlag(ResLang);
        Additional.LanguageId := ResLang.Id;
        AStream.WriteBuffer(Additional, SizeOf(ULONG) * 2);
        ResTypeId := ResType.Id;
        if ResTypeId = ULONG(RT_MENUEX) then
          ResTypeId := ULONG(RT_MENU);
        if ResTypeId = ULONG(RT_DIALOGEX) then
          ResTypeId := ULONG(RT_DIALOG);
        WriteStringOrID(ResTypeId, ResType.Name);
        WriteStringOrID(ResName.Id, ResName.Name);
        AlignWriteStream(AStream);
        AStream.WriteBuffer(Additional.DataVersion, SizeOf(TResAdditional) - SizeOf(ULONG) * 2);
        AStream.CopyFrom(ResLang.Data, 0);
        AlignWriteStream(AStream);
      end;
end;

procedure TBinaryResourceWriter.WriteStringOrID(Id: Word; const AString: UnicodeString);
const
  ZeroChar: Word = 0;
var
  OrdID: ULONG;
begin
  if Id = 0 then
  begin
    FStream.WriteBuffer(AString[1], Length(AString) * SizeOf(WideChar));
    FStream.WriteBuffer(ZeroChar, SizeOf(Word));
  end
  else
  begin
    OrdID := Id shl 16 + ID_WORD;
    FStream.WriteBuffer(OrdID, SizeOf(ULONG));
  end;
end;

{ TStringFileInfo }

constructor TStringFileInfo.Create;
begin
  FItems := TList<TStringKeyValue>.Create;
end;

destructor TStringFileInfo.Destroy;
begin
  FItems.Free;
  inherited;
end;

{ TTranslation }

constructor TTranslation.Create;
begin
  FItems := TList<TTranslationItem>.Create;
end;

destructor TTranslation.Destroy;
begin
  FItems.Free;
  inherited;
end;

{ TResVersionStream }

constructor TResVersionStream.Create;
begin
  FStrings := TObjectList<TStringFileInfo>.Create;
  FTranslation := TObjectList<TTranslation>.Create;
end;

destructor TResVersionStream.Destroy;
begin
  FStrings.Free;
  FTranslation.Free;
  inherited;
end;

function TResVersionStream.FindStringValue(const Key: string): string;
var
  S: TStringKeyValue;
begin
  for S in StringFileInfo.Items[0].Items do
    if S.Key = Key then
      Exit(S.Value);
  Result := '';
end;

function TResVersionStream.Load(AStream: TStream): Boolean;
var
  Info: TVersionInfoW;
  VerBlock: TVerBlock;
  AKey: UnicodeString;
  HeaderSize: Integer;
begin
  Result := False;
  AStream.Position := 0;
  AStream.ReadBuffer(Info, SizeOf(Info));
  if not CompareMem(@Info.szName[0], @VS_VERSION_INFO[0], SizeOf(VS_VERSION_INFO)) then Exit;
  if Info.FixedFileInfo.dwSignature <> VS_FFI_SIGNATURE then Exit;
  FStrings.Clear;
  FTranslation.Clear;
  FFixedFileInfo.Version := Info.FixedFileInfo.dwStrucVersion;
  FFixedFileInfo.FileVersionMS.Version := Info.FixedFileInfo.dwFileVersionMS;
  FFixedFileInfo.FileVersionLS.Version := Info.FixedFileInfo.dwFileVersionLS;
  FFixedFileInfo.ProductVersionMS.Version := Info.FixedFileInfo.dwProductVersionMS;
  FFixedFileInfo.ProductVersionLS.Version := Info.FixedFileInfo.dwProductVersionLS;
  FFixedFileInfo.FileFlags := Info.FixedFileInfo.dwFileFlags;
  FFixedFileInfo.FileOS := Info.FixedFileInfo.dwFileOS;
  FFixedFileInfo.FileType := Info.FixedFileInfo.dwFileType;
  FFixedFileInfo.FileSubtype := Info.FixedFileInfo.dwFileSubtype;
  FFixedFileInfo.FileDateMS := Info.FixedFileInfo.dwFileDateMS;
  FFixedFileInfo.FileDateLS := Info.FixedFileInfo.dwFileDateLS;
  Dec(Info.TotalSize, AStream.Position);
  while Info.TotalSize > 0 do
  begin
    HeaderSize := LoadVerBlock(AStream, VerBlock, AKey);
    Dec(Info.TotalSize, HeaderSize);
    Dec(VerBlock.wTotLen, HeaderSize);
    if AKey = strStringFileInfo then
      Dec(Info.TotalSize, LoadStringFileInfo(AStream, VerBlock.wTotLen));
    if AKey = strVarFileInfo then
      Dec(Info.TotalSize, LoadVarFileInfo(AStream, VerBlock.wTotLen));
  end;
  Result := True;
end;

function TResVersionStream.LoadStringFileInfo(AStream: TStream; ASize: Int64): Int64;
var
  VerBlock: TVerBlock;
  AKey: UnicodeString;
  KeyValue: TStringKeyValue;
  StringFileInfo: TStringFileInfo;
  TableLen: Int64;
begin
  Result := AStream.Position;
  while ASize > AStream.Position - Result do
  begin
    TableLen := LoadVerBlock(AStream, VerBlock, AKey);
    Dec(VerBlock.wTotLen, TableLen);
    StringFileInfo := TStringFileInfo.Create;
    StringFileInfo.Name := AKey;
    FStrings.Add(StringFileInfo);
    TableLen := VerBlock.wTotLen;
    while TableLen > 0 do
    begin
      KeyValue := Default(TStringKeyValue);
      Dec(TableLen, LoadVerBlock(AStream, VerBlock, KeyValue.Key));
      if VerBlock.wValLen > 0 then
        Dec(TableLen, LoadWideString(AStream, KeyValue.Value));
      Dec(TableLen, AlignReadStream(AStream));
      StringFileInfo.Items.Add(KeyValue);
    end;
  end;
  Result := AStream.Position - Result;
end;

function TResVersionStream.LoadVarFileInfo(AStream: TStream; ASize: Int64): Int64;
var
  VerBlock: TVerBlock;
  AKey: UnicodeString;
  KeyValue: TTranslationItem;
  Translation: TTranslation;
begin
  Result := AStream.Position;
  KeyValue := Default(TTranslationItem);
  while ASize > AStream.Position - Result do
  begin
    LoadVerBlock(AStream, VerBlock, AKey);
    Translation := TTranslation.Create;
    VarFileInfo.Add(Translation);
    Translation.Name := AKey;
    while VerBlock.wValLen > 0 do
    begin
      AStream.ReadBuffer(KeyValue, SizeOf(KeyValue));
      Dec(VerBlock.wValLen, SizeOf(KeyValue));
      Translation.Items.Add(KeyValue);
    end;;
  end;
  Result := AStream.Position - Result;
end;

function TResVersionStream.LoadVerBlock(AStream: TStream;
  out AVerBlock: TVerBlock; out AKey: UnicodeString): Int64;
begin
  Result := AStream.Position;
  AVerBlock := Default(TVerBlock);
  AStream.ReadBuffer(AVerBlock, SizeOf(AVerBlock));
  LoadWideString(AStream, AKey);
  AlignReadStream(AStream);
  Result := AStream.Position - Result;
end;

procedure TResVersionStream.Save(AStream: TStream);
var
  Info: TVersionInfoW;
  I: Integer;
  TotalPos: Int64;
  VerBlock: TVerBlock;
begin
  Info := Default(TVersionInfoW);
  Info.DataSize := SizeOf(TVSFixedFileInfo);
  Move(VS_VERSION_INFO[0], Info.szName[0], SizeOf(VS_VERSION_INFO));
  Info.FixedFileInfo.dwSignature := VS_FFI_SIGNATURE;
  Info.FixedFileInfo.dwStrucVersion := VS_FFI_STRUCVERSION;
  Info.FixedFileInfo.dwFileVersionMS := FixedFileInfo.FileVersionMS.Version;
  Info.FixedFileInfo.dwFileVersionLS := FixedFileInfo.FileVersionLS.Version;
  Info.FixedFileInfo.dwProductVersionMS := FixedFileInfo.ProductVersionMS.Version;
  Info.FixedFileInfo.dwProductVersionLS := FixedFileInfo.ProductVersionLS.Version;
  Info.FixedFileInfo.dwFileFlagsMask := VS_FFI_FILEFLAGSMASK;
  Info.FixedFileInfo.dwFileFlags := FixedFileInfo.FileFlags;
  Info.FixedFileInfo.dwFileOS := FixedFileInfo.FileOS;
  Info.FixedFileInfo.dwFileType := FixedFileInfo.FileType;
  Info.FixedFileInfo.dwFileSubtype := FixedFileInfo.FileSubtype;
  Info.FixedFileInfo.dwFileDateMS := FixedFileInfo.FileDateMS;
  Info.FixedFileInfo.dwFileDateLS := FixedFileInfo.FileDateLS;
  AStream.WriteBuffer(Info, SizeOf(Info));
  if StringFileInfo.Count > 0 then
  begin
    VerBlock := Default(TVerBlock);
    VerBlock.wType := 1;
    TotalPos := AStream.Seek(0, soFromEnd);
    WriteVerBlock(AStream, VerBlock, strStringFileInfo);
    for I := 0 to StringFileInfo.Count - 1 do
    begin
      AlignWriteStream(AStream);
      WriteStringFileInfo(AStream, StringFileInfo[I]);
    end;
    WriteBlockSize(AStream, TotalPos, AStream.Size - TotalPos);
  end;
  if VarFileInfo.Count > 0 then
  begin
    AlignWriteStream(AStream);
    VerBlock := Default(TVerBlock);
    VerBlock.wType := 1;
    TotalPos := AStream.Seek(0, soFromEnd);
    WriteVerBlock(AStream, VerBlock, strVarFileInfo);
    for I := 0 to VarFileInfo.Count - 1 do
    begin
      AlignWriteStream(AStream);
      WriteTranslationItem(AStream, VarFileInfo.Items[I]);
    end;
    WriteBlockSize(AStream, TotalPos, AStream.Size - TotalPos);
  end;
  WriteBlockSize(AStream, 0, AStream.Size);
end;

procedure TResVersionStream.WriteBlockSize(AStream: TStream; APosition: Int64;
  ASize: Word);
var
  OldPos: Int64;
begin
  OldPos := AStream.Position;
  AStream.Position := APosition;
  AStream.WriteBuffer(ASize, SizeOf(ASize));
  AStream.Position := OldPos;
end;

procedure TResVersionStream.WriteStringFileInfo(AStream: TStream;
  AInfo: TStringFileInfo);
var
  TotalPos: Int64;
  VerBlock: TVerBlock;
  I: Integer;
begin
  TotalPos := AStream.Seek(0, soFromEnd);
  VerBlock := Default(TVerBlock);
  VerBlock.wType := 1;
  WriteVerBlock(AStream, VerBlock, AInfo.Name);
  for I := 0 to AInfo.Items.Count - 1 do
  begin
    AlignWriteStream(AStream);
    WriteStringKeyValue(AStream, AInfo.Items[I]);
  end;
  WriteBlockSize(AStream, TotalPos, AStream.Size - TotalPos);
end;

procedure TResVersionStream.WriteStringKeyValue(AStream: TStream;
  const AKeyValue: TStringKeyValue);
var
  TotalPos: Int64;
  VerBlock: TVerBlock;
begin
  TotalPos := AStream.Seek(0, soFromEnd);
  VerBlock := Default(TVerBlock);
  VerBlock.wValLen := Length(AKeyValue.Value) + 1;
  VerBlock.wType := 1;
  WriteVerBlock(AStream, VerBlock, AKeyValue.Key);
  AlignWriteStream(AStream);
  SaveWideString(AStream, AKeyValue.Value);
  WriteBlockSize(AStream, TotalPos, AStream.Size - TotalPos);
end;

procedure TResVersionStream.WriteTranslationItem(AStream: TStream;
  ATranslation: TTranslation);
var
  TotalPos: Int64;
  VerBlock: TVerBlock;
  I: Integer;
  TranslationItem: TTranslationItem;
begin
  TotalPos := AStream.Seek(0, soFromEnd);
  VerBlock := Default(TVerBlock);
  VerBlock.wValLen := ATranslation.Items.Count * SizeOf(TTranslationItem);
  WriteVerBlock(AStream, VerBlock, ATranslation.Name);
  AlignWriteStream(AStream);
  for I := 0 to ATranslation.Items.Count - 1 do
  begin
    TranslationItem := ATranslation.Items[I];
    AStream.WriteBuffer(TranslationItem, SizeOf(TranslationItem));
  end;
  WriteBlockSize(AStream, TotalPos, AStream.Size - TotalPos);
end;

procedure TResVersionStream.WriteVerBlock(AStream: TStream;
  const AVerBlock: TVerBlock; const AKey: string);
begin
  AStream.WriteBuffer(AVerBlock, SizeOf(AVerBlock));
  SaveWideString(AStream, AKey);
end;

end.
