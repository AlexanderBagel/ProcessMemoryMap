////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : RawScanner.Pdb.pas
//  * Purpose   : Classes for working directly with debug PDB files
//  *           : in RAW mode, replacing dbghlp.dll and symsrv.dll
//  * Author    : Alexander (Rouse_) Bagel   
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.2.30
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : https://github.com/AlexanderBagel/ProcessMemoryMap/releases/latest
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//  *
//  * SPDX-License-Identifier: MPL-2.0
//  * This Source Code Form is subject to the terms of the Mozilla Public
//  * License, v. 2.0. If a copy of the MPL was not distributed with this
//  * file, You can obtain one at http://mozilla.org/MPL/2.0/.
//  *
//  ****************************************************************************
//  *
//  * Support the Project:
//  *
//  * If you found this project useful, you can support its development
//  * on the author's main-project page:
//  *
//  * https://boosty.to/processmemorymap
//  *
//  ****************************************************************************
//

//
// External Info:
// https://github.com/microsoft/microsoft-pdb/
// https://github.com/luser/dump_syms
// https://llvm.org/docs/PDB/
//

unit RawScanner.Pdb;

interface

uses
  Windows,
  Classes,
  SysUtils,
  Math,
  Generics.Collections,
  Generics.Defaults,
  Hash,
  WinInet,
  WinHTTP,
  IOUtils,
  JSON,
  SyncObjs,
  DateUtils,
  RawScanner.Utils;
  
  // the alignment must be exactly eight, otherwise, the record sizes will be incorrect.
  // [ru] выравнивание строго восемь, иначе поплывут размеры структур

{$A8}

const
  // Fixed stream numbers
  // [ru] Фиксированные номера потоков
  // https://llvm.org/docs/PDB/index.html#stream-layout
  PDB_STREAM_OLD_MSF_DIRECTORY  = 0;
  PDB_STREAM_PDB_INFO           = 1;
  PDB_STREAM_TPI                = 2;
  PDB_STREAM_DBI                = 3;
  PDB_STREAM_IPI                = 4;

  DBI_INVALID_STREAM_INDEX      = Word($FFFF);

  GSI_HASH_SIGNATURE = DWORD($FFFFFFFF);
  GSI_HASH_VERSION = DWORD($EFFE0000) + 19990810;

  // https://llvm.org/docs/PDB/CodeViewSymbols.html
  CV_SYMBOL_KIND_S_PUB32 = Word($110E);

  // https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h#L3685
  CVPSF_CODE         = DWORD(1 shl 0);
  CVPSF_FUNCTION     = DWORD(1 shl 1);
  CVPSF_MANAGED_CODE = DWORD(1 shl 2);
  CVPSF_MANAGED_IL   = DWORD(1 shl 3);

  PdbInfoFile = '.pdb-info';

type
  CB = Long;   // count of bytes
  UPN = Int32; // universal page no.

  // Structure of an MSF Container
  // [ru] Структура MSF контейнера
  // https://github.com/microsoft/microsoft-pdb/

  // https://github.com/microsoft/microsoft-pdb/blob/master/PDB/msf/msf.cpp#L282
  SI_PERSIST = record
    cb: CB;
    mpspnpn: Int32;
  end;

  // https://github.com/microsoft/microsoft-pdb/blob/master/PDB/msf/msf.cpp#L946
  BIGMSF_HDR = record
    Magic: array [0..29] of Byte;
    cbPg: CB;           // page size
    pnFpm: UPN;         // page no. of valid FPM
    pnMac: UPN;         // current no. of pages
    siSt: SI_PERSIST;   // stream table stream info
    mpspnpnSt: array [0..0] of Int32;
  end;

  // https://llvm.org/docs/_sources/PDB/PdbStream.rst.txt
  PPdbStreamHeader = ^TPdbStreamHeader;
  TPdbStreamHeader = record
    Version: DWORD;

    // a DWORD (-1) is supposed to be here, but it's not there
    // [ru] вот тут якобы должно лежать DWORD(-1), но его там нет

    Signature: DWORD;

    // in LLVM, it's called "Age", but in reality, it's definitely not "Age"
    // [ru] у LLVM это Age, но по факту там лежит точно не Age

    Age: DWORD;

    // and this is the only field that actually stores the file's GUID
    // [ru] и только вот это поле действительно хранит GUID файла

    UinqueId: TGUID;
  end;


  // https://llvm.org/docs/PDB/DbiStream.html
  // https://github.com/microsoft/microsoft-pdb/blob/master/PDB/dbi/dbi.h#L124
  PDbiStreamHeader = ^TDbiStreamHeader;
  TDbiStreamHeader = record
    VersionSignature: Integer;
    VersionHeader: DWORD;
    Age: DWORD;
    GlobalStreamIndex: SmallInt;
    BuildNumber: Word;
    PublicStreamIndex: SmallInt;
    PdbDllVersion: Word;
    SymbolRecordStreamIndex: SmallInt;
    PdbDllRbld: Word;
    ModuleInfoSize: Integer;
    SectionContributionSize: Integer;
    SectionMapSize: Integer;
    SourceInfoSize: Integer;
    TypeServerMapSize: Integer;
    MfcTypeServerIndex: DWORD;
    OptionalDebugHeaderSize: Integer;
    EcSubstreamSize: Integer;
    Flags: Word;
    Machine: Word;
    Padding: DWORD;
  end;

  // https://github.com/luser/dump_syms
  // https://llvm.org/docs/PDB/DbiStream.html#optional-debug-header-stream
  PDbiDebugHeader = ^TDbiDebugHeader;
  TDbiDebugHeader = record
    FpoDataStreamIndex: Word;
    ExceptionDataStreamIndex: Word;
    FixupDataStreamIndex: Word;
    OmapToSrcDataStreamIndex: Word;
    OmapFromSrcDataStreamIndex: Word;
    SectionHeaderStreamIndex: Word;
    TokenDataStreamIndex: Word;
    XdataStreamIndex: Word;
    PdataStreamIndex: Word;
    NewFpoDataStreamIndex: Word;
    OriginalSectionHeaderDataStreamIndex: Word;
  end;

  // Public Symbol Stream
  // https://llvm.org/docs/PDB/PublicStream.html
  PPublicStreamHeader = ^TPublicStreamHeader;
  TPublicStreamHeader = record
    SymHashSize: DWORD;
    AddrMapSize: DWORD;
    ThunkCount: DWORD;
    SizeOfThunk: DWORD;
    IsectThunkTable: Word;
    Padding: Word;
    OffsetThunkTable: DWORD;
    SectionCount: Word;
    Padding2: Word;
  end;

  PGsiHashTableHeader = ^TGsiHashTableHeader;
  TGsiHashTableHeader = record
    Signature: DWORD;
    Version: DWORD;
    HashRecordsSize: DWORD;
    BucketsSize: DWORD;
  end;

  PPdbHashRecord = ^TPdbHashRecord;
  TPdbHashRecord = record
    // offset in the Symbol Record Stream, stored with an OFFSET OF +1
    // [ru] смещение в Symbol Record Stream, хранится СО СДВИГОМ +1
    Offset: DWORD;
    CRef: DWORD;
  end;

  // https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h#L3696
  PPUBSYM32 = ^PUBSYM32;

  // it's packed here, because there's more data right after the seg.
  // [ru] тут packed, т.к. сразу за seg идут еще данные

  PUBSYM32 = packed record
    reclen: Word;
    rectyp: Word;
    pubsymflags: DWORD; // CVPSF_xxx
    off: DWORD;

    // the section numbers start with one
    // [ru] номера секций идут от единицы

    seg: Word;

    // Next comes a variable-length “Name”
    // [ru] Дальше следует Name переменной длины

  end;

  EPdbException = class(Exception);

  TPages = array of UPN;
  TSectionsRva = array of DWORD;

  TPdbState = (

    // debug symbols were not found locally, but we haven't checked remotely yet
    // [ru] отладочные символы не найдены локально, но ещё не проверяли удалённо

    psNotFoundLocally,

    // all symbol servers were queried, symbols were not found
    // [ru] опросили все symsrv, символов нигде нет

    psNotFoundAnywhere,

    // symbols are not available locally, but they can be downloaded
    // [ru] символы локально отсутствуют, но их можно загрузить

    psAvailableForLoading,

    // symbols are loading and are not yet ready for use
    // [ru] символы загружаются и еще не готовы к работе

    psLoading,

    // symbols have been loaded, but the PE sections of the file are missing
    // [ru] символы загрузились, но секции PE файла отсутствуют

    psNoSections,

    // failed to read the PDB file
    // [ru] ошибка чтения PDB файла

    psBroken,

    // symbols have been loaded and are ready to use
    // [ru] символы загружены и готовы к работе

    psReady
  );

  TPdbSymbolType = (pstData, pstFunc, pstIcfStub);

  TPdbSymbol = record
    Name: string;
    Rva: DWORD;
    Section: Integer;
    SymbolType: TPdbSymbolType;
  end;

  TPdbKey = packed record
    Uid: TGUID;
    Age: DWORD;
    Name: string;
  end;

  TPdbInfo = record
    DownloadedAt: TDateTime;
    DownloadedBy,
    RequestedForBinaryPath: string;
    BinaryGuid: TGUID;
    BinaryAge: DWORD;
  end;

  TPdb = class
  strict private
    FAge: DWORD;
    FHeader: BIGMSF_HDR;
    FMaxSectionIdx: Integer;
    FBinaryPath, FRelativePath, FPdbName, FLocalPath, FRemotePath: string;
    FSectionsRva: TSectionsRva;
    FState: TPdbState;
    FStreamPages: array of TPages;
    FStreamSizes: array of CB;
    FSymbols: TList<TPdbSymbol>;
    FUnicalId: TGUID;
    procedure CheckStream(AStream: TStream);
    procedure DetectIsfStubs;
    function GetStream(AStream: TStream; Index: Integer): TBytes;
    function GetSymbol(Index: Integer): TPdbSymbol;
    procedure LoadSectionData(AStream: TStream; const Dbi: TBytes);
    procedure LoadStreams(AStream: TStream);
    procedure LoadSymbols(AStream: TStream);
    function PagesCount(Value: CB): Integer;
    function ReadPages(AStream: TStream; const PageList: TPages; TotalSize: Int64): TBytes;
    function ReadSymbolName(const Data: TBytes; NameStart, RecordEnd: Integer): string;
    procedure UpdateUnicalId(AStream: TStream);
  protected
    procedure SetLocalPath(const Value: string);
    procedure UpdateState(NewState: TPdbState);
    property RelativePath: string read FRelativePath write FRelativePath;
    property RemotePath: string read FRemotePath write FRemotePath;
  public
    constructor Create; overload;
    constructor Create(APdbKey: TPdbKey); overload;
    destructor Destroy; override;
    function Count: Integer;
    function GetRemotePath: string;
    function Key: TPdbKey;
    procedure LoadFromFile(const FilePath: string);
    procedure LoadFromStream(AStream: TStream);
    procedure Reset;
    procedure UpdateSections(const Value: TSectionsRva);
    procedure UpdateStubSymbol(Index: Integer; AddrVA: Int64);
    property Age: DWORD read FAge;
    property BinaryPath: string read FBinaryPath write FBinaryPath;
    property LocalPath: string read FLocalPath;
    property PdbName: string read FPdbName;
    property State: TPdbState read FState;
    property Symbol[Index: Integer]: TPdbSymbol read GetSymbol; default;
    property UnicalId: TGUID read FUnicalId;
  end;

  TProxyKind = (pkNone, pkDefault, pkUserSettings, pkUserSettingsWithAuthority);
  TProxyAuthKind = (pakAuto, pakBasic, pakNegotiate, pakNTLM);

  TProxySettings = record
    Kind: TProxyKind;
    AuthKind: TProxyAuthKind;
    Host: string;
    Port: Integer;
    Login: string;
    Password: string;
  end;

  ESymSrvException = class(Exception);

  TSymSrvHandleChain = class
  private
    FSession, FConnect, FRequest: HINTERNET;
  public
    destructor Destroy; override;
    property Session: HINTERNET read FSession write FSession;
    property Connect: HINTERNET read FConnect write FConnect;
    property Request: HINTERNET read FRequest write FRequest;
  end;

  TSymSrvProgressState = (spsConnecting, spsDownloading, spsDone, spsError);
  TSymSrvContinueState = (scsRun, scsPause, scsCancel);
  TSymSrvProgressEvent = procedure(Sender: TObject;
    State: TSymSrvProgressState; Pdb: TPdb; BytesReceived, TotalBytes: Int64;
    var AContinueState: TSymSrvContinueState) of object;

  TSymSrv = class
  const
    UserAgent = 'RawScanner-PDB-Downloader/1.0';
  private
    FLastErrorCode, FLastHttpStatus: DWORD;
    FLastError: string;
    FProxySettings: TProxySettings;
    FState: TSymSrvProgressState;
    FOnProgress: TSymSrvProgressEvent;
    function AuthKindToScheme(Kind: TProxyAuthKind): DWORD;
    procedure DoProgress(State: TSymSrvProgressState; Pdb: TPdb;
      BytesReceived, TotalBytes: Int64; var AContinueState: TSymSrvContinueState);
    function OpenSession: HINTERNET;
    function PrepareRequest(const Url, Verb: string): TSymSrvHandleChain;
    function QueryStatusCode(hRequest: HINTERNET): DWORD;
    function QueryContentLength(hRequest: HINTERNET): DWORD;
    procedure ResetLastError;
    function SendAndReceive(hRequest: HINTERNET; out StatusCode: DWORD): Boolean;
    procedure SetLastErrorFrom(const Context: string);
    procedure SetLastErrorMsg(const Msg: string);
    procedure SetProxyCredentials(hRequest: HINTERNET; Scheme: DWORD);
    procedure SetProxySettings(const Value: TProxySettings);
    function WinHttpErrorMessage(ErrorCode: DWORD): string;
  public
    function CheckTwoTierStorage(const BaseUrl: string): Boolean;
    function CheckRemoteFilePresent(const BaseUrl: string): Boolean;
    function DownloadPdb(Pdb: TPdb): Boolean;
    function DownloadJson(const Url: string; out json: string): Boolean;
    property DownloadState: TSymSrvProgressState read FState;
    property LastErrorCode: DWORD read FLastErrorCode;
    property LastError: string read FLastError;
    property LastHttpStatus: DWORD read FLastHttpStatus;
    property ProxySettings: TProxySettings read FProxySettings write SetProxySettings;
    property OnProgress: TSymSrvProgressEvent read FOnProgress write FOnProgress;
  end;

  TAsyncSymSrv = class(TThread)
  private
    FBytesReceived, FTotalBytes: Int64;
    FContinueState: TSymSrvContinueState;
    FLastError: string;
    FLastErrorCode, FLastHttpStatus: DWORD;
    FPdb: TPdb;
    FProxySettings: TProxySettings;
    FState: TSymSrvProgressState;
    FSymSrv: TSymSrv;
    FOnProgress: TSymSrvProgressEvent;
    procedure InternalProgress(Sender: TObject; State: TSymSrvProgressState;
      Pdb: TPdb; BytesReceived, TotalBytes: Int64;
      var AContinueState: TSymSrvContinueState);
    procedure NotifyProgress;
  protected
    procedure Execute; override;
  public
    property DownloadState: TSymSrvProgressState read FState;
    property LastError: string read FLastError;
    property LastErrorCode: DWORD read FLastErrorCode;
    property LastHttpStatus: DWORD read FLastHttpStatus;
    property Pdb: TPdb read FPdb write FPdb;
    property ProxySettings: TProxySettings read FProxySettings write FProxySettings;
    property OnProgress: TSymSrvProgressEvent read FOnProgress write FOnProgress;
  end;

  TPdbKeyComparer = class(TInterfacedObject, IEqualityComparer<TPdbKey>)
  public
    function Equals(const Left, Right: TPdbKey): Boolean; reintroduce;
    function GetHashCode(const Value: TPdbKey): Integer; reintroduce;
  end;

  TPdbDownloadMode = (

    // synchronous, we just wait for it to finish downloading, DownloadPDB return nil
    // [ru] синхронно, просто ждем когда скачается, DownloadPDB возвращает nil

    pdmSync,

    // asynchronous in automatic mode, DownloadPDB return nil
    // [ru] асинхронно в автоматическом режиме, DownloadPDB возвращает nil

    pdmAsyncAuto,

    // asynchronous in modal mode, DownloadPDB return nil
    // [ru] асинхронно в модальном режиме, DownloadPDB возвращает nil

    pdmAsyncModal,

    // asynchronous with manual control, DownloadPDB returns a suspended TAsyncSymSrv,
    // which you must start and release yourself.

    // [ru] асинхронно с ручным контролем, DownloadPDB возвращает засуспенженый TAsyncSymSrv,
    // который нужно запустить и самому освободить.

    pdmAsyncManual
  );

  TSymStorageType = (
    sstUnknown,
    sstOneTier,
    sstTwoTiear
  );

  TPdbStorage = class
  private const
    OneTierFileName = 'pingme.txt';
    TwoTierFileName = 'index2.txt';
  private
    FCacheFolders: TStringList;
    FDefaultTwoTierStorage: Boolean;
    FLock: TCriticalSection;
    FPdbList: TObjectList<TPdb>;
    FPdbDict: TDictionary<TPdbKey, Integer>;
    FProxySettings: TProxySettings;
    FSymConfig: string;
    FSymServers: TStringList;
    FOnProgress: TSymSrvProgressEvent;
    function CheckRelativeKeyName(const Value: string): Boolean;
    function GetRelativePath(const APdbKey: TPdbKey): string;
    function GetSymSrvIndex(Value: Pointer): Integer;
    function GetSymSrvStorageType(Value: Pointer): TSymStorageType;
    function FixUpPath(const Folder, PdbPath: string; CreateNew: Boolean): string;
    function MakeSymSrvData(StorageType: TSymStorageType; Index: Integer): Pointer;
    procedure RunThreadModal(AThread: TThread);
    procedure SetSymConfig(const Value: string);
    procedure SetProxySettings(const Value: TProxySettings);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Clear;
    function DownloadPDB(Pdb: TPdb; SyncMode: TPdbDownloadMode): TAsyncSymSrv;
    function FindLocalPdb(const APdbKey: TPdbKey): string;
    function QueryPDB(const APdbKey: TPdbKey): TPdb; overload;
    function QueryPDB(const Uid: TGUID; Age: DWORD; const PdbFileName: string): TPdb; overload;
    function QueryRemotePDB(Pdb: TPdb): TPdbState;
    // CacheFolders — READ-ONLY!!! Use SymConfig to make changes
    property CacheFolders: TStringList read FCacheFolders;
    property DefaultTwoTierStorage: Boolean read FDefaultTwoTierStorage write FDefaultTwoTierStorage;
    property Items: TObjectList<TPdb> read FPdbList;
    property ProxySettings: TProxySettings read FProxySettings write SetProxySettings;
    property SymConfig: string read FSymConfig write SetSymConfig;
    property OnProgress: TSymSrvProgressEvent read FOnProgress write FOnProgress;
  end;

  TSymJobKind = (jkQuery, jkDownload);

  TSymJob = record
    Pdb: TPdb;
    Kind: TSymJobKind;
  end;

  TSymQueue = class;

  TSymWorkerThread = class(TThread)
  strict private
    FOwner: TSymQueue;
  protected
    procedure Execute; override;
  public
    constructor Create(AOwner: TSymQueue);
  end;

  TSymJobQueue = class
  private
    FItems: TQueue<TSymJob>;
    FLock: TCriticalSection;
    FEvent: TEvent;
    FContinueState: TSymSrvContinueState;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Push(const Job: TSymJob);
    function Pop(out Job: TSymJob): Boolean;
    procedure Pause;
    procedure Resume;
    procedure Stop;
  end;

  TSymQueueDoneEvent = procedure(Sender: TObject; const Job: TSymJob; const Error: string) of object;
  TSymQueueProgressEvent = procedure(Sender: TObject; State: TSymSrvProgressState;
    Pdb: TPdb; BytesReceived, TotalBytes: Int64) of object;

  TSymQueue = class
  strict private
    FActiveWorkers, FTotal, FDone: Integer;
    FStorage: TPdbStorage;
    FWorkers: TArray<TSymWorkerThread>;
    FJobs: TSymJobQueue;
    FContinueState: TSymSrvContinueState;
    FStopped: Boolean;
    FOnJobDone: TSymQueueDoneEvent;
    FOnBatchDone: TNotifyEvent;
    FOnProgress: TSymQueueProgressEvent;
    FOnStopped: TNotifyEvent;
    procedure HandleProgress(Sender: TObject; State: TSymSrvProgressState;
      Pdb: TPdb; BytesReceived, TotalBytes: Int64;
      var AContinueState: TSymSrvContinueState);
    procedure WorkerTerminated(Sender: TObject);
  protected
    function GetNextJob(out Job: TSymJob): Boolean;
    procedure RunJob(const Job: TSymJob);
    procedure NotifyJobDone(const Job: TSymJob; const Error: string);
  public
    constructor Create(AStorage: TPdbStorage; AWorkerCount: Integer);
    destructor Destroy; override;
    procedure QueryPdb(Pdb: TPdb);
    procedure DownloadPdb(Pdb: TPdb);
    procedure Pause;
    procedure Resume;
    procedure Stop;
    property ContinueState: TSymSrvContinueState read FContinueState;
    property OnJobDone: TSymQueueDoneEvent read FOnJobDone write FOnJobDone;
    property OnBatchDone: TNotifyEvent read FOnBatchDone write FOnBatchDone;
    property OnProgress: TSymQueueProgressEvent read FOnProgress write FOnProgress;
    property OnStopped: TNotifyEvent read FOnStopped write FOnStopped;
  end;

  function GetImagePdbKey(const FilePath: string; out Key: TPdbKey): Boolean;
  function IsPdbKeyEqual(const A, B: TPdbKey): Boolean;
  function LoadPdbInfo(const PdbFolder: string; out Info: TPdbInfo): Boolean;
  function SavePdbInfo(Pdb: TPdb; const ImageFilePath: string): Boolean;

implementation

function GetImagePdbKey(const FilePath: string; out Key: TPdbKey): Boolean;
const
  CV_SIGNATURE_RSDS = DWORD($53445352);
type
  TCV_INFO_PDB70 = record
    Signature: DWORD;   // 'RSDS'
    Guid: TGUID;
    Age: DWORD;
    // char  PdbFileName[]; // null-terminated
  end;
var
  Stream: TBufferedFileStream;
  DosHeader: TImageDosHeader;
  NtSignature: DWORD;
  FileHeader: TImageFileHeader;
  OptHeaderStart: Int64;
  OptMagic: Word;
  Opt32: TImageOptionalHeader32;
  Opt64: TImageOptionalHeader64;
  DebugDataDir: TImageDataDirectory;
  SectionTableStart: Int64;
  DebugDir: TImageDebugDirectory;
  EntryCount, I, NameLen: Integer;
  DebugDirFileOffset: Int64;
  CvInfo: TCV_INFO_PDB70;
  NameBuff: array of Byte;

  function RvaToFileOffset(Rva: DWORD): Int64;
  var
    S: Integer;
    Sec: TImageSectionHeader;
  begin
    Result := -1;
    Stream.Position := SectionTableStart;
    for S := 0 to FileHeader.NumberOfSections - 1 do
    begin
      Stream.ReadBuffer(Sec, SizeOf(Sec));
      if (Rva >= Sec.VirtualAddress) and (Rva < Sec.VirtualAddress + Sec.SizeOfRawData) then
      begin
        Result := Int64(Sec.PointerToRawData) + Int64(Rva - Sec.VirtualAddress);
        Exit;
      end;
    end;
  end;

begin
  Result := False;
  Key := Default(TPdbKey);

  Stream := TBufferedFileStream.Create(FilePath, fmOpenRead or fmShareDenyWrite);
  try
    if Stream.Size < SizeOf(TImageDosHeader) then Exit;
    Stream.ReadBuffer(DosHeader, SizeOf(DosHeader));
    if DosHeader.e_magic <> IMAGE_DOS_SIGNATURE then Exit;

    Stream.Position := DosHeader._lfanew;
    Stream.ReadBuffer(NtSignature, SizeOf(NtSignature));
    if NtSignature <> IMAGE_NT_SIGNATURE then Exit;

    Stream.ReadBuffer(FileHeader, SizeOf(FileHeader));
    OptHeaderStart := Stream.Position;
    SectionTableStart := OptHeaderStart + FileHeader.SizeOfOptionalHeader;

    if FileHeader.SizeOfOptionalHeader < SizeOf(Word) then Exit;

    Stream.ReadBuffer(OptMagic, SizeOf(OptMagic));
    Stream.Position := OptHeaderStart;

    case OptMagic of
      IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        begin
          if OptHeaderStart + SizeOf(Opt32) > Stream.Size then Exit;
          Stream.ReadBuffer(Opt32, SizeOf(Opt32));
          DebugDataDir := Opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        end;
      IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        begin
          if OptHeaderStart + SizeOf(Opt64) > Stream.Size then Exit;
          Stream.ReadBuffer(Opt64, SizeOf(Opt64));
          DebugDataDir := Opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        end;
    else
      Exit;
    end;

    if (DebugDataDir.VirtualAddress = 0) or (DebugDataDir.Size = 0) then Exit;

    DebugDirFileOffset := RvaToFileOffset(DebugDataDir.VirtualAddress);
    if DebugDirFileOffset < 0 then Exit;

    EntryCount := DebugDataDir.Size div SizeOf(TImageDebugDirectory);
    Stream.Position := DebugDirFileOffset;

    for I := 0 to EntryCount - 1 do
    begin
      if Stream.Position + SizeOf(TImageDebugDirectory) > Stream.Size then Break;
      Stream.ReadBuffer(DebugDir, SizeOf(DebugDir));

      if DebugDir._Type <> IMAGE_DEBUG_TYPE_CODEVIEW then Continue;
      if DebugDir.PointerToRawData = 0 then Continue;
      if Int64(DebugDir.PointerToRawData) + SizeOf(TCV_INFO_PDB70) > Stream.Size then Continue;

      Stream.Position := DebugDir.PointerToRawData;
      Stream.ReadBuffer(CvInfo, SizeOf(CvInfo));
      if CvInfo.Signature <> CV_SIGNATURE_RSDS then Continue; // PDB 2.0 (NB10) is not supported

      Key.Uid := CvInfo.Guid;
      Key.Age := CvInfo.Age;

      SetLength(NameBuff, Min(Int64(MAX_PATH), Stream.Size - Stream.Position));
      if Length(NameBuff) > 0 then
      begin
        Stream.ReadBuffer(NameBuff[0], Length(NameBuff));
        NameLen := 0;
        while (NameLen < Length(NameBuff)) and (NameBuff[NameLen] <> 0) do
          Inc(NameLen);
        SetString(Key.Name, PAnsiChar(@NameBuff[0]), NameLen);
      end;

      Result := True;
      Break;
    end;
  finally
    Stream.Free;
  end;
end;

function IsPdbKeyEqual(const A, B: TPdbKey): Boolean;
begin
  Result :=
    AnsiSameText(A.Name, B.Name) and
    (A.Age = B.Age) and
    IsEqualGUID(A.Uid, B.Uid);
end;

function LoadPdbInfo(const PdbFolder: string; out Info: TPdbInfo): Boolean;
var
  InfoFilePath, JsonText, GuidStr: string;
  JsonObj: TJSONObject;
  JsonValue: TJSONValue;
begin
  Result := False;
  Info := Default(TPdbInfo);
  InfoFilePath := IncludeTrailingPathDelimiter(PdbFolder) + PdbInfoFile;
  if not FileExists(InfoFilePath) then Exit;

  try
    JsonText := TFile.ReadAllText(InfoFilePath, TEncoding.UTF8);
  except
    Exit;
  end;

  JsonValue := TJSONObject.ParseJSONValue(JsonText);
  if not Assigned(JsonValue) then Exit;
  try
    if not (JsonValue is TJSONObject) then Exit;
    JsonObj := TJSONObject(JsonValue);
    Info.DownloadedAt := ISO8601ToDate(JsonObj.GetValue<string>('downloadedAt', ''));
    Info.DownloadedBy := JsonObj.GetValue<string>('downloadedBy', '');
    Info.DownloadedAt := TTimeZone.Local.ToLocalTime(Info.DownloadedAt);
    Info.RequestedForBinaryPath := JsonObj.GetValue<string>('requestedForBinaryPath', '');
    Info.BinaryAge := JsonObj.GetValue<Integer>('binaryAge', 0);
    GuidStr := JsonObj.GetValue<string>('binaryGuid', '');
    if GuidStr <> '' then
      Info.BinaryGuid := StringToGUID(GuidStr);
    Result := True;
  finally
    JsonValue.Free;
  end;
end;

function SavePdbInfo(Pdb: TPdb; const ImageFilePath: string): Boolean;
var
  InfoFilePath: string;
  JsonObj: TJSONObject;
begin
  Result := True;
  InfoFilePath := ExtractFilePath(Pdb.LocalPath) + PdbInfoFile;
  JsonObj := TJSONObject.Create;
  try
    JsonObj.AddPair('downloadedAt', DateToISO8601(TTimeZone.Local.ToUniversalTime(Now)));
    JsonObj.AddPair('downloadedBy', ExtractFileName(ParamStr(0)));
    JsonObj.AddPair('requestedForBinaryPath', ImageFilePath);
    JsonObj.AddPair('binaryGuid', GUIDToString(Pdb.UnicalId));
    JsonObj.AddPair('binaryAge', TJSONNumber.Create(Pdb.Age));

    try
      TFile.WriteAllText(InfoFilePath, JsonObj.Format(2), TEncoding.UTF8);
    except
      Exit(False); // No write permissions
    end;

    {$WARN SYMBOL_PLATFORM OFF}
    FileSetAttr(InfoFilePath, faHidden);
    {$WARN SYMBOL_PLATFORM ON}
  finally
    JsonObj.Free;
  end;
end;

procedure ValidateProxy(Value: TProxySettings);
begin
  if Value.Kind in [pkUserSettings, pkUserSettingsWithAuthority] then
  begin
    if Value.Host = '' then
      raise ESymSrvException.Create('The proxy server address is not specified');
    if Value.Port = 0 then
      raise ESymSrvException.Create('The proxy server port is not specified');
  end;
  if Value.Kind = pkUserSettingsWithAuthority then
    if Value.Login = '' then
      raise ESymSrvException.Create('The proxy server username is not specified');
end;

{ TPdb }

procedure TPdb.CheckStream(AStream: TStream);
const
  MsfMagicPrefix: AnsiString = 'Microsoft C/C++ MSF 7.00';
begin
  if AStream.Size < SizeOf(BIGMSF_HDR) then
    raise EPdbException.Create('The PDB file is too small or corrupted');

  AStream.Position := 0;
  AStream.ReadBuffer(FHeader, SizeOf(BIGMSF_HDR));

  if not CompareMem(@FHeader.Magic[0], @MsfMagicPrefix[1], Length(MsfMagicPrefix)) then
    raise EPdbException.Create('Invalid MSF signature, this is not a PDB file');

  if (FHeader.cbPg = 0) or (FHeader.pnMac = 0) then
    raise EPdbException.Create('Invalid MSF header');
end;

function TPdb.Count: Integer;
begin
  Result := FSymbols.Count;
end;

constructor TPdb.Create(APdbKey: TPdbKey);
begin
  FSymbols := TList<TPdbSymbol>.Create;
  FAge := APdbKey.Age;
  FUnicalId := APdbKey.Uid;
  FPdbName := APdbKey.Name;
end;

constructor TPdb.Create;
begin
  Create(Default(TPdbKey));
end;

destructor TPdb.Destroy;
begin
  FSymbols.Free;
  inherited;
end;

procedure TPdb.DetectIsfStubs;
var
  Dict: TDictionary<DWORD, Integer>;
  I, Cnt: Integer;
begin
  Dict := TDictionary<DWORD, Integer>.Create;
  try
    Dict.Capacity := FSymbols.Count;
    for I := 0 to FSymbols.Count - 1 do
    begin
      if FSymbols.List[I].SymbolType = pstData then
        Continue;
      if not Dict.TryGetValue(FSymbols.List[I].Rva, Cnt) then
        Cnt := 0;
      Inc(Cnt);
      Dict.AddOrSetValue(FSymbols.List[I].Rva, Cnt);
    end;
    for I := 0 to FSymbols.Count - 1 do
    begin
      Dict.TryGetValue(FSymbols.List[I].Rva, Cnt);
      if Cnt > 2 then
        FSymbols.List[I].SymbolType := pstIcfStub
    end;
  finally
    Dict.Free;
  end;
end;

function TPdb.GetRemotePath: string;
begin
  Result := RemotePath;
end;

function TPdb.GetStream(AStream: TStream; Index: Integer): TBytes;
begin
  if (Index < 0) or (Index >= Length(FStreamSizes)) then
    Result := nil
  else
    Result := ReadPages(AStream, FStreamPages[Index], FStreamSizes[Index]);
end;

function TPdb.GetSymbol(Index: Integer): TPdbSymbol;
begin
  if FState = psNoSections then
    raise EPdbException.Create('The PDB does not contain information about sections.' + sLineBreak +
      'This information must be loaded from an external source by calling `UpdateSections()`');

  Result := FSymbols[Index];
  if (Result.Section < 0) or (Result.Section >= Length(FSectionsRva)) then
    raise EPdbException.CreateFmt('"%s" contain invalid symbol (%d). Invalid section index (%d). Expected 0..%d',
      [PdbName, Index, Result.Section, Length(FSectionsRva) - 1]);

  Inc(Result.Rva, FSectionsRva[Result.Section]);
end;

function TPdb.Key: TPdbKey;
begin
  Result := Default(TPdbKey);
  Result.Uid := FUnicalId;
  Result.Age := Age;
  Result.Name := PdbName;
end;

procedure TPdb.LoadFromFile(const FilePath: string);
var
  F: TBufferedFileStream;
begin
  F := TBufferedFileStream.Create(FilePath, fmOpenRead or fmShareDenyWrite);
  try
    SetLocalPath(StringReplace(FilePath, '/', '\', [rfReplaceAll]));
    LoadFromStream(F);
  finally
    F.Free;
  end;
end;

procedure TPdb.LoadFromStream(AStream: TStream);
begin
  CheckStream(AStream);
  LoadStreams(AStream);
  LoadSymbols(AStream);
  UpdateUnicalId(AStream);
  DetectIsfStubs;
end;

procedure TPdb.LoadSectionData(AStream: TStream; const Dbi: TBytes);
var
  Sections: TBytes;
  DbiHeader: PDbiStreamHeader;
  DebugHeaderOffset: Int64;
  DebugHeader: PDbiDebugHeader;
  pSection: PImageSectionHeader;
  I: Integer;
begin
  DbiHeader := PDbiStreamHeader(@Dbi[0]);
  FAge := DbiHeader^.Age;
  if DbiHeader^.OptionalDebugHeaderSize = 0 then Exit;

  // https://llvm.org/docs/PDB/DbiStream.html#dbi-optional-dbg-stream
  // An additional debug header follows all the substreams specified in the DBI header.

  // [ru] Дополнительный отладочный заголовок лежит после всех подпотоков
  // которые указаны в заголовке DBI

  DebugHeaderOffset :=
    SizeOf(TDbiStreamHeader) +
    DbiHeader.ModuleInfoSize +
    DbiHeader.SectionContributionSize +
    DbiHeader.SectionMapSize +
    DbiHeader.SourceInfoSize +
    DbiHeader.TypeServerMapSize +
    DbiHeader.EcSubstreamSize;

  if DebugHeaderOffset + SizeOf(TDbiDebugHeader) > Length(Dbi) then Exit;

  // and that's exactly where the stream number with titles might be found
  // [ru] и именно в нем может лежать номер стрима с заголовками

  DebugHeader := PDbiDebugHeader(@Dbi[DebugHeaderOffset]);

  // or maybe not
  // [ru] а может и не лежать

  if DebugHeader^.SectionHeaderStreamIndex = DBI_INVALID_STREAM_INDEX then Exit;
  Sections := GetStream(AStream, DebugHeader^.SectionHeaderStreamIndex);
  if Sections = nil then Exit;

  // The section stream itself is literally a one-to-one dump of the PE file's sections,
  // so we read it using the standard structure. We only need to know the VirtualAddress

  // [ru] Сам поток секций это буквально дамп секций PE файла один в один,
  // поэтому читаем штатной структурой. Нам нужно знать только VirtualAddress

  pSection := @Sections[0];
  SetLength(FSectionsRva, Length(Sections) div SizeOf(TImageSectionHeader));
  for I := 0 to Length(FSectionsRva) - 1 do
  begin
    FSectionsRva[I] := pSection^.VirtualAddress;
    Inc(pSection);
  end;
end;

procedure TPdb.LoadStreams(AStream: TStream);
var
  DirectoryPageCount: Integer;
  BlockMapEntryCount: Integer;
  BlockMapPages: TPages;
  DirectoryPagesRaw: TBytes;
  DirectoryPages: TPages;
  DirectoryData: TBytes;
  DirData: PIntegerArray;
  StreamCount: Integer;
  Idx, I, A: Integer;
begin

  // First, we retrieve a list of pages containing information about the pages
  // in the directory. Typically, this list consists of fewer than one page, and to store a link to
  // it, the first element of the FHeader.mpspnpnSt[0] header is sufficient

  // [ru] Для начала получаем список страниц где расположена информация о страницах
  // директории. Как правило она меньше одной страницы и для хранения ссылки на
  // неё достаточно первого элемента заголовка FHeader.mpspnpnSt[0]

  DirectoryPageCount := PagesCount(FHeader.siSt.cb);
  BlockMapEntryCount := PagesCount(DirectoryPageCount * SizeOf(UPN));
  SetLength(BlockMapPages, BlockMapEntryCount);
  if BlockMapEntryCount > 0 then
  begin
    BlockMapPages[0] := FHeader.mpspnpnSt[0];

    // But if more data is needed (it would have to be a massive PDB),
    // then we read in the additional data

    // [ru] Но если вдруг нужно больше (это должен быть гигантский PDB),
    // то дочитываем дополнительные данные

    if BlockMapEntryCount > 1 then
    begin
      AStream.Position := SizeOf(BIGMSF_HDR);
      AStream.ReadBuffer(BlockMapPages[1], (BlockMapEntryCount - 1) * SizeOf(UPN));
    end;
  end;

  // Now we get a list of the pages that make up the directory.
  // [ru] Теперь получаем список страниц, из которых состоит директория.

  DirectoryPagesRaw := ReadPages(AStream, BlockMapPages, DirectoryPageCount * SizeOf(UPN));
  SetLength(DirectoryPages, DirectoryPageCount);
  if DirectoryPageCount > 0 then
    Move(DirectoryPagesRaw[0], DirectoryPages[0], DirectoryPageCount * SizeOf(UPN));

  // Step 3: Read the directory data
  // [ru] Шаг 3: читаем данные директории

  DirectoryData := ReadPages(AStream, DirectoryPages, FHeader.siSt.cb);

  // Step four: Retrieve stream data from the directory
  // The structure itself is straightforward (processed in 4-byte blocks):
  // Count (4 bytes) of streams containing data
  // An array (Count * 4) of the sizes of each stream
  // An array of pages containing the data for each stream, where the number of records
  // per page for each stream is calculated based on the size of the stream itself.

  // [ru] Шаг четыре: извлекаем из директории данные о стримах
  // Сама структура тривиальная (идет блоками по 4 байта):
  // Count (4 байта) стримов с данными
  // Массив (Count * 4) размеров каждого стрима
  // Массив страниц содержащий данные каждого стрима, где количетсво записей
  // страниц для каждого стрима рассчитывается от размера самого стрима.

  DirData := @DirectoryData[0];
  StreamCount := DirData[0];

  SetLength(FStreamPages, StreamCount);
  SetLength(FStreamSizes, StreamCount);

  // We read it in two passes because the dimensions come first
  // [ru] Читаем в два прохода, потому что сначала идут размеры

  Idx := 1;
  for I := 0 to StreamCount - 1 do
  begin
    FStreamSizes[I] := DirData[Idx];

    // and the amount of data for each stream depends on its size
    // [ru] и количество данных по каждому стриму зависит от его размера

    SetLength(FStreamPages[I], PagesCount(FStreamSizes[I]));
    Inc(Idx);
  end;

  // And right after the dimensions come the data itself,
  // the size of which was calculated above

  // [ru] А уже после размеров идут сами данные,
  // размер которых рассчитан выше

  for I := 0 to StreamCount - 1 do
  begin
    for A := 0 to Length(FStreamPages[I]) - 1 do
    begin
      FStreamPages[I][A] := DirData[Idx];
      Inc(Idx);
    end;

    // Once the mini-FAT has been assembled (i.e. the page numbers specifying the order
    // in which the data should be read to put everything together),
    // the data can be read using a lazy load

    // [ru] как только собрали мини-FAT (т.е. номера страниц указывающих порядок
    // чтения данных чтобы собрать все воедино), данные можно зачитать ленивым вызовом

  end;
end;

procedure TPdb.LoadSymbols(AStream: TStream);
var
  Dbi: TBytes;
  DbiHeader: PDbiStreamHeader;
  PublicsData, SymRecordData: TBytes;
  GsiHeader: PGsiHashTableHeader;
  HashRecordsOffset: Integer;
  NumRecords, I, SymCount, PublicsDataLen, SymDataLen, SecCount: Integer;
  HashRec: PPdbHashRecord;
  SymOffset: DWORD;
  PubSym: PPUBSYM32;
  NameStart, NameEnd: Integer;
  Sym: TPdbSymbol;
begin
  Dbi := GetStream(AStream, PDB_STREAM_DBI);
  if Length(Dbi) < SizeOf(TDbiStreamHeader) then Exit;

  LoadSectionData(AStream, Dbi);
  SecCount := Length(FSectionsRva);
  if SecCount > 0 then
    FMaxSectionIdx := SecCount - 1;

  DbiHeader := PDbiStreamHeader(@Dbi[0]);

  // To load the data, you need a stream containing character hashes (PublicStreamIndex)
  // and a stream containing the characters themselves (SymbolRecordStreamIndex)

  // [ru] Для загрузки нужен стрим с хэшами символов (PublicStreamIndex)
  // и стрим с самими символами (SymbolRecordStreamIndex)

  if (DbiHeader^.PublicStreamIndex < 0) or (DbiHeader^.SymbolRecordStreamIndex < 0) then Exit;

  PublicsData := GetStream(AStream, DbiHeader^.PublicStreamIndex);
  PublicsDataLen := Length(PublicsData);
  SymRecordData := GetStream(AStream, DbiHeader^.SymbolRecordStreamIndex);
  SymDataLen := Length(SymRecordData);
  if (PublicsDataLen < SizeOf(TPublicStreamHeader) + SizeOf(TGsiHashTableHeader)) or
     (SymDataLen = 0) then Exit;

  GsiHeader := PGsiHashTableHeader(@PublicsData[SizeOf(TPublicStreamHeader)]);

  // The same safety check as in raw_pdb (HasValidPublicSymbolStream)
  // [ru] Такая же подстраховка как и в raw_pdb (HasValidPublicSymbolStream)

  if GsiHeader^.Signature <> GSI_HASH_SIGNATURE then Exit;
  if GsiHeader^.Version <> GSI_HASH_VERSION then Exit;

  HashRecordsOffset := SizeOf(TPublicStreamHeader) + SizeOf(TGsiHashTableHeader);
  if HashRecordsOffset + Integer(GsiHeader^.HashRecordsSize) > PublicsDataLen then Exit;

  NumRecords := GsiHeader^.HashRecordsSize div SizeOf(TPdbHashRecord);

  FSymbols.Count := NumRecords;
  SymCount := 0;
  for I := 0 to NumRecords - 1 do
  begin
    HashRec := PPdbHashRecord(@PublicsData[HashRecordsOffset + I * SizeOf(TPdbHashRecord)]);
    if HashRec^.Offset = 0 then Continue;

    // is saved with an offset of +1
    // [ru] хранится со сдвигом +1

    SymOffset := HashRec^.Offset - 1;

    if Int64(SymOffset) + SizeOf(PUBSYM32) > SymDataLen then Continue;
    PubSym := PPUBSYM32(@SymRecordData[SymOffset]);
    if PubSym^.rectyp <> CV_SYMBOL_KIND_S_PUB32 then Continue;

    // Symbols not associated with a section are skipped
    // [ru] Символы не привязанные к секции тоже пропускаются

    if PubSym^.seg = 0 then Continue;

    // If the sections are available, we discard everything outside the section range.
    // [ru] Если секции есть в наличии, то выкидываем все что за диапазоном секций.

    if (SecCount > 0) and (PubSym^.seg >= SecCount) then Continue;

    NameStart := Integer(SymOffset) + SizeOf(PUBSYM32);

    // the Size field does not contain itself, it needs to be added.
    // [ru] поле Size себя не содержит, нужно добавить

    NameEnd := Integer(SymOffset) + PubSym^.reclen + SizeOf(Word);
    if NameEnd > SymDataLen then Continue;

    Sym.Name := ReadSymbolName(SymRecordData, NameStart, NameEnd);
    Sym.Rva := PubSym^.off;

    // also with a shift of one
    // [ru] также со сдвидом в единицу

    Sym.Section := PubSym^.seg - 1;
    if (PubSym^.pubsymflags and CVPSF_FUNCTION) <> 0 then
      Sym.SymbolType := pstFunc
    else
      Sym.SymbolType := pstData;

    if SecCount = 0 then
      FMaxSectionIdx := Max(FMaxSectionIdx, Sym.Section);

    FSymbols.List[SymCount] := Sym;
    Inc(SymCount);
  end;
  FSymbols.Count := SymCount;
end;

function TPdb.PagesCount(Value: CB): Integer;
begin
  if Value <= 0 then
    Result := 0
  else
    Result := Max(1, (Value + FHeader.cbPg - 1) div FHeader.cbPg);
end;

function TPdb.ReadPages(AStream: TStream; const PageList: TPages; TotalSize: Int64): TBytes;
var
  I: Integer;
  ChunkSize: CB;
  SrcOffset, DstOffset: Int64;
begin
  if TotalSize <= 0 then Exit(nil);  
  SetLength(Result, TotalSize);
  DstOffset := 0;
  for I := 0 to Length(PageList) - 1 do
  begin
    if DstOffset >= TotalSize then Break;
    ChunkSize := FHeader.cbPg;
    if DstOffset + ChunkSize > TotalSize then
      ChunkSize := TotalSize - DstOffset;
    SrcOffset := Int64(PageList[I]) * FHeader.cbPg;
    if SrcOffset + ChunkSize > AStream.Size then
      ChunkSize := AStream.Size - SrcOffset;
    if ChunkSize <= 0 then Break;
    AStream.Position := SrcOffset;
    AStream.ReadBuffer(Result[DstOffset], ChunkSize);
    Inc(DstOffset, FHeader.cbPg);
  end;
end;

function TPdb.ReadSymbolName(const Data: TBytes; NameStart,
  RecordEnd: Integer): string;
const
  LINKER_INTERNAL_SYMBOL_PREFIX = $7F;
var
  NameEnd, DataEnd: Integer;
begin
  NameEnd := NameStart;
  DataEnd := Length(Data);
  while (NameEnd < RecordEnd) and (NameEnd < Length(Data)) and (Data[NameEnd] <> 0) do
  begin
    Inc(NameEnd);
    if NameEnd = DataEnd then
      Break;
  end;
  SetString(Result, PAnsiChar(@Data[NameStart]), NameEnd - NameStart);
  if Data[NameStart] = LINKER_INTERNAL_SYMBOL_PREFIX then
    Result[1] := '_';
end;

procedure TPdb.Reset;
begin
  FState := psNotFoundLocally;
  FSymbols.Clear;
  FMaxSectionIdx := 0;
  SetLength(FSectionsRva, 0);
  FHeader := Default(BIGMSF_HDR);
end;

procedure TPdb.SetLocalPath(const Value: string);
begin
  FLocalPath := Value;
  FPdbName := ExtractFileName(Value);
end;

procedure TPdb.UpdateSections(const Value: TSectionsRva);
begin
  FSectionsRva := Value;
  if (FState = psNoSections) and (FMaxSectionIdx < Length(Value)) then
    FState := psReady;
end;

procedure TPdb.UpdateState(NewState: TPdbState);
begin
  FState := NewState;
end;

procedure TPdb.UpdateStubSymbol(Index: Integer; AddrVA: Int64);
begin
  FSymbols.List[Index].Name := Format('null_stub_%X', [AddrVA]);
end;

procedure TPdb.UpdateUnicalId(AStream: TStream);
var
  Strm: TBytes;
begin
  FState := psBroken;

  Strm := GetStream(AStream, PDB_STREAM_PDB_INFO);
  if Length(Strm) >= SizeOf(TPdbStreamHeader) then
  begin
    FUnicalId := PPdbStreamHeader(@Strm[0]).UinqueId;
    if Count > 0 then
    begin
      if FMaxSectionIdx >= Length(FSectionsRva) then
        FState := psNoSections
      else
        FState := psReady;
    end;
  end;

  // We no longer need the FAT streams, let's free up some memory
  // [ru] FAT стримов больше не нужен, освобождаем память

  SetLength(FStreamPages, 0);
  SetLength(FStreamSizes, 0);
end;

{ TSymSrvHandleChain }

destructor TSymSrvHandleChain.Destroy;
begin
  if FRequest <> nil then WinHttpCloseHandle(FRequest);
  if FConnect <> nil then WinHttpCloseHandle(FConnect);
  if FSession <> nil then WinHttpCloseHandle(FSession);
  inherited;
end;

{ TSymSrv }

function TSymSrv.AuthKindToScheme(Kind: TProxyAuthKind): DWORD;
begin
  case Kind of
    pakBasic: Result := WINHTTP_AUTH_SCHEME_BASIC;
    pakNegotiate: Result := WINHTTP_AUTH_SCHEME_NEGOTIATE;
    pakNTLM: Result := WINHTTP_AUTH_SCHEME_NTLM;
  else
    Result := 0;
  end;
end;

function TSymSrv.CheckRemoteFilePresent(const BaseUrl: string): Boolean;
var
  Chain: TSymSrvHandleChain;
  StatusCode: DWORD;
begin
  Result := False;
  ResetLastError;
  Chain := PrepareRequest(BaseUrl, 'HEAD');
  if Chain = nil then Exit;
  try
    if not SendAndReceive(Chain.Request, StatusCode) then Exit;
    Result := StatusCode = HTTP_STATUS_OK;
    if not Result then
      SetLastErrorMsg(Format('Server returned HTTP status %d', [StatusCode]));
  finally
    Chain.Free;
  end;
end;

function TSymSrv.CheckTwoTierStorage(const BaseUrl: string): Boolean;
begin
  // Here, we only need the status code to confirm that the file is present
  // in the character storage.
  // "The content of the file is of no importance"

  // [ru] Тут нам нужен только статус-код, что файл присутствует в хранилище символов.
  // содержимое файла неважно: "The content of the file is of no importance"

  // https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-store-folder-tree
  Result := CheckRemoteFilePresent(BaseUrl + '/index2.txt');
end;

procedure TSymSrv.DoProgress(State: TSymSrvProgressState; Pdb: TPdb;
  BytesReceived, TotalBytes: Int64; var AContinueState: TSymSrvContinueState);
begin
  FState := State;
  if Assigned(FOnProgress) then
    FOnProgress(Self, State, Pdb, BytesReceived, TotalBytes, AContinueState);
end;

function TSymSrv.DownloadJson(const Url: string; out json: string): Boolean;
const
  BuffSize = $100000;
var
  Chain: TSymSrvHandleChain;
  StatusCode: DWORD;
  ContentLength: DWORD;
  BytesAvailable, BytesRead: DWORD;
  Buff: array of Byte;
  TmpStream: TMemoryStream;
  StartOffset: Integer;
  P: PByte;
begin
  Result := False;
  ResetLastError;
  SetLength(Buff, BuffSize);
  Chain := PrepareRequest(Url, 'GET');
  if Chain = nil then Exit;
  try

    if not WinHttpAddRequestHeaders(Chain.Request,
      'User-Agent: ' + UserAgent + sLineBreak +
      'Accept: application/vnd.github+json',
      DWORD(-1), WINHTTP_ADDREQ_FLAG_ADD or WINHTTP_ADDREQ_FLAG_REPLACE) then
    begin
      SetLastErrorFrom('WinHttpAddRequestHeaders');
      Exit;
    end;

    if not SendAndReceive(Chain.Request, StatusCode) then Exit;

    if StatusCode <> HTTP_STATUS_OK then
    begin
      SetLastErrorMsg(Format('Server returned HTTP status %d', [StatusCode]));
      Exit;
    end;

    ContentLength := QueryContentLength(Chain.Request);

    TmpStream := TMemoryStream.Create;
    try
      repeat
        BytesAvailable := 0;
        if not WinHttpQueryDataAvailable(Chain.Request, @BytesAvailable) then
        begin
          SetLastErrorFrom('WinHttpQueryDataAvailable');
          Break;
        end;
        if BytesAvailable = 0 then Break;
        if BytesAvailable > BuffSize then
          BytesAvailable := BuffSize;
        if not WinHttpReadData(Chain.Request, Buff[0], BytesAvailable, @BytesRead) then
        begin
          SetLastErrorFrom('WinHttpReadData');
          Break;
        end;
        if BytesRead = 0 then Break;
        TmpStream.WriteBuffer(Buff[0], BytesRead);
      until False;

      if (FLastErrorCode = 0) and (ContentLength > 0) and (TmpStream.Size <> ContentLength) then
      begin
        SetLastErrorMsg(Format(
          'Download interrupted: received %d of %d bytes', [TmpStream.Size, ContentLength]));
        Exit;
      end;

      P := TmpStream.Memory;
      if (TmpStream.Size >= 3) and (P[0] = $EF) and (P[1] = $BB) and (P[2] = $BF) then
        StartOffset := 3
      else
        StartOffset := 0;
      SetLength(Buff, TmpStream.Size - StartOffset);
      TmpStream.Position := StartOffset;
      TmpStream.ReadBuffer(Buff[0], Length(Buff));
      json := TEncoding.UTF8.GetString(Buff);

    finally
      TmpStream.Free;
    end;

    Result := True;

  finally
    Chain.Free;
  end;
end;

function TSymSrv.DownloadPdb(Pdb: TPdb): Boolean;
const
  BuffSize = $100000;
var
  Chain: TSymSrvHandleChain;
  StatusCode: DWORD;
  ContentLength: DWORD;
  BytesAvailable, BytesRead: DWORD;
  Buff: array of Byte;
  OutStream: TFileStream;
  TotalReceived: Int64;
  TmpFile: string;
  ContinueState: TSymSrvContinueState;
begin
  Result := False;
  ResetLastError;

  ContentLength := 0;
  TotalReceived := 0;
  SetLength(Buff, BuffSize);
  ContinueState := scsRun;
  repeat
    DoProgress(spsConnecting, Pdb, TotalReceived, ContentLength, ContinueState);
    if ContinueState = scsCancel then Exit;
  until ContinueState = scsRun;
  Pdb.UpdateState(psLoading);

  Chain := PrepareRequest(Pdb.RemotePath, 'GET');
  if Chain = nil then Exit;
  try
    if not SendAndReceive(Chain.Request, StatusCode) then Exit;

    if StatusCode <> HTTP_STATUS_OK then
    begin
      SetLastErrorMsg(Format('Server returned HTTP status %d', [StatusCode]));
      Exit;
    end;

    ContentLength := QueryContentLength(Chain.Request);

    try
      TmpFile := Pdb.LocalPath + '.downloading';
      ForceDirectories(ExtractFilePath(TmpFile));
      OutStream := TFileStream.Create(TmpFile, fmCreate);
    except
      on E: Exception do
      begin
        SetLastErrorMsg('Cannot create temp file "' + TmpFile + '"' + sLineBreak +
          E.ClassName + ': ' + E.Message);
        Exit;
      end;
    end;
    try
      TotalReceived := 0;
      repeat
        BytesAvailable := 0;
        if not WinHttpQueryDataAvailable(Chain.Request, @BytesAvailable) then
        begin
          SetLastErrorFrom('WinHttpQueryDataAvailable');
          Break;
        end;
        if BytesAvailable = 0 then Break;
        if BytesAvailable > BuffSize then
          BytesAvailable := BuffSize;
        if not WinHttpReadData(Chain.Request, Buff[0], BytesAvailable, @BytesRead) then
        begin
          SetLastErrorFrom('WinHttpReadData');
          Break;
        end;
        if BytesRead = 0 then Break;
        OutStream.WriteBuffer(Buff[0], BytesRead);
        Inc(TotalReceived, BytesRead);
        repeat
          DoProgress(spsDownloading, Pdb, TotalReceived, ContentLength, ContinueState);
          case ContinueState of
            scsRun: ;
            scsPause: Sleep(100);
            scsCancel: Break;
          end;
        until ContinueState = scsRun;
        if ContinueState = scsCancel then
        begin
          Pdb.UpdateState(psAvailableForLoading);
          Result := True;
          Break;
        end;
      until False;
    finally
      OutStream.Free;
    end;

    if (FLastErrorCode = 0) and (ContentLength > 0) and (TotalReceived <> ContentLength) then
      SetLastErrorMsg(Format(
        'Download interrupted: received %d of %d bytes', [TotalReceived, ContentLength]));

    if FLastError <> '' then
    begin
      TFile.Delete(TmpFile);
      Exit;
    end;

    try
      if FileExists(Pdb.LocalPath) then
        TFile.Delete(Pdb.LocalPath);
      TFile.Move(TmpFile, Pdb.LocalPath);
    except
      on E: Exception do
      begin
        SetLastErrorMsg('Cannot move "' + TmpFile + '" to "' + Pdb.LocalPath + '"' +
          sLineBreak + E.ClassName + ': ' + E.Message);
        Exit;
      end;
    end;

    Pdb.LoadFromFile(Pdb.LocalPath);
    Pdb.RemotePath := '';

    Result := True;

  finally
    Chain.Free;
    if Result then
      DoProgress(spsDone, Pdb, TotalReceived, ContentLength, ContinueState)
    else
      DoProgress(spsError, Pdb, TotalReceived, ContentLength, ContinueState);
  end;
end;

function TSymSrv.OpenSession: HINTERNET;
var
  ProtocolFlags: DWORD;
begin
  case FProxySettings.Kind of
    pkNone:
      Result := WinHttpOpen(PChar(UserAgent),
        WINHTTP_ACCESS_TYPE_NO_PROXY, nil, nil, 0);
    pkUserSettings, pkUserSettingsWithAuthority:
      Result := WinHttpOpen(PChar(UserAgent),
        WINHTTP_ACCESS_TYPE_NAMED_PROXY,
        PChar(Format('%s:%d', [FProxySettings.Host, FProxySettings.Port])),
        nil, 0);
  else
    Result := WinHttpOpen(PChar(UserAgent),
      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nil, nil, 0);
  end;
  if Result = nil then
    SetLastErrorFrom('WinHttpOpen')
  else
  begin

    // Force a fallback to HTTP/1.1 — to work around a bug
    // that causes WinHTTP to hang when using HTTP/2 for large downloads

    // [ru] Принудительный откат на HTTP/1.1 — для обхода бага
    // зависания WinHTTP при работе по HTTP/2 на больших закачках

    ProtocolFlags := 0;
    if not WinHttpSetOption(Result, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL,
      @ProtocolFlags, SizeOf(ProtocolFlags)) then
    begin
      SetLastErrorFrom('WinHttpSetOption');
      WinHttpCloseHandle(Result);
      Result := nil;
    end;
  end;
end;

function TSymSrv.PrepareRequest(const Url, Verb: string): TSymSrvHandleChain;
var
  Comp: TUrlComponents;
  HostBuf: array[0..INTERNET_MAX_HOST_NAME_LENGTH - 1] of Char;
  PathBuf: array[0..INTERNET_MAX_PATH_LENGTH - 1] of Char;
  Flags: DWORD;
begin
  Result := TSymSrvHandleChain.Create;
  try
    Comp := Default(TUrlComponents);
    Comp.dwStructSize := SizeOf(Comp);
    Comp.lpszHostName := @HostBuf[0];
    Comp.dwHostNameLength := Length(HostBuf);
    Comp.lpszUrlPath := @PathBuf[0];
    Comp.dwUrlPathLength := Length(PathBuf);
    if not WinHttpCrackUrl(PChar(Url), Length(Url), 0, Comp) then
    begin
      SetLastErrorFrom('WinHttpCrackUrl');
      FreeAndNil(Result);
      Exit;
    end;

    Result.Session := OpenSession;
    if Result.Session = nil then
    begin
      FreeAndNil(Result);
      Exit;
    end;

    Result.Connect := WinHttpConnect(Result.Session, Comp.lpszHostName, Comp.nPort, 0);
    if Result.Connect = nil then
    begin
      SetLastErrorFrom('WinHttpConnect');
      FreeAndNil(Result);
      Exit;
    end;

    Flags := 0;
    if Comp.nScheme = INTERNET_SCHEME_HTTPS then
      Flags := WINHTTP_FLAG_SECURE;

    Result.Request := WinHttpOpenRequest(Result.Connect, PChar(Verb),
      Comp.lpszUrlPath, nil, nil, nil, Flags);
    if Result.Request = nil then
    begin
      SetLastErrorFrom('WinHttpOpenRequest');
      FreeAndNil(Result);
      Exit;
    end;

    // If the proxy's authorization scheme is specified explicitly,
    // then you need to provide the credentials right away to avoid an extra step due to a 407 error

    // [ru] Если схема авторизации прокси задана явно,
    // то нужно выставить реквизиты сразу, чтобы не тратить лишний шаг на 407

    if (FProxySettings.Kind = pkUserSettingsWithAuthority) and
       (FProxySettings.AuthKind <> pakAuto) then
      SetProxyCredentials(Result.Request, AuthKindToScheme(FProxySettings.AuthKind));
  except
    FreeAndNil(Result);
    raise;
  end;
end;

function TSymSrv.QueryContentLength(hRequest: HINTERNET): DWORD;
var
  Size: DWORD;
begin
  Result := 0;
  Size := SizeOf(Result);
  if not WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH or
    WINHTTP_QUERY_FLAG_NUMBER, nil, @Result, Size, nil) then
    Result := 0;
end;

function TSymSrv.QueryStatusCode(hRequest: HINTERNET): DWORD;
var
  Size: DWORD;
begin
  Result := 0;
  Size := SizeOf(Result);
  WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE or
    WINHTTP_QUERY_FLAG_NUMBER, nil, @Result, Size, nil);
  FLastHttpStatus := Result;
end;

procedure TSymSrv.ResetLastError;
begin
  FLastErrorCode := NO_ERROR;
  FLastHttpStatus := 0;
  FLastError := '';
end;

function TSymSrv.SendAndReceive(hRequest: HINTERNET;
  out StatusCode: DWORD): Boolean;
var
  SupportedSchemes, FirstScheme, AuthTarget: DWORD;
begin
  Result := False;
  StatusCode := 0;

  if not WinHttpSendRequest(hRequest, nil, 0, nil, 0, 0, 0) then
  begin
    SetLastErrorFrom('WinHttpSendRequest');
    Exit;
  end;
  if not WinHttpReceiveResponse(hRequest, nil) then
  begin
    SetLastErrorFrom('WinHttpReceiveResponse');
    Exit;
  end;
  StatusCode := QueryStatusCode(hRequest);

  // Automatic detection of the proxy authorization scheme for a 407 error (not tested)
  // [ru] Автоопределение схемы авторизации прокси при 407 (не протестировано)

  if (StatusCode = HTTP_STATUS_PROXY_AUTH_REQ) and (FProxySettings.Kind =
    pkUserSettingsWithAuthority) and (FProxySettings.AuthKind = pakAuto) then
  begin
    if not WinHttpQueryAuthSchemes(hRequest, SupportedSchemes, FirstScheme, AuthTarget) then
    begin
      SetLastErrorFrom('WinHttpQueryAuthSchemes');
      Exit;
    end;

    SetProxyCredentials(hRequest, FirstScheme);

    // Then we'll give it another try
    // [ru] После чего пробуем еще одну попытку

    if not WinHttpSendRequest(hRequest, nil, 0, nil, 0, 0, 0) then
    begin
      SetLastErrorFrom('WinHttpSendRequest (proxy auth retry)');
      Exit;
    end;

    if not WinHttpReceiveResponse(hRequest, nil) then
    begin
      SetLastErrorFrom('WinHttpReceiveResponse (proxy auth retry)');
      Exit;
    end;

    StatusCode := QueryStatusCode(hRequest);
  end;

  Result := True;
end;

procedure TSymSrv.SetLastErrorFrom(const Context: string);
begin
  FLastErrorCode := GetLastError;
  FLastError := Format('%s: %s', [Context, WinHttpErrorMessage(FLastErrorCode)]);
end;

procedure TSymSrv.SetLastErrorMsg(const Msg: string);
begin
  FLastErrorCode := 0;
  FLastError := Msg;
end;

procedure TSymSrv.SetProxyCredentials(hRequest: HINTERNET; Scheme: DWORD);
begin
  if Scheme = 0 then Exit;
  if not WinHttpSetCredentials(hRequest, WINHTTP_AUTH_TARGET_PROXY, Scheme,
    PChar(FProxySettings.Login), PChar(FProxySettings.Password), nil) then
    SetLastErrorFrom('WinHttpSetCredentials');
end;

procedure TSymSrv.SetProxySettings(const Value: TProxySettings);
begin
  ValidateProxy(Value);
  FProxySettings := Value;
end;

function TSymSrv.WinHttpErrorMessage(ErrorCode: DWORD): string;
var
  Buf: PChar;
  Len: DWORD;
  hWinHttp: HMODULE;
begin
  Result := '';
  Buf := nil;

  Len := FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER or FORMAT_MESSAGE_FROM_SYSTEM or
    FORMAT_MESSAGE_IGNORE_INSERTS, nil, ErrorCode, 0, @Buf, 0, nil);

  if (Len = 0) or (ErrorCode >= 12000) and (ErrorCode <= 12999) then
  begin
    if Buf <> nil then
      LocalFree(HLOCAL(Buf));
    Buf := nil;
    hWinHttp := GetModuleHandle('winhttp.dll');
    if hWinHttp <> 0 then
      Len := FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER or FORMAT_MESSAGE_FROM_HMODULE or
        FORMAT_MESSAGE_IGNORE_INSERTS, Pointer(hWinHttp), ErrorCode, 0, @Buf, 0, nil);
  end;

  if (Len > 0) and (Buf <> nil) then
    Result := Trim(string(Buf))
  else
    Result := Format('WinHTTP error 0x%x (%d)', [ErrorCode, ErrorCode]);

  if Buf <> nil then
    LocalFree(HLOCAL(Buf));
end;

{ TAsyncSymSrv }

procedure TAsyncSymSrv.Execute;
begin
  TThread.NameThreadForDebugging('TAsyncSymSrv');
  FSymSrv := TSymSrv.Create;
  try
    FSymSrv.ProxySettings := ProxySettings;
    FSymSrv.OnProgress := InternalProgress;

    // this applies only to pdmAsyncManual mode
    // (it might be useful to someone, but that's not certain)

    // [ru] это только для режима pdmAsyncManual
    // (кому-то пригодится, но это не точно)

    if not FSymSrv.DownloadPdb(Pdb) then
    begin
      FLastError := FSymSrv.LastError;
      FLastErrorCode := FSymSrv.LastErrorCode;
      FLastHttpStatus := FSymSrv.LastHttpStatus;
    end;
    FState := FSymSrv.DownloadState;
  finally
    FSymSrv.Free;
  end;
end;

procedure TAsyncSymSrv.InternalProgress(Sender: TObject;
  State: TSymSrvProgressState; Pdb: TPdb; BytesReceived, TotalBytes: Int64;
  var AContinueState: TSymSrvContinueState);
begin
  FBytesReceived := BytesReceived;
  FState := State;
  FTotalBytes := TotalBytes;
  Synchronize(NotifyProgress);
  AContinueState := FContinueState;
end;

procedure TAsyncSymSrv.NotifyProgress;
begin
  if Assigned(FOnProgress) then
    FOnProgress(FSymSrv, FState, Pdb, FBytesReceived, FTotalBytes, FContinueState);
end;

{ TPdbKeyComparer }

function TPdbKeyComparer.Equals(const Left, Right: TPdbKey): Boolean;
begin
  Result := IsPdbKeyEqual(Left, Right);
end;

function TPdbKeyComparer.GetHashCode(const Value: TPdbKey): Integer;
begin
  Result := THashBobJenkins.GetHashValue(Value.Name[1], Length(Value.Name) * SizeOf(Char), 0);
  Result := THashBobJenkins.GetHashValue(Value.Uid, SizeOf(TGUID), Result);
  Result := THashBobJenkins.GetHashValue(Value.Age, SizeOf(DWORD), Result);
end;

{ TPdbStorage }

function TPdbStorage.CheckRelativeKeyName(const Value: string): Boolean;
begin
  Result := (Pos('/', Value) = 0) and (Pos('\', Value) = 0);
end;

procedure TPdbStorage.Clear;
begin
  FPdbDict.Clear;
  FPdbList.Clear;
end;

constructor TPdbStorage.Create;
const
//  DefaultSymPath = 'd:\sym;srv*https://msdl.microsoft.com/download/symbols;C:\MyProject\pdb;cache*C:\Symbols*E:\sym;cache*D:\Symbols';
  DefaultSymPath = 'srv*c:\symbols*https://msdl.microsoft.com/download/symbols';
var
  Comparer: IEqualityComparer<TPdbKey>;
  SymPath: string;
begin
  FDefaultTwoTierStorage := True;
  FCacheFolders := TStringList.Create;
  FLock := TCriticalSection.Create;
  FPdbList := TObjectList<TPdb>.Create;
  Comparer := TPdbKeyComparer.Create;
  FPdbDict := TDictionary<TPdbKey, Integer>.Create(Comparer);
  FSymServers := TStringList.Create;
  SymPath := GetEnvironmentVariable('_NT_SYMBOL_PATH');
  if SymPath = '' then
    SymPath := DefaultSymPath;
  SetSymConfig(SymPath);
end;

destructor TPdbStorage.Destroy;
begin
  FCacheFolders.Free;
  FLock.Free;
  FSymServers.Free;
  FPdbList.Free;
  FPdbDict.Free;
  inherited;
end;

function TPdbStorage.DownloadPDB(Pdb: TPdb; SyncMode: TPdbDownloadMode): TAsyncSymSrv;
var
  SyncSymSrv: TSymSrv;
  AsyncSymSrv: TAsyncSymSrv;
begin
  Result := nil;
  if Pdb.State <> psAvailableForLoading then
    raise EPdbException.Create('The parameters for downloading the PDB file have not been specified.');
  if SyncMode = pdmSync then
  begin
    SyncSymSrv := TSymSrv.Create;
    try
      SyncSymSrv.ProxySettings := ProxySettings;
      SyncSymSrv.OnProgress := OnProgress;
      if not SyncSymSrv.DownloadPdb(Pdb) then
      begin
        Pdb.UpdateState(psAvailableForLoading);
        raise EPdbException.CreateFmt(
          'Error downloading a PDB file (HTTP %d, code %d): %s',
          [SyncSymSrv.LastHttpStatus, SyncSymSrv.LastErrorCode, SyncSymSrv.LastError]);
      end;
    finally
      SyncSymSrv.Free;
    end;
  end
  else
  begin
    AsyncSymSrv := TAsyncSymSrv.Create(True);
    AsyncSymSrv.Pdb := Pdb;
    AsyncSymSrv.ProxySettings := ProxySettings;
    AsyncSymSrv.OnProgress := OnProgress;
    case SyncMode of
      pdmAsyncAuto:
      begin
        AsyncSymSrv.FreeOnTerminate := True;
        AsyncSymSrv.Start;
      end;
      pdmAsyncModal: RunThreadModal(AsyncSymSrv);
      pdmAsyncManual: Result := AsyncSymSrv;
    end;
  end;
end;

function TPdbStorage.FindLocalPdb(const APdbKey: TPdbKey): string;
var
  I: Integer;
  RelativePath, LocalPath: string;
begin
  // Let's try the direct path on the disk
  // [ru] Пробуем прямой путь на диске

  if not CheckRelativeKeyName(APdbKey.Name) then
  begin
    if FileExists(APdbKey.Name) then
      Exit(APdbKey.Name)
    else
      Exit('');
  end;

  if FCacheFolders.Count = 0 then
    EPdbException.Create('The symbols server configuration has not been specified');

  RelativePath := GetRelativePath(APdbKey);

  // We're going through the local caches
  // [ru] перебираем локальные хэши

  for I := 0 to FCacheFolders.Count - 1 do
  begin
    if not DirectoryExists(FCacheFolders[I]) then Continue;

    // Testing for a two-level character storage system
    // [ru] Проверка на двухуровневое хранилище символов

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-store-folder-tree

    LocalPath := FixUpPath(FCacheFolders[I], RelativePath, False);

    if FileExists(LocalPath) then
      Exit(LocalPath);
  end;
end;

function TPdbStorage.FixUpPath(const Folder, PdbPath: string;
  CreateNew: Boolean): string;
begin
  if CreateNew and not DirectoryExists(Folder) then
  begin
    ForceDirectories(Folder);
    if DefaultTwoTierStorage then
      TFileStream.Create(Folder + TwoTierFileName, fmCreate).Free
    else
      TFileStream.Create(Folder + OneTierFileName, fmCreate).Free;
  end;
  if FileExists(Folder + TwoTierFileName) then
    Result := Folder + Copy(ExtractFileName(PdbPath), 1, 2) + '/' + PdbPath
  else
    Result := Folder + PdbPath;
  Result := StringReplace(Result, '/', '\', [rfReplaceAll]);
end;

function TPdbStorage.GetRelativePath(const APdbKey: TPdbKey): string;
begin
  if CheckRelativeKeyName(APdbKey.Name) then
    Result := Format('%s/%.8x%.4x%.4x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%d/%s',
      [APdbKey.Name, APdbKey.Uid.D1, APdbKey.Uid.D2, APdbKey.Uid.D3,
       APdbKey.Uid.D4[0], APdbKey.Uid.D4[1], APdbKey.Uid.D4[2],
       APdbKey.Uid.D4[3], APdbKey.Uid.D4[4], APdbKey.Uid.D4[5],
       APdbKey.Uid.D4[6], APdbKey.Uid.D4[7], APdbKey.Age, APdbKey.Name])
  else
    Result := '';
end;

function TPdbStorage.GetSymSrvIndex(Value: Pointer): Integer;
begin
  Result := Integer(Value) and $3FFFFFFF;
end;

function TPdbStorage.GetSymSrvStorageType(Value: Pointer): TSymStorageType;
begin
  Result := TSymStorageType(Integer(Value) shr 30);
end;

function TPdbStorage.MakeSymSrvData(StorageType: TSymStorageType;
  Index: Integer): Pointer;
begin
  Result := Pointer(Integer(StorageType) shl 30 + Index);
end;

function TPdbStorage.QueryPDB(const APdbKey: TPdbKey): TPdb;
var
  Idx: Integer;
  LocalPath: string;
begin
  if FPdbDict.TryGetValue(APdbKey, Idx) then
    Result := FPdbList[Idx]
  else
  begin
    Result := TPdb.Create(APdbKey);
    Idx := FPdbList.Add(Result);
    FPdbDict.Add(APdbKey, Idx);
    Result.RelativePath := GetRelativePath(APdbKey);
    LocalPath := FindLocalPdb(APdbKey);
    if FileExists(LocalPath) then
    begin
      try
        Result.LoadFromFile(LocalPath);

        // verify that the PDB matches the specified parameters?
        // [ru] проверка, точно ли PDB соответствует указаным параметрам?

        if Result.State in [psNoSections, psReady] then
        begin
          if (APdbKey.Age <> Result.Age) or not IsEqualGUID(APdbKey.Uid, Result.UnicalId) then
            Result.UpdateState(psBroken)
          else
            Exit;
        end;
      except
        Result.UpdateState(psBroken);
      end;
    end;
  end;
end;

function TPdbStorage.QueryPDB(const Uid: TGUID; Age: DWORD;
  const PdbFileName: string): TPdb;
var
  APdbKey: TPdbKey;
begin
  APdbKey.Uid := Uid;
  APdbKey.Age := Age;
  APdbKey.Name := PdbFileName;
  Result := QueryPDB(APdbKey);
end;

function TPdbStorage.QueryRemotePDB(Pdb: TPdb): TPdbState;
var
  SymSrv: TSymSrv;
  StorageType: TSymStorageType;
  LocalPath, RemotePath: string;
  I, A: Integer;
begin

  // Guard against a programmer error if the symbols are ALREADY available —
  // no need to query the symbol servers

  // [ru] Страхуемся от ошибки программиста, если символы УЖЕ доступны
  // незачем опрашивать серверы символов

  if Pdb.State in [psNoSections, psReady] then
    Exit(Pdb.State)
  else
    Result := psNotFoundAnywhere;

  if Pdb.RelativePath = '' then
  begin
    Pdb.UpdateState(Result);
    Exit;
  end;

  try
    SymSrv := TSymSrv.Create;
    try
      SymSrv.ProxySettings := ProxySettings;
      for I := 0 to FSymServers.Count - 1 do
      begin

        // The two-tier storage check is now at the character server
        // [ru] Проверка на двухуровневое хранилище теперь у сервера символов

        FLock.Enter;
        try
          StorageType := GetSymSrvStorageType(FSymServers.Objects[I]);
          if StorageType = sstUnknown then
          begin
            A := GetSymSrvIndex(FSymServers.Objects[I]);
            if SymSrv.CheckTwoTierStorage(FSymServers[I]) then
              StorageType := sstTwoTiear
            else
              StorageType := sstOneTier;
            FSymServers.Objects[I] := MakeSymSrvData(StorageType, A);
          end;
        finally
          FLock.Leave;
        end;

        if StorageType = sstTwoTiear then
          RemotePath := FSymServers[I] + Copy(Pdb.PdbName, 1, 2) + '/' + Pdb.RelativePath
        else
          RemotePath := FSymServers[I] + Pdb.RelativePath;

        if not SymSrv.CheckRemoteFilePresent(RemotePath) then
          Continue;

        // Now we need to determine the location of the character cache
        // where the download will take place

        // [ru] Теперь нужно определить расположение кэша символов
        // в который будет происходить скачивание

        for A := 0 to FCacheFolders.Count - 1 do
          if Integer(FCacheFolders.Objects[A]) = GetSymSrvIndex(FSymServers.Objects[I]) then
          begin

            // ... and again, don't forget the check for the two-tier storage
            // [ru] ... и опять не забыть проверку на двухуровневое хранилище

            LocalPath := FixUpPath(FCacheFolders[A], Pdb.RelativePath, True);
            Break;
          end;

        Pdb.RemotePath := RemotePath;
        Pdb.SetLocalPath(LocalPath);
        Result := psAvailableForLoading;
        Break;
      end;
    finally
      SymSrv.Free;
    end;
  except
    Result := psNotFoundAnywhere;
  end;

  Pdb.UpdateState(Result);
end;

procedure TPdbStorage.RunThreadModal(AThread: TThread);
var
  AHandle: THandle;
  WaitResult: DWORD;
  Msg: TMsg;
begin
  AThread.FreeOnTerminate := False;
  AThread.Start;
  try
    AHandle := AThread.Handle;
    repeat
      WaitResult := MsgWaitForMultipleObjects(1, AHandle, False, INFINITE, QS_ALLINPUT);
      if WaitResult = WAIT_OBJECT_0 + 1 then
      begin
        CheckSynchronize;
        while PeekMessage(Msg, 0, 0, 0, PM_REMOVE) do
        begin
          TranslateMessage(Msg);
          DispatchMessage(Msg);
        end;
      end;
    until WaitResult = WAIT_OBJECT_0;
  finally
    AThread.Free;
  end;
end;

procedure TPdbStorage.SetProxySettings(const Value: TProxySettings);
begin
  ValidateProxy(Value);
  FProxySettings := Value;
end;

procedure TPdbStorage.SetSymConfig(const Value: string);

  procedure InsertCacheFolder(Value: string; ALevel: Integer);
  var
    I: Integer;
  begin
    Value := IncludeTrailingPathDelimiter(Value);
    for I := 0 to FCacheFolders.Count - 1 do
      if Integer(FCacheFolders.Objects[I]) > ALevel then
      begin
        FCacheFolders.InsertObject(I, Value, Pointer(ALevel));
        Exit;
      end;
    FCacheFolders.AddObject(Value, Pointer(ALevel));
  end;

var
  Parts, SubParts: TArray<string>;
  I, A, WaitCacheIdx: Integer;
begin
  if FSymConfig <> Value then
  begin
    FSymConfig := Value;
    FSymServers.Clear;
    FCacheFolders.Clear;
    Parts := Value.Split([';']);
    WaitCacheIdx := -1;
    for I := 0 to Length(Parts) - 1 do
    begin

      // main configuration of the character download server
      // [ru] основная конфигурация сервера загрузок символов

      if Parts[I].StartsWith('SRV*', True) then
      begin
        SubParts := Parts[I].Split(['*']);
        WaitCacheIdx := I;
        for A := 1 to Length(SubParts) - 1 do
          if SubParts[A].StartsWith('HTTP', True) then
          begin
            if SubParts[A][Length(SubParts[A])] <> '/' then
              FSymServers.AddObject(SubParts[A] + '/', MakeSymSrvData(sstUnknown, I))
            else
              FSymServers.AddObject(SubParts[A], MakeSymSrvData(sstUnknown, I));
            Break;
          end
          else
          begin
            WaitCacheIdx := -1;
            InsertCacheFolder(SubParts[A], I);
          end;
        Continue;
      end;

      // cache is processed only for non-standard situations
      // when the SRV path to the left of the cache does not specify its own cache folder
      // all other cache types are ignored

      // [ru] кэш обрабатывается только для нестандартной ситуации
      // когда у SRV слева от кэша не указана своя папка для кэша
      // все остальные типы кэша игнорируются

      if Parts[I].StartsWith('CACHE*', True) then
      begin
        if WaitCacheIdx >= 0 then
        begin
          SubParts := Parts[I].Split(['*']);
          for A := 1 to Length(SubParts) - 1 do
            InsertCacheFolder(SubParts[A], WaitCacheIdx);
          WaitCacheIdx := -1;
        end;
        Continue;
      end;

      // we don't care about the SYMSRV parameter
      // [ru] кастомная библиотека нас не интересует, у нас всё своё

      if Parts[I].StartsWith('SYMSRV*', True) then
        Continue;

      // we will consider this a folder
      // [ru] будем считать это папкой

      InsertCacheFolder(Parts[I], I);
    end;
  end;
end;

{ TSymWorkerThread }

constructor TSymWorkerThread.Create(AOwner: TSymQueue);
begin
  inherited Create(True);
  FOwner := AOwner;
  FreeOnTerminate := False;
end;

procedure TSymWorkerThread.Execute;
var
  Job: TSymJob;
begin
  TThread.NameThreadForDebugging('TSymWorkerThread');
  while not Terminated do
  begin
    if FOwner.GetNextJob(Job) then
      FOwner.RunJob(Job)
    else
      Break;
  end;
end;

{ TSymJobQueue }

constructor TSymJobQueue.Create;
begin
  inherited Create;
  FItems := TQueue<TSymJob>.Create;
  FLock := TCriticalSection.Create;
  FEvent := TEvent.Create(nil, True, False, '');
  FContinueState := scsRun;
end;

destructor TSymJobQueue.Destroy;
begin
  FEvent.Free;
  FLock.Free;
  FItems.Free;
  inherited;
end;

procedure TSymJobQueue.Pause;
begin
  FContinueState := scsPause;
end;

function TSymJobQueue.Pop(out Job: TSymJob): Boolean;
begin
  while True do
  begin
    FLock.Enter;
    try
      case FContinueState of
        scsRun:
        begin
          if FItems.Count > 0 then
          begin
            Job := FItems.Dequeue;
            if FItems.Count = 0 then
              FEvent.ResetEvent;
            Exit(True);
          end;
        end;
        scsPause: FEvent.ResetEvent;
        scsCancel: Exit(False);
      end;
    finally
      FLock.Leave;
    end;
    FEvent.WaitFor(INFINITE);
  end;
end;

procedure TSymJobQueue.Push(const Job: TSymJob);
begin
  FLock.Enter;
  try
    FItems.Enqueue(Job);
  finally
    FLock.Leave;
  end;
  FEvent.SetEvent;
end;

procedure TSymJobQueue.Resume;
begin
  FLock.Enter;
  try
    FContinueState := scsRun;
  finally
    FLock.Leave;
  end;
  FEvent.SetEvent;
end;

procedure TSymJobQueue.Stop;
begin
  FLock.Enter;
  try
    FContinueState := scsCancel;
  finally
    FLock.Leave;
  end;
  FEvent.SetEvent;
end;

{ TSymQueue }

constructor TSymQueue.Create(AStorage: TPdbStorage; AWorkerCount: Integer);
var
  I: Integer;
begin
  inherited Create;
  FStorage := AStorage;
  FStorage.OnProgress := HandleProgress;
  FJobs := TSymJobQueue.Create;
  FActiveWorkers := AWorkerCount;
  SetLength(FWorkers, AWorkerCount);
  for I := 0 to AWorkerCount - 1 do
  begin
    FWorkers[I] := TSymWorkerThread.Create(Self);
    FWorkers[I].FreeOnTerminate := True;
    FWorkers[I].OnTerminate := WorkerTerminated;
  end;
  for I := 0 to AWorkerCount - 1 do
    FWorkers[I].Start;
end;

destructor TSymQueue.Destroy;
var
  Worker: TSymWorkerThread;
begin
  if not FStopped then
  begin
    for Worker in FWorkers do
      Worker.OnTerminate := nil;
    Stop;
  end;
  FJobs.Free;
  inherited;
end;

procedure TSymQueue.DownloadPdb(Pdb: TPdb);
var
  Job: TSymJob;
begin
  Job.Pdb := Pdb;
  Job.Kind := jkDownload;
  TInterlocked.Increment(FTotal);
  FJobs.Push(Job);
end;

function TSymQueue.GetNextJob(out Job: TSymJob): Boolean;
begin
  Result := FJobs.Pop(Job);
end;

procedure TSymQueue.HandleProgress(Sender: TObject;
  State: TSymSrvProgressState; Pdb: TPdb; BytesReceived, TotalBytes: Int64;
  var AContinueState: TSymSrvContinueState);
begin
  AContinueState := FContinueState;
  if Assigned(FOnProgress) then
    TThread.Queue(nil, procedure
    begin
      FOnProgress(Self, State, Pdb, BytesReceived, TotalBytes);
    end);
end;

procedure TSymQueue.NotifyJobDone(const Job: TSymJob;
  const Error: string);
var
  Done: Integer;
begin
  Done := TInterlocked.Increment(FDone);
  TThread.Queue(nil, procedure
  begin
    if Assigned(FOnJobDone) then
      FOnJobDone(Self, Job, Error);
    if (Done >= FTotal) and Assigned(FOnBatchDone) then
      FOnBatchDone(Self);
  end);
end;

procedure TSymQueue.Pause;
begin
  if FStopped then Exit;
  FContinueState := scsPause;
  FJobs.Pause;
end;

procedure TSymQueue.QueryPdb(Pdb: TPdb);
var
  Job: TSymJob;
begin
  Job.Pdb := Pdb;
  Job.Kind := jkQuery;
  TInterlocked.Increment(FTotal);
  FJobs.Push(Job);
end;

procedure TSymQueue.Resume;
begin
  if FStopped then Exit;
  FContinueState := scsRun;
  FJobs.Resume;
end;

procedure TSymQueue.RunJob(const Job: TSymJob);
var
  Error: string;
begin
  Error := '';
  try
    case Job.Kind of
      jkQuery:
        FStorage.QueryRemotePDB(Job.Pdb);
      jkDownload:
        FStorage.DownloadPDB(Job.Pdb, pdmSync);
    end;
  except
    on E: Exception do
      Error := E.ClassName + ': ' + E.Message;
  end;
  NotifyJobDone(Job, Error);
end;

procedure TSymQueue.Stop;
begin
  if FStopped then Exit;
  FStopped := True;
  FContinueState := scsCancel;
  FJobs.Stop;
end;

procedure TSymQueue.WorkerTerminated(Sender: TObject);
begin
  if TInterlocked.Decrement(FActiveWorkers) = 0 then
    if Assigned(FOnStopped) then
      FOnStopped(Self);
end;

end.
