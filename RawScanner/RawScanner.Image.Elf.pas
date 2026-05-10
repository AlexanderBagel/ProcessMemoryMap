////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Image.Elf.pas
//  * Purpose   : Классы получающие данные о состоянии ELF файлов в процессе
//  *           : рассчитанные на основе образов файлов с диска.
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

unit RawScanner.Image.Elf;

interface

  {$I rawscanner.inc}

uses
  {$IFNDEF FPC}
  Windows,
  {$ENDIF}
  Classes,
  SysUtils,
  Math,
  Generics.Collections,
  RawScanner.AbstractImage,
  RawScanner.Types,
  RawScanner.Elf,
  RawScanner.CoffDwarf;

type
  TElfSectionHeader = record
    DisplayName: string;
    Hdr: Elf64_Shdr;
  end;

  TImageSymbolType = (istUnknown, istImport, istExport, istDebug);

  TImageSymbol = record
    DisplayName: string;
    Executable: Boolean;
    Hdr: Elf64_Sym;
    SymbolType: TImageSymbolType;
    case TImageSymbolType of
      istImport: (
        GotAddrVA: Int64;
        GotIdx: Integer;
      );
      istExport: (
        Hash: UInt32;
        HashIdx: Integer;
      );
  end;

  TRawElfImage = class;

  TElfImageGate = class(TAbstractImageGate)
  private
    FImage: TRawElfImage;
    FImageReplaced: Boolean;
    procedure ClearReplaced;
    function GetSectionParams(const ASection: TElfSectionHeader): TSectionParams;
  protected
    procedure ReplaceImage(ANewImage: TRawElfImage);
  public
    constructor Create(AImage: TRawElfImage);
    destructor Destroy; override;
    function IsObjectFile: Boolean; override;
    function GetIs64Image: Boolean; override;
    function NumberOfSymbols: Integer; override;
    function SectionAtIndex(AIndex: Integer; out ASection: TSectionParams): Boolean; override;
    function SectionAtName(const AName: string; out ASection: TSectionParams): Boolean; override;
    function PointerToSymbolTable: ULONG_PTR64; override;
    function RawToVa(RawAddr: DWORD): ULONG_PTR64; override;
    function Rebase(Value: ULONG_PTR64): ULONG_PTR64; override;
    function RvaToRaw(RvaAddr: DWORD): DWORD; override;
    function RvaToVa(RvaAddr: DWORD): ULONG_PTR64; override;
    function VaToRaw(VaAddr: ULONG_PTR64): DWORD; override;
    function VaToRva(VaAddr: ULONG_PTR64): DWORD; override;
  end;

  THashReader = class
  strict private
    FOwner: TRawElfImage;
    FBucketCount, FChainCount: Integer;
    FBuckets: array of UInt32;
    FChains: array of UInt32;
  public
    constructor Create(AOwner: TRawElfImage);
    function CheckSymbolExportIndex(var Symbol: TImageSymbol; Idx: Integer): Boolean;
    function LoadGnuHash(Raw: TMemoryStream): Boolean;
  end;

  TGnuHashReader = class
  strict private
    FOwner: TRawElfImage;
    FBloomFilter: array of UInt64;
    FBuckets: array of UInt32;
    FHeader: TGnuHashHeader;
    FHashValues: array of UInt32;
  public
    constructor Create(AOwner: TRawElfImage);
    function CheckSymbolExportIndex(var Symbol: TImageSymbol): Boolean;
    function LoadGnuHash(Raw: TMemoryStream): Boolean;
  end;

  TRawElfImage = class(TAbstractImage)
  strict private
    FDebugData: TDebugInfoTypes;
    FDebugLinkPath: string;
    FDwarfDebugInfo: TDwarfDebugInfo;
    FDynSymbolsCount: Integer;
    FHashReader: THashReader;
    FGnuHashReader: TGnuHashReader;
    FHeader: Elf64_Ehdr;
    FHeaderSize: DWORD;
    FHeaderPresent: Boolean;
    FImageBase, FLoadedImageBase, FEntryPoint: ULONG_PTR64;
    FImageGate: TElfImageGate;
    FImageLoadType: TImageLoadType;
    FImagePath, FImageName: string;
    FImportLibs: TStringList;
    FIndex: Integer;
    FProgramHeaders: array of Elf64_Phdr;
    FSections: array of TElfSectionHeader;
    FSectionsPresent: Boolean;
    FSizeOfFileImage: Int64;
    FSymbols: TList<TImageSymbol>;
    FValidImage: Boolean;
    function GetGnuDebugLink(Raw: TStream): string;
    procedure LoadFromImage;
    procedure LoadDwarf(Raw: TStream);
    function LoadHeader(Raw: TStream): Boolean;
    function LoadProgramHeaders(Raw: TStream): Boolean;
    function LoadSections(Raw: TMemoryStream): Boolean;
    function LoadDynSection(Raw: TMemoryStream): Boolean;
    function LoadSymbols(Raw: TMemoryStream): Boolean;
  public
    constructor Create(const ImagePath: string; AImageLoadType: TImageLoadType;
      ImageBase: ULONG_PTR64 = 0); overload;
    constructor Create(const ModuleData: TModuleData; AModuleIndex: Integer); overload;
    destructor Destroy; override;

    function DebugData: TDebugInfoTypes; override;
    function DebugLinkPath: string; override;
    function DwarfDebugInfo: TDwarfDebugInfo; override;
    function GetSectionData(RvaAddr: DWORD; var Data: TSectionData): Boolean; override;
    function Image64: Boolean; override;
    function ImageBase: ULONG_PTR64; override;

    function RawToVa(RawAddr: DWORD): ULONG_PTR64; override;
    function RvaToRaw(RvaAddr: DWORD): DWORD; override;
    function RvaToVa(RvaAddr: DWORD): ULONG_PTR64; override;
    function VaToRaw(AddrVA: ULONG_PTR64): DWORD; override;
    function VaToRva(VaAddr: ULONG_PTR64): DWORD; override;
    function ValidImage: Boolean; override;

    function ProgramHeadersCount: Integer;
    function ProgramHeaderAtAddrVA(AddrVA: Int64; out AHeader: Elf64_Phdr): Integer;
    function ProgramHeaderAtIndex(AIndex: Integer; out AHeader: Elf64_Phdr): Boolean;
    function ProgramHeaderByType(AType: UInt32; out AHeader: Elf64_Phdr): Boolean;

    function SectionCount: Integer;
    function SectionAtIndex(AIndex: Integer; out Section: TElfSectionHeader): Boolean;
    function SectionAtName(const AName: string; out AIndex: Integer): Boolean;
    function SectionByType(AType: UInt32; out Section: TElfSectionHeader): Boolean;

    property DynSymbolsCount: Integer read FDynSymbolsCount;
    property EntryPoint: ULONG_PTR64 read FEntryPoint;
    property Header: Elf64_Ehdr read FHeader;
    property HeaderPresent: Boolean read FHeaderPresent;
    property ImageBaseInHeaders: ULONG_PTR64 read FLoadedImageBase;
    property ImageName: string read FImageName;
    property ImagePath: string read FImagePath;
    property ImportLibs: TStringList read FImportLibs;
    property ModuleIndex: Integer read FIndex;
    property SectionsPresent: Boolean read FSectionsPresent;
    property Symbols: TList<TImageSymbol> read FSymbols;
  end;

implementation

{$IFNDEF DISABLE_LOGGER}
uses
  RawScanner.Logger;
{$ENDIF}

const
  PtrSize: array [Boolean] of Integer = (4, 8);

procedure Error(const Description: string);
begin
  {$IFNDEF DISABLE_LOGGER}
  RawScannerLogger.Error(llPE, Description);
  {$ENDIF}
end;

procedure Notify(const FuncName, Description: string);
begin
  {$IFNDEF DISABLE_LOGGER}
  RawScannerLogger.Notify(llPE, FuncName, Description);
  {$ENDIF}
end;

{ TElfImageGate }

procedure TElfImageGate.ClearReplaced;
begin
  if FImageReplaced then
  begin
    FImageReplaced := False;
    FImage.Free;
  end;
end;

constructor TElfImageGate.Create(AImage: TRawElfImage);
begin
  FImage := AImage;
  ModuleIndex := AImage.ModuleIndex;
end;

destructor TElfImageGate.Destroy;
begin
  ClearReplaced;
  inherited;
end;

function TElfImageGate.GetIs64Image: Boolean;
begin
  Result := FImage.Image64;
end;

function TElfImageGate.GetSectionParams(
  const ASection: TElfSectionHeader): TSectionParams;
begin
  Result.AddressVA := ASection.Hdr.sh_addr;
  Result.AddressRaw := ASection.Hdr.sh_offset;
  Result.SizeOfRawData := ASection.Hdr.sh_size;
  Result.DisplayName := ASection.DisplayName;
  Result.IsExecutable :=
    (ASection.Hdr.sh_flags and SHF_ALLOC <> 0) and
    (ASection.Hdr.sh_flags and SHF_EXECINSTR <> 0);
end;

function TElfImageGate.IsObjectFile: Boolean;
begin
  Result := not FImage.HeaderPresent;
end;

function TElfImageGate.NumberOfSymbols: Integer;
begin
  Result := 0;
end;

function TElfImageGate.PointerToSymbolTable: ULONG_PTR64;
begin
  Result := 0;
end;

function TElfImageGate.RawToVa(RawAddr: DWORD): ULONG_PTR64;
begin
  Result := FImage.RawToVa(RawAddr);
end;

function TElfImageGate.Rebase(Value: ULONG_PTR64): ULONG_PTR64;
begin
  if FImage.ImageBase <> FImage.ImageBaseInHeaders then
    Result := Value - FImage.ImageBaseInHeaders + FImage.ImageBase
  else
    Result := Value;
end;

procedure TElfImageGate.ReplaceImage(ANewImage: TRawElfImage);
begin
  ClearReplaced;
  FImage := ANewImage;
  FImageReplaced := True;
end;

function TElfImageGate.RvaToRaw(RvaAddr: DWORD): DWORD;
begin
  Result := FImage.RvaToRaw(RvaAddr);
end;

function TElfImageGate.RvaToVa(RvaAddr: DWORD): ULONG_PTR64;
begin
  Result := FImage.RvaToVa(RvaAddr);
end;

function TElfImageGate.SectionAtIndex(AIndex: Integer;
  out ASection: TSectionParams): Boolean;
var
  Section: TElfSectionHeader;
begin
  Result := FImage.SectionAtIndex(AIndex, Section);
  if Result then
    ASection := GetSectionParams(Section);
end;

function TElfImageGate.SectionAtName(const AName: string;
  out ASection: TSectionParams): Boolean;
var
  AIndex: Integer;
  Section: TElfSectionHeader;
begin
  Result := FImage.SectionAtName(AName, AIndex);
  if Result then
  begin
    FImage.SectionAtIndex(AIndex, Section);
    ASection := GetSectionParams(Section);
  end;
end;

function TElfImageGate.VaToRaw(VaAddr: ULONG_PTR64): DWORD;
begin
  Result := FImage.VaToRaw(VaAddr);
end;

function TElfImageGate.VaToRva(VaAddr: ULONG_PTR64): DWORD;
begin
  Result := FImage.VaToRva(VaAddr);
end;

{ THashReader }

function THashReader.CheckSymbolExportIndex(var Symbol: TImageSymbol; Idx: Integer): Boolean;
var
  Index: Integer;
begin
  Result := False;
  if FBucketCount = 0 then Exit;
  Symbol.Hash := CalculateElfHash(AnsiString(Symbol.DisplayName));
  Index := FBuckets[Int32(Symbol.Hash) mod FBucketCount];
  while Index <> STN_UNDEF do
  begin
    if Index = Idx then
    begin
      Symbol.HashIdx := Idx;
      Result := True;
      Exit;
    end;
    if Index >= FChainCount then
      Break;
    Index := FChains[Index];
  end;
  Symbol.Hash := 0;
end;

constructor THashReader.Create(AOwner: TRawElfImage);
begin
  FOwner := AOwner;
end;

function THashReader.LoadGnuHash(Raw: TMemoryStream): Boolean;
var
  I: Integer;
  HashSection: TElfSectionHeader;
begin
  Result := FOwner.SectionAtName('.hash', I) and FOwner.SectionAtIndex(I, HashSection);
  if not Result then Exit;
  Raw.Position := HashSection.Hdr.sh_offset;
  Raw.ReadBuffer(FBucketCount, SizeOf(Integer));
  Raw.ReadBuffer(FChainCount, SizeOf(Integer));
  SetLength(FBuckets, FBucketCount);
  for I := 0 to FBucketCount - 1 do
    Raw.Read(FBuckets[I], SizeOf(UInt32));
  SetLength(FChains, FChainCount);
  for I := 0 to FChainCount - 1 do
    Raw.Read(FChains[I], SizeOf(UInt32));
end;

{ TGnuHashReader }

function TGnuHashReader.CheckSymbolExportIndex(
  var Symbol: TImageSymbol): Boolean;
var
  BucketIdx: UInt32;
  SymIdx: UInt32;
  BloomIdx: UInt32;
  BitMask: UInt64;
  HashIdx: Integer;
  WordSizeBits: Integer;
begin
  Result:= False;
  if (FHeader.nbuckets = 0) or (FHeader.maskwords = 0) then Exit;

  Symbol.Hash := CalculateGnuHash(AnsiString(Symbol.DisplayName));
  BucketIdx := Int32(Symbol.Hash) mod FHeader.nbuckets;

  // Индекс символа из корзины
  SymIdx := FBuckets[BucketIdx];
  if SymIdx = 0 then
  begin
    Symbol.Hash := 0;
    Exit;
  end;

  // Проверяем фильтр Блума
  WordSizeBits := PtrSize[FOwner.Image64] shl 3;
  BloomIdx := (Int32(Symbol.Hash) div WordSizeBits) mod FHeader.maskwords;
  BitMask := (UInt64(1) shl (Int32(Symbol.Hash) mod WordSizeBits)) or
    (UInt64(1) shl ((Int32(Symbol.Hash) shr FHeader.shift2) mod WordSizeBits));

  if (FBloomFilter[BloomIdx] and BitMask) <> BitMask then
  begin
    Symbol.Hash := 0;
    Exit;
  end;

  // Поиск в цепочке (нечетный хэш означает конец цепочки)
  Symbol.Hash := Symbol.Hash and not 1;
  for HashIdx := SymIdx - FHeader.symndx to Length(FHashValues) - 1 do
  begin
    if (FHashValues[HashIdx] and not 1 = Symbol.Hash) then
    begin
      Symbol.HashIdx := HashIdx + Int32(FHeader.symndx);
      Exit(True);
    end;

    // Конец цепочки
    if (FHashValues[HashIdx] and 1) <> 0 then
      Break;
  end;

  Symbol.Hash := 0;
end;

constructor TGnuHashReader.Create(AOwner: TRawElfImage);
begin
  FOwner := AOwner;
end;

function TGnuHashReader.LoadGnuHash(Raw: TMemoryStream): Boolean;
var
  I, ACount: Integer;
  HashSection: TElfSectionHeader;
begin
  Result := FOwner.SectionAtName('.gnu.hash', I) and FOwner.SectionAtIndex(I, HashSection);
  if not Result then Exit;
  Raw.Position := HashSection.Hdr.sh_offset;
  FHeader := Default(TGnuHashHeader);
  Raw.ReadBuffer(FHeader, SizeOf(FHeader));
  SetLength(FBloomFilter, FHeader.maskwords);
  for I := 0 to Length(FBloomFilter) - 1 do
    Raw.Read(FBloomFilter[I], PtrSize[FOwner.Image64]);
  SetLength(FBuckets, FHeader.nbuckets);
  for I := 0 to Length(FBuckets) - 1 do
    Raw.Read(FBuckets[I], SizeOf(UInt32));
  ACount := Int32(HashSection.Hdr.sh_size - (UInt64(Raw.Position) - HashSection.Hdr.sh_offset)) shr 2;
  SetLength(FHashValues, ACount);
  for I := 0 to Length(FHashValues) - 1 do
    Raw.Read(FHashValues[I], SizeOf(UInt32));
end;

{ TRawElfImage }

constructor TRawElfImage.Create(const ImagePath: string;
  AImageLoadType: TImageLoadType; ImageBase: ULONG_PTR64);
begin
  ProfilingBegin;
  FImagePath := ImagePath;
  FImageBase := ImageBase;
  FImageName := ExtractFileName(ImagePath);
  FImageLoadType := AImageLoadType;
  FSymbols := TList<TImageSymbol>.Create;
  FImageGate := TElfImageGate.Create(Self);
  FImportLibs := TStringList.Create;
  FDwarfDebugInfo := TDwarfDebugInfo.Create(FImageGate);
  FDwarfDebugInfo.AppendUnitName := DefaultDwarfAppendUnitName;
  FHashReader := THashReader.Create(Self);
  FGnuHashReader := TGnuHashReader.Create(Self);
  LoadFromImage;
  ProfilingEnd;
end;

constructor TRawElfImage.Create(const ModuleData: TModuleData;
  AModuleIndex: Integer);
begin
  FIndex := AModuleIndex;
  Create(ModuleData.ImagePath, iltFull, ModuleData.ImageBase);
end;

function TRawElfImage.DebugData: TDebugInfoTypes;
begin
  Result := FDebugData;
end;

function TRawElfImage.DebugLinkPath: string;
begin
  Result := FDebugLinkPath;
end;

destructor TRawElfImage.Destroy;
begin
  FHashReader.Free;
  FGnuHashReader.Free;
  FDwarfDebugInfo.Free;
  FImageGate.Free;
  FImportLibs.Free;
  FSymbols.Free;
  inherited;
end;

function TRawElfImage.DwarfDebugInfo: TDwarfDebugInfo;
begin
  Result := FDwarfDebugInfo;
end;

function TRawElfImage.GetGnuDebugLink(Raw: TStream): string;
var
  Index: Integer;
  DebugLink: AnsiString;
begin
  if SectionAtName('.gnu_debuglink', Index) then
  begin
    SetLength(DebugLink, FSections[Index].Hdr.sh_size);
    Raw.Position := FSections[Index].Hdr.sh_offset;
    Raw.ReadBuffer(DebugLink[1], FSections[Index].Hdr.sh_size);
    Result := ExtractFilePath(ImagePath) + string(PAnsiChar(@DebugLink[1]));
    if not FileExists(Result) then
      Result := '';
  end
  else
    Result := '';
end;

function TRawElfImage.GetSectionData(RvaAddr: DWORD;
  var Data: TSectionData): Boolean;
var
  I: Integer;
begin
  Result := False;
  Data := Default(TSectionData);
  if RvaAddr <= FHeaderSize then
    Exit;
  for I := 0 to Length(FSections) - 1 do
  begin
    if FSections[I].Hdr.sh_addr = 0 then
      Continue;
    if FSections[I].Hdr.sh_size = 0 then
      Continue;
    if FSections[I].Hdr.sh_offset = 0 then
      Continue;
    Data.StartRVA := AlignDown(FSections[I].Hdr.sh_addr, FSections[I].Hdr.sh_addralign);
    Data.Size := AlignUp(FSections[I].Hdr.sh_size, FSections[I].Hdr.sh_addralign);
    if (RvaAddr >= Data.StartRVA) and (RvaAddr < Data.StartRVA + Data.Size) then
    begin
      Data.Index := I;
      Data.Read := FSections[I].Hdr.sh_flags and SHF_ALLOC <> 0;
      Data.Write := FSections[I].Hdr.sh_flags and SHF_WRITE <> 0;
      Data.Execute := FSections[I].Hdr.sh_flags and SHF_EXECINSTR <> 0;
      Result := True;
      Break;
    end;
  end;
end;

function TRawElfImage.Image64: Boolean;
begin
  Result := ImageType = itELF64;
end;

function TRawElfImage.ImageBase: ULONG_PTR64;
begin
  Result := FImageBase;
end;

procedure TRawElfImage.LoadDwarf(Raw: TStream);
begin
  FDebugData := FDebugData + FDwarfDebugInfo.Load(Raw);
end;

procedure TRawElfImage.LoadFromImage;
var
  Raw: TMemoryStream;
  DebugLinkImage: TRawElfImage;
begin
  Raw := TMemoryStream.Create;
  try
    try
      Raw.LoadFromFile(FImagePath);
    except
      on E: Exception do
      begin
        Notify('Image load error ' + ImagePath, E.ClassName + ': ' + E.Message);
        Exit;
      end;
    end;
    FSizeOfFileImage := Raw.Size;

    if not LoadHeader(Raw) then Exit;
    FSectionsPresent := LoadSections(Raw);
    FHeaderPresent := LoadProgramHeaders(Raw);

    FValidImage := True;

    if FImageLoadType = iltSectionOnly then Exit;

    LoadDynSection(Raw);
    LoadSymbols(Raw);

    if FImageLoadType = iltWithoutDebug then Exit;

    // COFF + DWARF могут сидеть во внешнем отладочном файле
    // ссылка на который будет находится в секции .gnu_debuglink
    FDebugLinkPath := GetGnuDebugLink(Raw);
    if FDebugLinkPath <> '' then
    begin
      // если это так - то переопределяем гейт образа на вспомогательный,
      // откуда будем брать актуальные отладочные данные, причем грузить его
      // будем только до секций (второй параметр), остальное в принципе лишнее
      // (да и нет там больше ничего)
      DebugLinkImage := TRawElfImage.Create(FDebugLinkPath, iltSectionOnly, ImageBase);
      FImageGate.ReplaceImage(DebugLinkImage);
      Raw.LoadFromFile(FDebugLinkPath);
    end;

    LoadDwarf(Raw);
  finally
    Raw.Free;
  end;
end;

function TRawElfImage.LoadHeader(Raw: TStream): Boolean;
var
  TmpHeader: Elf32_Ehdr;
begin
  Result := False;
  Raw.ReadBuffer(FHeader.e_ident, EI_NIDENT);
  if FHeader.e_ident.e_magic <> ELF_MAGIC then
  begin
    Error(Format('File %s is not an ELF-format file', [ImagePath]));
    Exit;
  end;
  if not (FHeader.e_ident.e_class in [ELFCLASS32, ELFCLASS64]) then
  begin
    Error(Format('File %s is an unknown class (%d)', [ImagePath, FHeader.e_ident.e_class]));
    Exit;
  end;
  case FHeader.e_ident.e_class of
    ELFCLASS32: SetImageType(itELF32);
    ELFCLASS64: SetImageType(itELF64);
  else
    Exit;
  end;
  if Image64 then
  begin
    Raw.ReadBuffer(FHeader.e_type, SizeOf(FHeader) - EI_NIDENT);
    FHeaderSize := SizeOf(Elf64_Ehdr);
  end
  else
  begin
    Raw.ReadBuffer(TmpHeader.e_type, SizeOf(Elf32_Ehdr) - EI_NIDENT);
    FHeader.e_type := TmpHeader.e_type;
    FHeader.e_machine := TmpHeader.e_machine;
    FHeader.e_version := TmpHeader.e_version;
    FHeader.e_entry := TmpHeader.e_entry;
    FHeader.e_phoff := TmpHeader.e_phoff;
    FHeader.e_shoff := TmpHeader.e_shoff;
    FHeader.e_flags := TmpHeader.e_flags;
    FHeader.e_ehsize := TmpHeader.e_ehsize;
    FHeader.e_phentsize := TmpHeader.e_phentsize;
    FHeader.e_phnum := TmpHeader.e_phnum;
    FHeader.e_shentsize := TmpHeader.e_shentsize;
    FHeader.e_shnum := TmpHeader.e_shnum;
    FHeader.e_shstrndx := TmpHeader.e_shstrndx;
    FHeaderSize := SizeOf(Elf32_Ehdr);
  end;
  FEntryPoint := FHeader.e_entry;
  Result := True;
end;

function TRawElfImage.LoadDynSection(Raw: TMemoryStream): Boolean;
var
  SymSection, SymStrSection, RelaPltSection, ExecutableSection: TElfSectionHeader;
  Symbol: TImageSymbol;
  I, ACount: Integer;
  Hdr32: Elf32_Sym;
  Strings: PByte;
  Elf64Dyn: Elf64_Dyn;
  Elf32Dyn: Elf32_Dyn;
  ASectionsCount: Integer;
  LibName: string;
  IsValidExportFlags: Boolean;
  RelaPltDict: TDictionary<Integer, Elf64_Rela>;
  Elf64Rela: Elf64_Rela;
  Elf32Rela: Elf32_Rela;
begin
  Result := SectionByType(SHT_DYNAMIC, SymSection) and
    SectionAtIndex(SymSection.Hdr.sh_link, SymStrSection);
  if not Result then Exit;
  if Image64 then
    Result := SymSection.Hdr.sh_entsize = SizeOf(Elf64_Dyn)
  else
    Result := SymSection.Hdr.sh_entsize = SizeOf(Elf32_Dyn);
  if not Result then Exit;

  RelaPltDict := TDictionary<Integer, Elf64_Rela>.Create;
  try

    ACount := SymSection.Hdr.sh_size div SymSection.Hdr.sh_entsize;
    Raw.Position := SymSection.Hdr.sh_offset;
    Strings := PByte(Raw.Memory) + SymStrSection.Hdr.sh_offset;
    Elf64Dyn := Default(Elf64_Dyn);
    for I := 0 to ACount - 1 do
    begin
      if Image64 then
        Raw.ReadBuffer(Elf64Dyn, SizeOf(Elf64Dyn))
      else
      begin
        Raw.ReadBuffer(Elf32Dyn, SizeOf(Elf32Dyn));
        Elf64Dyn.d_tag := Elf32Dyn.d_tag;
        Elf32Dyn.d_ptr := Elf32Dyn.d_ptr;
      end;
      if Elf64Dyn.d_tag = DT_NEEDED then
      begin
        LibName := string(PAnsiChar(Strings + Elf64Dyn.d_ptr));
        if LibName <> '' then
          ImportLibs.Add(LibName);
      end;
    end;

    Result := SectionByType(SHT_DYNSYM, SymSection) and
      SectionAtIndex(SymSection.Hdr.sh_link, SymStrSection);
    if not Result then Exit;
    if Image64 then
      Result := SymSection.Hdr.sh_entsize = SizeOf(Elf64_Sym)
    else
      Result := SymSection.Hdr.sh_entsize = SizeOf(Elf32_Sym);
    if not Result then Exit;
    ACount := SymSection.Hdr.sh_size div SymSection.Hdr.sh_entsize;
    FSymbols.Count := ACount;
    if ACount = 0 then Exit;
    Strings := PByte(Raw.Memory) + SymStrSection.Hdr.sh_offset;
    Symbol := Default(TImageSymbol);
    ASectionsCount := Length(FSections);

    // зачитываем таблицу импортируемых символов
    if SectionAtName('.rela.plt', I) and SectionAtIndex(I, RelaPltSection) then
    begin
      Raw.Position := RelaPltSection.Hdr.sh_offset;
      Elf64Rela := Default(Elf64_Rela);
      for I := 0 to (RelaPltSection.Hdr.sh_size div RelaPltSection.Hdr.sh_entsize) - 1 do
      begin
        if Image64 then
          Raw.ReadBuffer(Elf64Rela, SizeOf(Elf64_Rela))
        else
        begin
          Raw.ReadBuffer(Elf32Rela, SizeOf(Elf32_Rela));
          Elf64Rela.r_offset := Elf32Rela.r_offset;
          Elf64Rela.r_info := ELF64_R_INFO(
            ELF32_R_SYM(Elf32Rela.r_info), ELF32_R_TYPE(Elf32Rela.r_info));
          Elf64Rela.r_addend := Elf32Rela.r_addend;
        end;
        Elf64Rela.r_addend := I;
        RelaPltDict.Add(ELF64_R_SYM(Elf64Rela.r_info), Elf64Rela);
      end;
    end;

    // зачитываем список хэшей экспортируемых функций
    FHashReader.LoadGnuHash(Raw);
    FGnuHashReader.LoadGnuHash(Raw);

    Raw.Position := SymSection.Hdr.sh_offset;
    for I := 0 to ACount - 1 do
    begin
      Symbol := Default(TImageSymbol);
      if Image64 then
        Raw.ReadBuffer(Symbol.Hdr, SizeOf(Elf64_Sym))
      else
      begin
        Raw.ReadBuffer(Hdr32, SizeOf(Hdr32));
        Symbol.Hdr.st_name := Hdr32.st_name;
        Symbol.Hdr.st_info := Hdr32.st_info;
        Symbol.Hdr.st_other := Hdr32.st_other;
        Symbol.Hdr.st_shndx := Hdr32.st_shndx;
        Symbol.Hdr.st_value := Hdr32.st_value;
        Symbol.Hdr.st_size := Hdr32.st_size;
      end;

      // игнорируем абсолютные и OS специфичные символы
      if Symbol.Hdr.st_shndx >= ASectionsCount then
        Continue;

      if (Symbol.Hdr.st_name > 0) and (Symbol.Hdr.st_name < SymStrSection.Hdr.sh_size) then
        Symbol.DisplayName := string(PAnsiChar(Strings + Symbol.Hdr.st_name))
      else
        Symbol.DisplayName := '';

      // Экспорт идентифицируется по следующим признакам:
      // 1. st_shndx != undef
      // 2. bind == STB_GLOBAL
      // 3. type == STT_OBJECT, STT_FUNC
      // 4. visiblity == STV_DEFAULT, STV_PROTECTED
      IsValidExportFlags :=
        (Symbol.Hdr.st_value > 0) and
        (ELF32_ST_TYPE(Symbol.Hdr.st_info) in [STT_OBJECT, STT_FUNC, STT_GNU_IFUNC]) and
        (ELF32_ST_BIND(Symbol.Hdr.st_info) in [STB_GLOBAL, STB_WEAK, STB_GNU_UNIQUE]) and
        (ELF32_ST_VISIBLITY(Symbol.Hdr.st_other) in [STV_DEFAULT, STV_PROTECTED]);

      Symbol.SymbolType := istUnknown;
      if RelaPltDict.TryGetValue(I, Elf64Rela) then
      begin
        if FSections[Symbol.Hdr.st_shndx].Hdr.sh_flags and SHF_ALLOC = 0 then
        begin
          Symbol.SymbolType := istImport;
          Symbol.GotAddrVA := Int64(Elf64Rela.r_offset);
          Symbol.GotIdx := Elf64Rela.r_addend;
        end;
      end;

      if (Symbol.SymbolType <> istImport) and IsValidExportFlags and
        (FGnuHashReader.CheckSymbolExportIndex(Symbol) or
        FHashReader.CheckSymbolExportIndex(Symbol, I)) then
        Symbol.SymbolType := istExport;

      Symbol.Executable :=
        SectionAtIndex(Symbol.Hdr.st_shndx, ExecutableSection) and
        ((ExecutableSection.Hdr.sh_flags and SHF_EXECINSTR) <> 0);

      FSymbols[I] := Symbol;
    end;
  finally
    RelaPltDict.Free;
  end;
end;

function TRawElfImage.LoadProgramHeaders(Raw: TStream): Boolean;
var
  ACount, Index: UInt32;
  Hdr32: Elf32_Phdr;
begin
  if Image64 then
    Result := FHeader.e_phentsize = SizeOf(Elf64_Phdr)
  else
    Result := FHeader.e_phentsize = SizeOf(Elf32_Phdr);
  if not Result then Exit;
  Result := FHeader.e_phnum > 0;
  if not Result then Exit;
  Raw.Position := FHeader.e_phoff;
  ACount := FHeader.e_phnum;
  if ACount = PN_XNUM then
  begin
    if FSectionsPresent then
      ACount := FSections[0].Hdr.sh_info
    else
      ACount := 0;
  end;
  if ACount = 0 then Exit(False);
  SetLength(FProgramHeaders, ACount);
  Index := 0;
  FLoadedImageBase := 0;
  while Index < ACount do
  begin
    if Image64 then
      Raw.ReadBuffer(FProgramHeaders[Index], FHeader.e_phentsize)
    else
    begin
      Raw.ReadBuffer(Hdr32, SizeOf(Hdr32));
      FProgramHeaders[Index].p_type := Hdr32.p_type;
      FProgramHeaders[Index].p_flags := Hdr32.p_flags;
      FProgramHeaders[Index].p_offset := Hdr32.p_offset;
      FProgramHeaders[Index].p_vaddr := Hdr32.p_vaddr;
      FProgramHeaders[Index].p_paddr := Hdr32.p_paddr;
      FProgramHeaders[Index].p_filesz := Hdr32.p_filesz;
      FProgramHeaders[Index].p_memsz := Hdr32.p_memsz;
      FProgramHeaders[Index].p_align := Hdr32.p_align;
    end;
    if FProgramHeaders[Index].p_type = PT_LOAD then
      if FLoadedImageBase = 0 then
        FLoadedImageBase := FProgramHeaders[Index].p_vaddr;

    Inc(Index);
  end;
  if FImageBase = 0 then
    FImageBase := FLoadedImageBase;
end;

function TRawElfImage.LoadSections(Raw: TMemoryStream): Boolean;
var
  I: Integer;
  ACount, Index: UInt32;
  StringsLen: UInt32;
  ACountInited: Boolean;
  Hdr32: Elf32_Shdr;
  Strings: PByte;
begin
  if Image64 then
    Result := FHeader.e_shentsize = SizeOf(Elf64_Shdr)
  else
    Result := FHeader.e_shentsize = SizeOf(Elf32_Shdr);
  if not Result then Exit;
  Result := FHeader.e_shnum > 0;
  if not Result then Exit;
  Raw.Position := FHeader.e_shoff;
  ACount := FHeader.e_shnum;
  ACountInited := ACount < SHN_LORESERVE;
  if ACountInited then
    SetLength(FSections, ACount)
  else
    SetLength(FSections, 1);
  Index := 0;
  while Index < ACount do
  begin
    if Image64 then
    begin
      Raw.ReadBuffer(FSections[Index].Hdr, FHeader.e_shentsize);
      if not ACountInited then
      begin
        ACountInited := True;
        ACount := FSections[Index].Hdr.sh_size;
        SetLength(FSections, ACount);
      end;
      Inc(Index);
    end
    else
    begin
      Raw.ReadBuffer(Hdr32, SizeOf(Hdr32));
      if not ACountInited then
      begin
        ACountInited := True;
        ACount := Hdr32.sh_size;
        SetLength(FSections, ACount);
      end;
      FSections[Index].Hdr.sh_name := Hdr32.sh_name;
      FSections[Index].Hdr.sh_type := Hdr32.sh_type;
      FSections[Index].Hdr.sh_flags := Hdr32.sh_flags;
      FSections[Index].Hdr.sh_addr := Hdr32.sh_addr;
      FSections[Index].Hdr.sh_offset := Hdr32.sh_offset;
      FSections[Index].Hdr.sh_size := Hdr32.sh_size;
      FSections[Index].Hdr.sh_link := Hdr32.sh_link;
      FSections[Index].Hdr.sh_info := Hdr32.sh_info;
      FSections[Index].Hdr.sh_addralign := Hdr32.sh_addralign;
      FSections[Index].Hdr.sh_entsize := Hdr32.sh_entsize;
      Inc(Index);
    end;
  end;
  StringsLen := Integer(FSections[FHeader.e_shstrndx].Hdr.sh_size);
  if StringsLen <= 0 then Exit(False);
  Strings := PByte(Raw.Memory) + FSections[FHeader.e_shstrndx].Hdr.sh_offset;
  for I := 0 to Index - 1 do
    if (FSections[I].Hdr.sh_name > 0) and (FSections[I].Hdr.sh_name < StringsLen) then
      FSections[I].DisplayName := string(PAnsiChar(Strings + FSections[I].Hdr.sh_name));
end;

function TRawElfImage.LoadSymbols(Raw: TMemoryStream): Boolean;
var
  SymSection, SymStrSection, ExecutableSection: TElfSectionHeader;
  Symbol: TImageSymbol;
  I, ACount: Integer;
  Hdr32: Elf32_Sym;
  Strings: PByte;
begin
  Result := SectionByType(SHT_SYMTAB, SymSection) and
    SectionAtIndex(SymSection.Hdr.sh_link, SymStrSection);
  if not Result then Exit;
  if Image64 then
    Result := SymSection.Hdr.sh_entsize = SizeOf(Elf64_Sym)
  else
    Result := SymSection.Hdr.sh_entsize = SizeOf(Elf32_Sym);
  if not Result then Exit;
  ACount := SymSection.Hdr.sh_size div SymSection.Hdr.sh_entsize;
  FDynSymbolsCount := Symbols.Count;
  Symbols.Count := FDynSymbolsCount + ACount;
  if ACount = 0 then Exit;
  Raw.Position := SymSection.Hdr.sh_offset;
  Strings := PByte(Raw.Memory) + SymStrSection.Hdr.sh_offset;
  Symbol := Default(TImageSymbol);
  Symbol.SymbolType := istDebug;
  for I := 0 to ACount - 1 do
  begin
    if Image64 then
      Raw.ReadBuffer(Symbol.Hdr, SizeOf(Elf64_Sym))
    else
    begin
      Raw.ReadBuffer(Hdr32, SizeOf(Hdr32));
      Symbol.Hdr.st_name := Hdr32.st_name;
      Symbol.Hdr.st_info := Hdr32.st_info;
      Symbol.Hdr.st_other := Hdr32.st_info;
      Symbol.Hdr.st_shndx := Hdr32.st_shndx;
      Symbol.Hdr.st_value := Hdr32.st_value;
      Symbol.Hdr.st_size := Hdr32.st_size;
    end;
    Symbol.Executable :=
      (Symbol.Hdr.st_shndx > 0) and
      (ELF32_ST_TYPE(Symbol.Hdr.st_info) in [STT_FUNC, STT_GNU_IFUNC]) and
      SectionAtIndex(Symbol.Hdr.st_shndx, ExecutableSection) and
      ((ExecutableSection.Hdr.sh_flags and SHF_EXECINSTR) <> 0);
    if (Symbol.Hdr.st_name > 0) and (Symbol.Hdr.st_name < SymStrSection.Hdr.sh_size) then
      Symbol.DisplayName := string(PAnsiChar(Strings + Symbol.Hdr.st_name))
    else
      Symbol.DisplayName := '';
    Symbols[FDynSymbolsCount + I] := Symbol;
  end;
  Include(FDebugData, ditSymbols);
end;

function TRawElfImage.ProgramHeaderAtAddrVA(AddrVA: Int64;
  out AHeader: Elf64_Phdr): Integer;
var
  I: Integer;
  StartRVA, Size: Int64;
begin
  Result := -1;
  AHeader := Default(Elf64_Phdr);
  if AddrVA <= FHeaderSize then
    Exit;
  for I := 0 to Length(FProgramHeaders) - 1 do
  begin
    if FProgramHeaders[I].p_offset = 0 then
      Continue;
    if FProgramHeaders[I].p_vaddr = 0 then
      Continue;
    if FProgramHeaders[I].p_filesz = 0 then
      Continue;
    if FProgramHeaders[I].p_memsz = 0 then
      Continue;
    StartRVA := FProgramHeaders[I].p_vaddr;
    Size := FProgramHeaders[I].p_memsz;
    if FProgramHeaders[I].p_type = PT_TLS then
    begin
      StartRVA := AlignUp(StartRVA, FProgramHeaders[I].p_align);
      Size := AlignDown(Size, FProgramHeaders[I].p_align);
    end;
    if (AddrVA >= StartRVA) and (AddrVA < StartRVA + Size) then
    begin
      if AHeader.p_vaddr = 0 then
        AHeader := FProgramHeaders[I]
      else
        if AHeader.p_vaddr < FProgramHeaders[I].p_vaddr then
          AHeader := FProgramHeaders[I];
        if AHeader.p_vaddr + AHeader.p_memsz >
          FProgramHeaders[I].p_vaddr + FProgramHeaders[I].p_memsz then
          AHeader := FProgramHeaders[I];
      Result := I;
    end;
  end;
end;

function TRawElfImage.ProgramHeaderAtIndex(AIndex: Integer;
  out AHeader: Elf64_Phdr): Boolean;
begin
  Result := (AIndex >= 0) and (AIndex < Length(FProgramHeaders));
  if Result then
    AHeader := FProgramHeaders[AIndex];
end;

function TRawElfImage.ProgramHeaderByType(AType: UInt32;
  out AHeader: Elf64_Phdr): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 0 to Length(FProgramHeaders) - 1 do
    if FProgramHeaders[I].p_type = AType then
    begin
      AHeader := FProgramHeaders[I];
      Result := True;
      Break;
    end;
end;

function TRawElfImage.ProgramHeadersCount: Integer;
begin
  Result := Length(FProgramHeaders);
end;

function TRawElfImage.RawToVa(RawAddr: DWORD): ULONG_PTR64;
var
  I: Integer;
  StartRVA: DWORD;
  FoundProgHeader: Elf64_Phdr;
begin
  Result := 0;
  for I := 0 to Length(FSections) - 1 do
    if (RawAddr >= FSections[I].Hdr.sh_offset) and
      (RawAddr < FSections[I].Hdr.sh_offset + FSections[I].Hdr.sh_size) then
    begin
      StartRVA := FSections[I].Hdr.sh_addr;
      Result := RawAddr - FSections[I].Hdr.sh_offset + StartRVA;
      Exit;
    end;
  FoundProgHeader := Default(Elf64_Phdr);
  for I := 0 to Length(FProgramHeaders) - 1 do
    if (RawAddr >= FProgramHeaders[I].p_offset) and
      (RawAddr < FProgramHeaders[I].p_offset + FProgramHeaders[I].p_filesz) then
    begin
      if FoundProgHeader.p_vaddr = 0 then
        FoundProgHeader := FProgramHeaders[I]
      else
      begin
        if FoundProgHeader.p_vaddr < FProgramHeaders[I].p_vaddr then
          FoundProgHeader := FProgramHeaders[I];
        if FoundProgHeader.p_vaddr + FoundProgHeader.p_memsz >
          FProgramHeaders[I].p_vaddr + FProgramHeaders[I].p_memsz then
          FoundProgHeader := FProgramHeaders[I];
      end;
    end;
  if FoundProgHeader.p_offset <> 0 then
  begin
    if FoundProgHeader.p_type = PT_TLS then
      StartRVA := AlignDown(FoundProgHeader.p_vaddr, FoundProgHeader.p_align)
    else
      StartRVA := FoundProgHeader.p_vaddr;
    Result := RawAddr - FoundProgHeader.p_offset + StartRVA;
  end;
end;

function TRawElfImage.RvaToRaw(RvaAddr: DWORD): DWORD;
begin
  // ELF файлы не работают в RVA адресации
  Result := VaToRaw(RvaAddr);
end;

function TRawElfImage.RvaToVa(RvaAddr: DWORD): ULONG_PTR64;
begin
  // ELF файлы не работают в RVA адресации
  Result := RvaAddr;
end;

function TRawElfImage.SectionAtIndex(AIndex: Integer;
  out Section: TElfSectionHeader): Boolean;
begin
  Result := (AIndex >= 0) and (AIndex < Length(FSections));
  if Result then
    Section := FSections[AIndex];
end;

function TRawElfImage.SectionAtName(const AName: string;
  out AIndex: Integer): Boolean;
var
  I: Integer;
begin
  Result := False;
  AIndex := -1;
  for I := 0 to Length(FSections) - 1 do
    if AnsiSameText(AName, FSections[I].DisplayName) then
    begin
      AIndex := I;
      Result := True;
      Break;
    end;
end;

function TRawElfImage.SectionByType(AType: UInt32;
  out Section: TElfSectionHeader): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 0 to Length(FSections) - 1 do
    if FSections[I].Hdr.sh_type = AType then
    begin
      Section := FSections[I];
      Result := True;
      Break;
    end;
end;

function TRawElfImage.SectionCount: Integer;
begin
  Result := Length(FSections);
end;

function TRawElfImage.ValidImage: Boolean;
begin
  Result := FValidImage;
end;

function TRawElfImage.VaToRaw(AddrVA: ULONG_PTR64): DWORD;
var
  NumberOfSections: Integer;
  SectionData: TSectionData;
  PointerToRawData: DWORD;
  ProgHeader: Elf64_Phdr;
begin
  Result := 0;

  if AddrVA < FHeader.e_ehsize then
    Exit(AddrVA);

  NumberOfSections := Length(FSections);
  if NumberOfSections = 0 then
  begin
    if AddrVA < FSizeOfFileImage then
      Exit(AddrVA);
    Exit;
  end;

  if GetSectionData(AddrVA, SectionData) then
  begin
    PointerToRawData := FSections[SectionData.Index].Hdr.sh_offset;
    Inc(PointerToRawData, AddrVA - SectionData.StartRVA);
    if PointerToRawData < FSizeOfFileImage then
      Exit(PointerToRawData);
  end;

  if ProgramHeaderAtAddrVA(AddrVA, ProgHeader) >= 0 then
  begin
    PointerToRawData := ProgHeader.p_offset;
    Inc(PointerToRawData, AddrVA - ProgHeader.p_vaddr);
    if PointerToRawData < FSizeOfFileImage then
      Result := PointerToRawData;
  end;
end;

function TRawElfImage.VaToRva(VaAddr: ULONG_PTR64): DWORD;
begin
  // ELF файлы не работают в RVA адресации
  Result := VaAddr;
end;

end.
