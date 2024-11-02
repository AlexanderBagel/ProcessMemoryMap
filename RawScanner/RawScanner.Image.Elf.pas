////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Image.Elf.pas
//  * Purpose   : Классы получающие данные о состоянии ELF файлов в процессе
//  *           : рассчитанные на основе образов файлов с диска.
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2024.
//  * Version   : 1.1.24
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.Image.Elf;

interface

uses
  Windows,
  Classes,
  SysUtils,
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

  TImageSymbol = record
    DisplayName: string;
    Executable: Boolean;
    Hdr: Elf64_Sym;
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
    function Rebase(Value: ULONG_PTR64): ULONG_PTR64; override;
  end;

  TRawElfImage = class(TAbstractImage)
  strict private
    FDebugData: TDebugInfoTypes;
    FDebugLinkPath: string;
    FDwarfDebugInfo: TDwarfDebugInfo;
    FHeader: Elf64_Ehdr;
    FHeaderSize: DWORD;
    FHeaderPresent: Boolean;
    FImageBase, FLoadedImageBase, FEntryPoint: ULONG_PTR64;
    FImageGate: TElfImageGate;
    FImagePath, FImageName: string;
    FIndex: Integer;
    FLoadSectionsOnly: Boolean;
    FProgramHeaders: array of Elf64_Phdr;
    FSections: array of TElfSectionHeader;
    FSectionsPresent: Boolean;
    FSizeOfFileImage: Int64;
    FSymbols: TList<TImageSymbol>;
    function GetGnuDebugLink(Raw: TStream): string;
    procedure LoadFromImage;
    procedure LoadDwarf(Raw: TStream);
    function LoadHeader(Raw: TStream): Boolean;
    function LoadProgramHeaders(Raw: TStream): Boolean;
    function LoadSections(Raw: TMemoryStream): Boolean;
    function LoadExport(Raw: TStream): Boolean;
    function LoadImport(Raw: TStream): Boolean;
    function LoadSymbols(Raw: TMemoryStream): Boolean;
  public
    constructor Create(const ImagePath: string; ALoadSectionsOnly: Boolean;
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
    function VaToRaw(AddrVA: ULONG_PTR64): DWORD; override;
    function VaToRva(VaAddr: ULONG_PTR64): DWORD; override;

    function SectionAtIndex(AIndex: Integer; out Section: TElfSectionHeader): Boolean;
    function SectionAtName(const AName: string; out AIndex: Integer): Boolean;
    function SectionByType(AType: UInt32; out Section: TElfSectionHeader): Boolean;

    property EntryPoint: ULONG_PTR64 read FEntryPoint;
    property Header: Elf64_Ehdr read FHeader;
    property HeaderPresent: Boolean read FHeaderPresent;
    property ImageBaseInHeaders: ULONG_PTR64 read FLoadedImageBase;
    property ImageName: string read FImageName;
    property ImagePath: string read FImagePath;
    property ModuleIndex: Integer read FIndex;
    property SectionsPresent: Boolean read FSectionsPresent;
    property Symbols: TList<TImageSymbol> read FSymbols;
  end;

implementation

{$IFNDEF DISABLE_LOGGER}
uses
  RawScanner.Logger;
{$ENDIF}

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

{ TRawElfImage }

constructor TRawElfImage.Create(const ImagePath: string;
  ALoadSectionsOnly: Boolean; ImageBase: ULONG_PTR64);
begin
  ProfilingBegin;
  FImagePath := ImagePath;
  FImageBase := ImageBase;
  FImageName := ExtractFileName(ImagePath);
  FLoadSectionsOnly := ALoadSectionsOnly;
  FSymbols := TList<TImageSymbol>.Create;
  FImageGate := TElfImageGate.Create(Self);
  FDwarfDebugInfo := TDwarfDebugInfo.Create(FImageGate);
  FDwarfDebugInfo.AppendUnitName := DefaultDwarfAppendUnitName;
  LoadFromImage;
  ProfilingEnd;
end;

constructor TRawElfImage.Create(const ModuleData: TModuleData;
  AModuleIndex: Integer);
begin
  FIndex := AModuleIndex;
  Create(ModuleData.ImagePath, False, ModuleData.ImageBase);
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
  FDwarfDebugInfo.Free;
  FImageGate.Free;
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
  ZeroMemory(@Data, SizeOf(Data));
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

function TRawElfImage.LoadExport(Raw: TStream): Boolean;
begin
  Result := False;
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

    if FLoadSectionsOnly then Exit;

    LoadExport(Raw);
    LoadImport(Raw);
    LoadSymbols(Raw);

    // COFF + DWARF могут сидеть во внешнем отладочном файле
    // ссылка на который будет находится в секции .gnu_debuglink
    FDebugLinkPath := GetGnuDebugLink(Raw);
    if FDebugLinkPath <> '' then
    begin
      // если это так - то переопределяем гейт образа на вспомогательный,
      // откуда будем брать актуальные отладочные данные, причем грузить его
      // будем только до секций (второй параметр), остальное в принципе лишнее
      // (да и нет там больше ничего)
      DebugLinkImage := TRawElfImage.Create(FDebugLinkPath, True, ImageBase);
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

function TRawElfImage.LoadImport(Raw: TStream): Boolean;
begin
  Result := False;
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
  if not Result  then Exit;
  if Image64 then
    Result := SymSection.Hdr.sh_entsize = SizeOf(Elf64_Sym)
  else
    Result := SymSection.Hdr.sh_entsize = SizeOf(Elf32_Sym);
  if not Result then Exit;
  ACount := SymSection.Hdr.sh_size div SymSection.Hdr.sh_entsize;
  Symbols.Count := ACount;
  if ACount = 0 then Exit;
  Raw.Position := SymSection.Hdr.sh_offset;
  Strings := PByte(Raw.Memory) + SymStrSection.Hdr.sh_offset;
  FillChar(Symbol, SizeOf(Symbols), 0);
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
    Symbol.Executable := False;
    if (Symbol.Hdr.st_shndx > 0) and (ELF32_ST_TYPE(Symbol.Hdr.st_info) = STT_FUNC) then
      if SectionAtIndex(Symbol.Hdr.st_shndx, ExecutableSection) then
        Symbol.Executable := (ExecutableSection.Hdr.sh_flags and SHF_EXECINSTR) <> 0;
    if (Symbol.Hdr.st_name > 0) and (Symbol.Hdr.st_name < SymStrSection.Hdr.sh_size) then
      Symbol.DisplayName := string(PAnsiChar(Strings + Symbol.Hdr.st_name))
    else
      Symbol.DisplayName := '';
    Symbols[I] := Symbol;
  end;
  Include(FDebugData, ditSymbols);
end;

function TRawElfImage.RawToVa(RawAddr: DWORD): ULONG_PTR64;
var
  I: Integer;
  StartRVA: DWORD;
begin
  Result := ImageBase + RawAddr;
  for I := 0 to Length(FSections) - 1 do
    if (RawAddr >= FSections[I].Hdr.sh_offset) and
      (RawAddr < FSections[I].Hdr.sh_offset + FSections[I].Hdr.sh_size) then
    begin
      StartRVA := FSections[I].Hdr.sh_addr;
      StartRVA := AlignDown(StartRVA, FSections[I].Hdr.sh_addralign);
      Result := RawAddr - FSections[I].Hdr.sh_addr + StartRVA + ImageBase;
      Break;
    end;
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

function TRawElfImage.VaToRaw(AddrVA: ULONG_PTR64): DWORD;
var
  NumberOfSections: Integer;
  SectionData: TSectionData;
  PointerToRawData: DWORD;
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
      Result := PointerToRawData;
  end;
end;

function TRawElfImage.VaToRva(VaAddr: ULONG_PTR64): DWORD;
begin
  // ELF файлы не работают в RVA адресации
  Result := VaAddr;
end;

end.
