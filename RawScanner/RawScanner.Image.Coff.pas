////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Image.Coff.pas
//  * Purpose   : Классы получающие данные о состоянии обьектных Coff файлов
//  *           : рассчитанные на основе образов файлов с диска.
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2024.
//  * Version   : 1.1.20
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.Image.Coff;

interface

uses
  Windows,
  Classes,
  SysUtils,
  Math,
  Generics.Collections,
  RawScanner.AbstractImage,
  RawScanner.Types,
  RawScanner.CoffDwarf;

type
  TCoffSectionHeader = record
    Name: packed array[0..IMAGE_SIZEOF_SHORT_NAME-1] of Byte;
    Misc: TISHMisc;
    VirtualAddress: DWORD;
    SizeOfRawData: DWORD;
    PointerToRawData: DWORD;
    PointerToRelocations: DWORD;
    PointerToLinenumbers: DWORD;
    NumberOfRelocations: Word;
    NumberOfLinenumbers: Word;
    Characteristics: DWORD;
    COFFDebugOffsetRaw: DWORD;
    DisplayName: string; // содержит реальное имя секции с учетом отладочных COFF символов
  end;

  TRawCoffImage = class;

  TCoffImageGate = class(TAbstractImageGate)
  private
    FImage: TRawCoffImage;
    FImageReplaced: Boolean;
    procedure ClearReplaced;
    function GetSectionParams(const ASection: TCoffSectionHeader): TSectionParams;
  protected
    procedure ReplaceImage(ANewImage: TRawCoffImage);
  public
    constructor Create(AImage: TRawCoffImage);
    destructor Destroy; override;
    function IsObjectFile: Boolean; override;
    function GetIs64Image: Boolean; override;
    function NumberOfSymbols: Integer; override;
    function SectionAtIndex(AIndex: Integer; out ASection: TSectionParams): Boolean; override;
    function SectionAtName(const AName: string; out ASection: TSectionParams): Boolean; override;
    function PointerToSymbolTable: ULONG_PTR64; override;
    function Rebase(Value: ULONG_PTR64): ULONG_PTR64; override;
  end;

  TCoffHeader = record
    FileHeader: TImageFileHeader;
    case Boolean of
      False: (OptionalHeader32: TImageOptionalHeader32);
      True: (OptionalHeader64: TImageOptionalHeader64);
  end;

  TRawCoffImage = class(TAbstractImage)
  private const
    DEFAULT_FILE_ALIGNMENT = $200;
    DEFAULT_SECTION_ALIGNMENT = $1000;
  strict private
    FCoffDebugInfo: TCoffDebugInfo;
    FDebugData: TDebugInfoTypes;
    FDebugLinkPath: string;
    FDwarfDebugInfo: TDwarfDebugInfo;
    FHeader: TCoffHeader;
    FImageBase, FEntryPoint: ULONG_PTR64;
    FImageGate: TCoffImageGate;
    FImagePath, FImageName: string;
    FIndex: Integer;
    FLoadSectionsOnly: Boolean;
    FSections: array of TCoffSectionHeader;
    FSectionsPresent: Boolean;
    FSizeOfFileImage: Int64;
    function GetGnuDebugLink(Raw: TStream): string;
    procedure LoadFromImage;
    procedure LoadCoff(Raw: TStream);
    procedure LoadDwarf(Raw: TStream);
    function LoadSections(Raw: TMemoryStream): Boolean;
    function LoadExport(Raw: TStream): Boolean;
    function LoadImport(Raw: TStream): Boolean;
  protected
    function FileAlignment: DWORD;
    function SectionAlignment: DWORD;
  public
    constructor Create(const ImagePath: string; ALoadSectionsOnly: Boolean;
      ImageBase: ULONG_PTR64 = 0); overload;
    constructor Create(const ModuleData: TModuleData; AModuleIndex: Integer); overload;
    destructor Destroy; override;

    property CoffDebugInfo: TCoffDebugInfo read FCoffDebugInfo;
    function DebugData: TDebugInfoTypes; override;
    function DebugLinkPath: string; override;
    function DwarfDebugInfo: TDwarfDebugInfo; override;
    function GetSectionData(RvaAddr: DWORD; var Data: TSectionData): Boolean; override;
    function Image64: Boolean; override;
    function ImageBase: ULONG_PTR64; override;

    function RawToVa(RawAddr: DWORD): ULONG_PTR64; override;
    function VaToRaw(AddrVA: ULONG_PTR64): DWORD; override;
    function VaToRva(AddrVA: ULONG_PTR64): DWORD; override;

    function SectionAtIndex(AIndex: Integer; out Section: TCoffSectionHeader): Boolean;
    function SectionAtName(const AName: string; out AIndex: Integer): Boolean;

    property EntryPoint: ULONG_PTR64 read FEntryPoint;
    property Header: TCoffHeader read FHeader;
    property ImageName: string read FImageName;
    property ImagePath: string read FImagePath;
    property ModuleIndex: Integer read FIndex;
    property SectionsPresent: Boolean read FSectionsPresent;
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

{ TCoffImageGate }

procedure TCoffImageGate.ClearReplaced;
begin
  if FImageReplaced then
  begin
    FImageReplaced := False;
    FImage.Free;
  end;
end;

constructor TCoffImageGate.Create(AImage: TRawCoffImage);
begin
  FImage := AImage;
  ModuleIndex := AImage.ModuleIndex;
end;

destructor TCoffImageGate.Destroy;
begin
  ClearReplaced;
  inherited;
end;

function TCoffImageGate.GetIs64Image: Boolean;
begin
  Result := FImage.Image64;
end;

function TCoffImageGate.GetSectionParams(
  const ASection: TCoffSectionHeader): TSectionParams;
const
  ExecutableCode = IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE;
begin
  Result.AddressVA := ASection.VirtualAddress;
  Result.AddressRaw := ASection.PointerToRawData;
  Result.SizeOfRawData := ASection.SizeOfRawData;
  Result.IsExecutable := ASection.Characteristics and ExecutableCode <> 0;
  Result.DisplayName := ASection.DisplayName;
end;

function TCoffImageGate.IsObjectFile: Boolean;
begin
  Result := True;
end;

function TCoffImageGate.NumberOfSymbols: Integer;
begin
  Result := FImage.Header.FileHeader.NumberOfSymbols;
end;

function TCoffImageGate.PointerToSymbolTable: ULONG_PTR64;
begin
  Result := FImage.Header.FileHeader.PointerToSymbolTable;
end;

function TCoffImageGate.Rebase(Value: ULONG_PTR64): ULONG_PTR64;
begin
  Result := Value;
end;

procedure TCoffImageGate.ReplaceImage(ANewImage: TRawCoffImage);
begin
  ClearReplaced;
  FImage := ANewImage;
  FImageReplaced := True;
end;

function TCoffImageGate.SectionAtIndex(AIndex: Integer;
  out ASection: TSectionParams): Boolean;
var
  Section: TCoffSectionHeader;
begin
  Result := FImage.SectionAtIndex(AIndex, Section);
  if Result then
    ASection := GetSectionParams(Section);
end;

function TCoffImageGate.SectionAtName(const AName: string;
  out ASection: TSectionParams): Boolean;
var
  AIndex: Integer;
  Section: TCoffSectionHeader;
begin
  Result := FImage.SectionAtName(AName, AIndex);
  if Result then
  begin
    FImage.SectionAtIndex(AIndex, Section);
    ASection := GetSectionParams(Section);
  end;
end;

{ TRawCoffImage }

constructor TRawCoffImage.Create(const ImagePath: string;
  ALoadSectionsOnly: Boolean; ImageBase: ULONG_PTR64);
begin
  FImagePath := ImagePath;
  FImageBase := ImageBase;
  FImageName := ExtractFileName(ImagePath);
  FImageGate := TCoffImageGate.Create(Self);
  FCoffDebugInfo := TCoffDebugInfo.Create(FImageGate);
  FDwarfDebugInfo := TDwarfDebugInfo.Create(FImageGate);
  FLoadSectionsOnly := ALoadSectionsOnly;
  LoadFromImage;
end;

constructor TRawCoffImage.Create(const ModuleData: TModuleData;
  AModuleIndex: Integer);
begin
  FIndex := AModuleIndex;
  Create(ModuleData.ImagePath, False, ModuleData.ImageBase);
end;

function TRawCoffImage.DebugData: TDebugInfoTypes;
begin
  Result := FDebugData;
end;

function TRawCoffImage.DebugLinkPath: string;
begin
  Result := FDebugLinkPath;
end;

destructor TRawCoffImage.Destroy;
begin
  FDwarfDebugInfo.Free;
  FCoffDebugInfo.Free;
  FImageGate.Free;
  inherited;
end;

function TRawCoffImage.DwarfDebugInfo: TDwarfDebugInfo;
begin
  Result := FDwarfDebugInfo;
end;

function TRawCoffImage.FileAlignment: DWORD;
begin
  if Image64 then
    Result := FHeader.OptionalHeader64.FileAlignment
  else
    Result := FHeader.OptionalHeader32.FileAlignment;
end;

function TRawCoffImage.GetGnuDebugLink(Raw: TStream): string;
var
  Index: Integer;
  DebugLink: AnsiString;
begin
  if SectionAtName('.gnu_debuglink', Index) then
  begin
    SetLength(DebugLink, FSections[Index].SizeOfRawData);
    Raw.Position := FSections[Index].PointerToRawData;
    Raw.ReadBuffer(DebugLink[1], FSections[Index].SizeOfRawData);
    Result := ExtractFilePath(ImagePath) + string(PAnsiChar(@DebugLink[1]));
    if not FileExists(Result) then
      Result := '';
  end
  else
    Result := '';
end;

function TRawCoffImage.GetSectionData(RvaAddr: DWORD;
  var Data: TSectionData): Boolean;
var
  I, NumberOfSections: Integer;
  SizeOfRawData, VirtualSize: DWORD;
begin
  Result := False;

  ZeroMemory(@Data, SizeOf(Data));
  if RvaAddr < SizeOf(TImageFileHeader) + Header.FileHeader.SizeOfOptionalHeader then
    Exit;

  NumberOfSections := Length(FSections);
  for I := 0 to NumberOfSections - 1 do
  begin

    if FSections[I].SizeOfRawData = 0 then
      Continue;
    if FSections[I].PointerToRawData = 0 then
      Continue;

    Data.StartRVA := FSections[I].VirtualAddress;
    if SectionAlignment >= DEFAULT_SECTION_ALIGNMENT then
      Data.StartRVA := AlignDown(Data.StartRVA, SectionAlignment);

    SizeOfRawData := FSections[I].SizeOfRawData;
    VirtualSize := FSections[I].Misc.VirtualSize;
    if VirtualSize = 0 then
      VirtualSize := SizeOfRawData;
    if SectionAlignment >= DEFAULT_SECTION_ALIGNMENT then
    begin
      SizeOfRawData := AlignUp(SizeOfRawData, FileAlignment);
      VirtualSize := AlignUp(VirtualSize, SectionAlignment);
    end;
    Data.Size := Min(SizeOfRawData, VirtualSize);

    if (RvaAddr >= Data.StartRVA) and (RvaAddr < Data.StartRVA + Data.Size) then
    begin
      Data.Index := I;
      Data.Read := FSections[I].Characteristics and IMAGE_SCN_MEM_READ <> 0;
      Data.Write := FSections[I].Characteristics and IMAGE_SCN_MEM_WRITE <> 0;
      Data.Execute := FSections[I].Characteristics and IMAGE_SCN_MEM_EXECUTE <> 0;
      Result := True;
      Break;
    end;

  end;
end;

function TRawCoffImage.Image64: Boolean;
begin
  Result := ImageType = itCOFF64;
end;

function TRawCoffImage.ImageBase: ULONG_PTR64;
begin
  Result := 0;
end;

procedure TRawCoffImage.LoadCoff(Raw: TStream);
begin
  if Header.FileHeader.PointerToSymbolTable = 0 then
    Exit;
  if FCoffDebugInfo.Load(Raw) then
    Include(FDebugData, ditCoff);
end;

procedure TRawCoffImage.LoadDwarf(Raw: TStream);
begin
  FDebugData := FDebugData + FDwarfDebugInfo.Load(Raw);
end;

function TRawCoffImage.LoadExport(Raw: TStream): Boolean;
begin
  Result := False;
end;

procedure TRawCoffImage.LoadFromImage;
var
  Raw: TMemoryStream;
  DebugLinkImage: TRawCoffImage;
  ValidHeader: Boolean;
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

    ZeroMemory(@FHeader, SizeOf(FHeader));
    Raw.ReadBuffer(FHeader.FileHeader, SizeOf(FHeader.FileHeader));
    ValidHeader := (FHeader.FileHeader.Machine = IMAGE_FILE_MACHINE_I386) or
      (FHeader.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64);
    if not ValidHeader then
    begin
      Error(Format('Invalid FileHeader.Machine (0x%.1x) in "%s"',
        [FHeader.FileHeader.Machine, ImagePath]));
      Exit;
    end;

    if FHeader.FileHeader.SizeOfOptionalHeader = 0 then
    begin
      if FHeader.FileHeader.Machine = IMAGE_FILE_MACHINE_I386 then
        SetImageType(itCOFF32)
      else
        SetImageType(itCOFF64);
    end
    else
    begin
      Raw.ReadBuffer(FHeader.OptionalHeader32, FHeader.FileHeader.SizeOfOptionalHeader);
      case FHeader.OptionalHeader32.Magic of
        IMAGE_NT_OPTIONAL_HDR32_MAGIC: SetImageType(itCOFF32);
        IMAGE_NT_OPTIONAL_HDR64_MAGIC: SetImageType(itCOFF64);
      else
        Exit;
      end;
      if ImageBase = 0 then
      begin
        if Image64 then
          FImageBase := FHeader.OptionalHeader64.ImageBase
        else
          FImageBase := FHeader.OptionalHeader32.ImageBase;
      end;
    end;

    if not LoadSections(Raw) then Exit;

    if FLoadSectionsOnly then Exit;

    LoadExport(Raw);
    LoadImport(Raw);

    FDebugLinkPath := GetGnuDebugLink(Raw);
    if FDebugLinkPath <> '' then
    begin
      DebugLinkImage := TRawCoffImage.Create(FDebugLinkPath, True, ImageBase);
      FImageGate.ReplaceImage(DebugLinkImage);
      Raw.LoadFromFile(FDebugLinkPath);
    end;

    LoadCoff(Raw);
    LoadDwarf(Raw);

  finally
    Raw.Free;
  end;
end;

function TRawCoffImage.LoadImport(Raw: TStream): Boolean;
begin
  Result := False;
end;

function TRawCoffImage.LoadSections(Raw: TMemoryStream): Boolean;
var
  COFFOffset: NativeUInt;
  I, Index: Integer;
  SectionName: array [0..255] of AnsiChar;
begin
  Result := FHeader.FileHeader.NumberOfSections > 0;
  SetLength(FSections, FHeader.FileHeader.NumberOfSections);
  for I := 0 to FHeader.FileHeader.NumberOfSections - 1 do
  begin
    Raw.ReadBuffer(FSections[I], SizeOf(TImageSectionHeader));
    FSections[I].DisplayName := Copy(string(PAnsiChar(@FSections[I].Name[0])), 1, 8);
  end;

  COFFOffset := FHeader.FileHeader.PointerToSymbolTable +
    FHeader.FileHeader.NumberOfSymbols * SizeOf(TCOFFSymbolRecord);

  // Если отладочных COFF символов нет, то и обрабатывать нечего
  if COFFOffset = 0 then
    Exit;

  for I := 0 to FHeader.FileHeader.NumberOfSections - 1 do
    if FSections[I].Name[0] = 47 {"/"} then
    begin
      if TryStrToInt(string(PAnsiChar(@FSections[I].Name[1])), Index) then
      begin
        FSections[I].COFFDebugOffsetRaw := COFFOffset + NativeUInt(Index);
        Raw.Position := FSections[I].COFFDebugOffsetRaw;
        SectionName[255] := #0;
        Raw.ReadBuffer(SectionName[0], Min(255, Raw.Size - Raw.Position));
        FSections[I].DisplayName := string(PAnsiChar(@SectionName[0]));
      end;
    end;
end;

function TRawCoffImage.RawToVa(RawAddr: DWORD): ULONG_PTR64;
begin
  Result := RawAddr;
end;

function TRawCoffImage.SectionAlignment: DWORD;
begin
  if Image64 then
    Result := FHeader.OptionalHeader64.SectionAlignment
  else
    Result := FHeader.OptionalHeader32.SectionAlignment;
end;

function TRawCoffImage.SectionAtIndex(AIndex: Integer;
  out Section: TCoffSectionHeader): Boolean;
begin
  Result := (AIndex >= 0) and (AIndex < Length(FSections));
  if Result then
    Section := FSections[AIndex];
end;

function TRawCoffImage.SectionAtName(const AName: string;
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

function TRawCoffImage.VaToRaw(AddrVA: ULONG_PTR64): DWORD;
begin
  Result := AddrVA;
end;

function TRawCoffImage.VaToRva(AddrVA: ULONG_PTR64): DWORD;
begin
  Result := AddrVA;
end;

end.
