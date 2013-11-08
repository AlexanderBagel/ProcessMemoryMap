////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : MemoryMap
//  * Unit Name : MemoryMap.PEImage
//  * Purpose   : Класс собирает данные по секциям и директориям PE файла
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2013.
//  * Version   : 1.0
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit MemoryMap.PEImage;

interface

uses
  Winapi.Windows,
  Generics.Collections,
  MemoryMap.Utils,
  Winapi.ImageHlp;

type
  TSection = record
    Caption: ShortString;
    Address: NativeUInt;
    Size: NativeUInt;
    IsCode: Boolean;
    IsData: Boolean;
  end;

  TDirectory = record
    Caption: ShortString;
    Address: NativeUInt;
    Size: NativeUInt;
  end;

  TDirectoryArray = record
    Count: Integer;
    Data: array [0..14] of TDirectory;
  end;

  TPEImage = class
  private
    FImageBase: Pointer;
    FImageInfo: LOADED_IMAGE;
    FSections: TList<TSection>;
    FDirectoryes: TList<TDirectoryArray>;
    FEntryPoints: TList<Pointer>;
  protected
    procedure EnumSections;
    procedure EnumDirectoryes;
  public
    constructor Create;
    destructor Destroy; override;
    procedure GetInfoFromImage(const FileName: string; ImageBase: Pointer;
      FirstSectionSize: NativeUInt);
    function GetSectionArAddr(Value: Pointer): TSection;
    property Sections: TList<TSection> read FSections;
    property Directoryes: TList<TDirectoryArray> read FDirectoryes;
    property EntryPoints: TList<Pointer> read FEntryPoints;
  end;

implementation

{ TPEImage }

constructor TPEImage.Create;
begin
  FSections := TList<TSection>.Create;
  FDirectoryes := TList<TDirectoryArray>.Create;
  FEntryPoints := TList<Pointer>.Create;
end;

destructor TPEImage.Destroy;
begin
  FEntryPoints.Free;
  FDirectoryes.Free;
  FSections.Free;
  inherited;
end;

procedure TPEImage.EnumDirectoryes;
const
  DirectoryStr: array [0..14] of string =
    ('export', 'import', 'resource', 'exception',
    'security', 'basereloc', 'debug', 'copyright',
    'globalptr', 'tls', 'load_config', 'bound_import',
    'iat', 'delay_import', 'com');
var
  I: Integer;
  dwDirSize: DWORD;
  DirAddr: Pointer;
  Directory: TDirectoryArray;
begin
  ZeroMemory(@Directory, SizeOf(TDirectoryArray));
  Directory.Count := 0;
  for I := 0 to 14 do
  begin
    // Получаем адрес директории
    DirAddr := ImageDirectoryEntryToData(FImageInfo.MappedAddress,
      True, I, dwDirSize);
    if DirAddr <> nil then
    begin
      Inc(Directory.Count);
      Directory.Data[I].Caption := ShortString(DirectoryStr[I]);
      Directory.Data[I].Address := NativeUint(FImageBase) +
        NativeUint(DirAddr) - NativeUint(FImageInfo.MappedAddress);
      Directory.Data[I].Size := dwDirSize;
    end;
  end;
  FDirectoryes.Add(Directory);
end;

procedure TPEImage.EnumSections;
var
  ImageSectionHeader: PImageSectionHeader;
  I: Integer;
  Section: TSection;
begin
  ImageSectionHeader := FImageInfo.Sections;
  for I := 0 to Integer(FImageInfo.NumberOfSections) - 1 do
  begin
    Section.Caption := ShortString(PAnsiChar(@ImageSectionHeader^.Name[0]));
    Section.Address := NativeUint(FImageBase) + ImageSectionHeader^.VirtualAddress;
    Section.Size := AlignedSectionSize(FImageInfo, ImageSectionHeader^.SizeOfRawData);
    Section.IsCode := IsExecute(ImageSectionHeader^.Characteristics);
    Section.IsData := IsWrite(ImageSectionHeader^.Characteristics);
    FSections.Add(Section);
    Inc(ImageSectionHeader);
  end;
end;

procedure TPEImage.GetInfoFromImage(const FileName: string; ImageBase: Pointer;
  FirstSectionSize: NativeUInt);
var
  Section: TSection;
begin
  FImageBase := ImageBase;
  if MapAndLoad(PAnsiChar(AnsiString(FileName)), nil, @FImageInfo, True, True) then
  try
    Section.Caption := 'PEHeader';
    Section.Address := NativeUint(ImageBase);
    Section.Size := FirstSectionSize;
    Section.IsCode := False;
    Section.IsData := False;
    FSections.Add(Section);
    if FImageInfo.FileHeader.OptionalHeader.AddressOfEntryPoint <> 0 then
      FEntryPoints.Add(Pointer(NativeUInt(ImageBase) +
        FImageInfo.FileHeader.OptionalHeader.AddressOfEntryPoint));
    EnumSections;
    EnumDirectoryes;
  finally
    UnMapAndLoad(@FImageInfo);
  end;
end;

function TPEImage.GetSectionArAddr(Value: Pointer): TSection;
var
  I: TSection;
begin
  ZeroMemory(@Result, SizeOf(TSection));
  for I in FSections do
    if I.Address <= NativeUInt(Value) then
      if I.Address + I.Size > NativeUInt(Value) then
        Exit(I);
end;

end.
