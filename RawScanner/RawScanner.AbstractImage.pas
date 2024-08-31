////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.AbstractImage.pas
//  * Purpose   : Базовый класс образа файла с которым умеет работать RawScanner
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

unit RawScanner.AbstractImage;

interface

uses
  Windows,
  RawScanner.Types,
  RawScanner.CoffDwarf;

type
  TSectionData = record
    Index: Integer;
    StartRVA, Size: DWORD;
    Read, Write, Execute: Boolean;
  end;

  TImageType = (itUnknown,
    itPE32, itPE64, itELF32, itELF64, itCOFF32, itCOFF64,
    // OMF пока что не поддерживается, т.к. не понятно где его взять с DWARF отладочными
    itOMF32, itOMF64);

  TAbstractImage = class
  private
    FImageType: TImageType;
  protected
    function AlignDown(Value: DWORD; Align: DWORD): DWORD;
    function AlignUp(Value: DWORD; Align: DWORD): DWORD;
    procedure SetImageType(Value: TImageType);
  public
    function DebugData: TDebugInfoTypes; virtual; abstract;
    function DebugLinkPath: string; virtual; abstract;
    function DwarfDebugInfo: TDwarfDebugInfo; virtual; abstract;
    function GetSectionData(RvaAddr: DWORD; var Data: TSectionData): Boolean; virtual; abstract;
    function Image64: Boolean; virtual; abstract;
    function ImageBase: ULONG_PTR64; virtual; abstract;
    function RawToVa(RawAddr: DWORD): ULONG_PTR64; virtual; abstract;
    function VaToRaw(AddrVA: ULONG_PTR64): DWORD; virtual; abstract;
    function VaToRva(VaAddr: ULONG_PTR64): DWORD; virtual; abstract;
    property ImageType: TImageType read FImageType;
  end;

implementation

{ TAbstractImage }

function TAbstractImage.AlignDown(Value, Align: DWORD): DWORD;
begin
  Result := Value and not DWORD(Align - 1);
end;

function TAbstractImage.AlignUp(Value, Align: DWORD): DWORD;
begin
  if Value = 0 then Exit(0);
  Result := AlignDown(Value - 1, Align) + Align;
end;

procedure TAbstractImage.SetImageType(Value: TImageType);
begin
  FImageType := Value;
end;

end.
