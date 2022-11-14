////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Types.pas
//  * Purpose   : Общие типы для модулей RawScanner
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2022.
//  * Version   : 1.0
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.Types;

interface

uses
  Windows,
  Generics.Collections;

const
  Space = ' ';
  Arrow = ' -> ';
  ReadError = 'Error reading %s at addr: 0x%.1x, code: %d, %s';
  ReadErrorIndex = 'Error reading %s[I] at addr: 0x%.1x, code: %d, %s';

type
  TProgressEvent = procedure(const Step: string; APecent: Integer) of object;

  THookType = (htImport, htDelayedImport, htExport, htCode);
  THookTypes = set of THookType;

  PULONG_PTR64 = ^ULONG_PTR64;
  ULONG_PTR64 = UInt64;

  TModuleData = record
    ImageBase: ULONG_PTR64;
    Is64Image,
    IsDll,
    IsBaseValid,
    IsILCoreImage,
    IsRedirected: Boolean;
    ImagePath: string;
    function IsEmpty: Boolean;
  end;
  TModuleList = TList<TModuleData>;

  UNICODE_STRING32 = record
    Length, MaximumLength: USHORT;
    Buffer: ULONG;
  end;

  UNICODE_STRING64 = record
    Length, MaximumLength: USHORT;
    Buffer: ULONG_PTR64;
  end;

  TMemoryBasicInformation64 = record
    BaseAddress : ULONG_PTR64;
    AllocationBase : ULONG_PTR64;
    AllocationProtect : DWORD;
    RegionSize : ULONG_PTR64;
    State : DWORD;
    Protect : DWORD;
    Type_9 : DWORD;
  end;


implementation

{ TModuleData }

function TModuleData.IsEmpty: Boolean;
begin
  Result := Self.ImageBase = 0;
end;

end.
