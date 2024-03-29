﻿////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Types.pas
//  * Purpose   : Общие типы для модулей RawScanner
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.0.15
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.Types;

interface

  {$I rawscanner.inc}

uses
  Windows,
  SysUtils,
  Generics.Collections;

const
  Space = ' ';
  Arrow = ' -> ';
  ReadError = 'Error reading %s at addr: 0x%.1x, code: %d, %s';
  ReadErrorIndex = 'Error reading %s[I] at addr: 0x%.1x, code: %d, %s';

const
  IMAGE_REL_BASED_ABSOLUTE = 0;
  IMAGE_REL_BASED_HIGH = 1;
  IMAGE_REL_BASED_LOW = 2;
  IMAGE_REL_BASED_HIGHLOW = 3;
  IMAGE_REL_BASED_HIGHADJ = 4;
  IMAGE_REL_BASED_MIPS_JMPADDR = 5;
  IMAGE_REL_BASED_SECTION = 6;
  IMAGE_REL_BASED_REL32 = 7;
  IMAGE_REL_BASED_MIPS_JMPADDR16 = 8;
  IMAGE_REL_BASED_IA64_IMM64 = 9;
  IMAGE_REL_BASED_DIR64 = 10;
  IMAGE_REL_BASED_HIGH3ADJ = 11;

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

  TInt64IntRec = record
    case Integer of
      0: (Lo, Hi: Integer);
      1: (Value: Int64);
      2: (Rec: Int64Rec);
  end;

implementation

{ TModuleData }

function TModuleData.IsEmpty: Boolean;
begin
  Result := Self.ImageBase = 0;
end;

end.
