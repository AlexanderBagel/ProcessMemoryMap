////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : MemoryMap
//  * Unit Name : MemoryMap.ImageHlp.pas
//  * Purpose   : Класс фиксит ошибки ImageHlp в Delphi 10.4
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

unit MemoryMap.ImageHlp;

interface

uses
  Windows,
  ImageHlp;

const
  ImagehlpLib = 'IMAGEHLP.DLL';

type
  // Delphi BUG!!!
  // Wrong record alignment!!!
  PloadedImage = ^TLoadedImage;
  {$EXTERNALSYM _LOADED_IMAGE}
  _LOADED_IMAGE = record
    ModuleName: LPSTR;
    hFile: THandle;
    MappedAddress: PChar;
    FileHeader: PImageNtHeaders;
    LastRvaSection: PImageSectionHeader;
    NumberOfSections: ULONG;
    Sections: PImageSectionHeader;
    Characteristics: ULONG;
    fSystemImage: ByteBool;
    fDOSImage: ByteBool;

    //Links: TListEntry;  WRONG ONE poiner record with align 16
    Links: LIST_ENTRY; // Valid two pointer record

    SizeOfImage: ULONG;
  end;
  {$EXTERNALSYM LOADED_IMAGE}
  LOADED_IMAGE = _LOADED_IMAGE;
  LoadedImage = _LOADED_IMAGE;
  TLoadedImage = _Loaded_IMAGE;

  function MapAndLoad(ImageName, DllPath: LPSTR; LoadedImage: PLoadedImage;
    DotDll, ReadOnly: Bool): Bool; stdcall; external ImagehlpLib;

  function ImageDirectoryEntryToData(Base: Pointer; MappedAsImage: ByteBool;
  DirectoryEntry: Word; var Size: ULONG): Pointer; stdcall; external ImagehlpLib;

  function UnMapAndLoad(LoadedImage: PLoadedImage): Bool; stdcall; external ImagehlpLib;

type
  PImagehlpSymbol = ^TImagehlpSymbol;
  _IMAGEHLP_SYMBOL = record
    SizeOfStruct: DWORD;
    Address: NativeUInt;
    Size,
    Flags,
    MaxNameLength: DWORD;
    Name: packed array[0..0] of Byte;
  end;
  TImagehlpSymbol = _IMAGEHLP_SYMBOL;

  {$IFDEF WIN64}
  function SymGetSymFromAddr(hProcess: THandle; dwAddr: ULONG_PTR;
    pdwDisplacement: PDWORD64; Symbol: PImagehlpSymbol): Bool; stdcall;
    external ImagehlpLib name 'SymGetSymFromAddr64';
  function SymLoadModule(hProcess: THandle; hFile: THandle; ImageName,
    ModuleName: LPSTR; BaseOfDll: ULONG_PTR; SizeOfDll: DWORD): DWORD; stdcall;
    external ImagehlpLib name 'SymLoadModule64';
  function SymUnloadModule(hProcess: THandle; BaseOfDll: ULONG_PTR): Bool; stdcall;
    external ImagehlpLib name 'SymUnloadModule64';
  function SymEnumerateSymbols(hProcess: THandle; BaseOfDll: ULONG_PTR;
    EnumSymbolsCallback: TSymEnumSymbolsCallback; UserContext: Pointer): Bool; stdcall;
    external ImagehlpLib name 'SymEnumerateSymbols64';
  {$ELSE}
  function SymGetSymFromAddr(hProcess: THandle; dwAddr: ULONG_PTR;
    pdwDisplacement: PDWORD; Symbol: PImagehlpSymbol): Bool; stdcall;
    external ImagehlpLib;
  function SymLoadModule(hProcess: THandle; hFile: THandle; ImageName,
    ModuleName: LPSTR; BaseOfDll: ULONG_PTR; SizeOfDll: DWORD): DWORD; stdcall;
    external ImagehlpLib;
  function SymUnloadModule(hProcess: THandle; BaseOfDll: ULONG_PTR): Bool; stdcall;
    external ImagehlpLib;
  function SymEnumerateSymbols(hProcess: THandle; BaseOfDll: ULONG_PTR;
    EnumSymbolsCallback: TSymEnumSymbolsCallback; UserContext: Pointer): Bool; stdcall;
    external ImagehlpLib;
  {$ENDIF}

{ options that are set/returned by SymSetOptions() & SymGetOptions() }
{ these are used as a mask }

const
  {$EXTERNALSYM SYMOPT_CASE_INSENSITIVE}
  SYMOPT_CASE_INSENSITIVE      = $00000001;
  {$EXTERNALSYM SYMOPT_UNDNAME}
  SYMOPT_UNDNAME               = $00000002;
  {$EXTERNALSYM SYMOPT_DEFERRED_LOADS}
  SYMOPT_DEFERRED_LOADS        = $00000004;
  {$EXTERNALSYM SYMOPT_NO_CPP}
  SYMOPT_NO_CPP                = $00000008;


  {$EXTERNALSYM SymSetOptions}
  function SymSetOptions(SymOptions: DWORD): DWORD; stdcall; external ImagehlpLib;

  {$EXTERNALSYM SymInitialize}
  function SymInitialize(hProcess: THandle; UserSearchPath: LPSTR;
    fInvadeProcess: Bool): Bool; stdcall; external ImagehlpLib;

  {$EXTERNALSYM SymCleanup}
  function SymCleanup(hProcess: THandle): Bool; stdcall; external ImagehlpLib;

implementation

end.
