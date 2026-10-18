////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : MemoryMap.ImageHlp.pas
//  * Purpose   : Fixes for ImageHlp errors in Delphi 10.4
//  * Author    : Alexander (Rouse_) Bagel
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.4.41
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : https://github.com/AlexanderBagel/ProcessMemoryMap/releases
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
  function SymUnDName(Symbol: PImagehlpSymbol; UnDecName: PChar; UnDecNameLength: DWORD): Bool; stdcall;
    external ImagehlpLib name 'SymUnDName64';
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
  function SymUnDName(Symbol: PImagehlpSymbol; UnDecName: PChar; UnDecNameLength: DWORD): Bool; stdcall;
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

  {$EXTERNALSYM SymSetOptions}
  function SymGetOptions: DWORD; stdcall; external ImagehlpLib;

  {$EXTERNALSYM SymInitialize}
  function SymInitialize(hProcess: THandle; UserSearchPath: LPSTR;
    fInvadeProcess: Bool): Bool; stdcall; external ImagehlpLib;

  {$EXTERNALSYM SymCleanup}
  function SymCleanup(hProcess: THandle): Bool; stdcall; external ImagehlpLib;

implementation

end.
