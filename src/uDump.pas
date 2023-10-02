////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uDump.pas
//  * Purpose   : Вспомогательный модуль для дампа памяти процесса
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

unit uDump;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  MemoryMap.Core,
  MemoryMap.Utils,
  MemoryMap.RegionData;

  function DumpAddr(const FileName: string;
    Address: Pointer; Size: NativeUInt = 0): NativeInt;
  function DumpRegion(const FileName: string; Value: TRegionData): NativeInt;

implementation

uses
  uUtils,
  uSettings;

function DumpAddr(const FileName: string;
  Address: Pointer; Size: NativeUInt): NativeInt;
var
  Process: THandle;
  ProcessLock: TProcessLockHandleList;
  Dummy: NativeUInt;
  Buff: array of Byte;
  MBI: TMemoryBasicInformation;
  dwLength: Cardinal;
  F: TFileStream;
begin
  ProcessLock := nil;
  Process := OpenProcessWithReconnect;
  try
    if Settings.SuspendProcess then
      ProcessLock := SuspendProcess(MemoryMapCore.PID);
    try
      if Size = 0 then
      begin
        dwLength := SizeOf(TMemoryBasicInformation);
        if VirtualQueryEx(Process,
          Address, MBI, dwLength) <> dwLength then
          RaiseLastOSError;
        Size := MBI.RegionSize;
      end;
      SetLength(Buff, Size);
      if ReadProcessData(Process, Address, @Buff[0], Size,
        Dummy, rcReadAllwais) then
      begin
        F := TFileStream.Create(FileName, fmCreate);
        try
          F.WriteBuffer(Buff[0], Size);
        finally
          F.Free;
        end;
      end;
      Result := Size;
    finally
      if Settings.SuspendProcess then
        ResumeProcess(ProcessLock);
    end;
  finally
    CloseHandle(Process);
  end;
end;

function DumpRegion(const FileName: string; Value: TRegionData): NativeInt;
begin
  Result := DumpAddr(FileName, Value.MBI.BaseAddress, Value.MBI.RegionSize);
end;

end.
