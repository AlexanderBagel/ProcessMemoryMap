////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Unit Name : CallStackTraceUtils
//  * Purpose   : Реализация дампа текущего стека вызовов
//  * Author    : Александр (Rouse_) Багель
//  * Version   : 1.01
//  ****************************************************************************
//

unit CallStackTraceUtils;

interface

uses
  Windows,
  Classes,
  SysUtils,
  PsAPI,
  MemoryMap.Symbols,
  MemoryMap.DebugMapData,
  MemoryMap.Utils;

  function GetCallStack(FramesCount: Integer = 128): TStringList;

implementation

  function RtlCaptureStackBackTrace(FramesToSkip, FramesToCapture: ULONG;
    BackTrace: PPVOID; BackTraceHash: PULONG): USHORT; stdcall; external kernel32;

  function EnumProcessModulesEx(hProcess: THandle; lphModule: PHandle;
    cb: DWORD; var lpcbNeeded: DWORD; dwFilterFlag: DWORD): BOOL; stdcall;
    external 'psapi.dll';

function GetBaseAddr(AAddress: NativeUInt): NativeUInt;
var
  Info: TMemoryBasicInformation;
begin
  if VirtualQuery(Pointer(AAddress), Info, SizeOf(TMemoryBasicInformation)) <> 0 then
    Result := NativeUInt(Info.BaseAddress)
  else
    Result := 0;
end;

function GetModuleNameFromAddr(AAddress: NativeUInt): string;
var
  Len: Cardinal;
begin
  SetLength(Result, MAX_PATH);
  Len := GetMappedFileName(GetCurrentProcess, Pointer(AAddress),
    @Result[1], MAX_PATH);
  SetLength(Result, Len);
  Result := NormalizePath(Result);
end;

function GetFunction(const Value: string): string;
var
  Index: Integer;
begin
  Index := Pos('+', Value);
  if Index > 0 then
    Result := Trim(Copy(Value, 1, Index - 1))
  else
    Result := '';
end;

function GetDescriptionAtAddr(AAddress: NativeUInt; ASymbols: TSymbols;
  AMap: TDebugMap): string;
var
  LineNumber: Integer;
  AUnitName, AFuncName: string;
  BaseAddr: NativeUInt;
begin
  LineNumber := AMap.GetLineNumberAtAddrForced(AAddress, 400, AUnitName);
  AFuncName := AMap.GetDescriptionAtAddrWithOffset(AAddress);
  if LineNumber <= 0 then
  begin
    BaseAddr := GetBaseAddr(AAddress);
    Result := ASymbols.GetDescriptionAtAddr(AAddress, BaseAddr, GetModuleNameFromAddr(BaseAddr));
    Result := Format('%.8x: %s', [AAddress, Result]);
  end
  else
  begin
    AFuncName := GetFunction(AFuncName);
    Result := Format('%.8x: %s line %d', [AAddress, AFuncName, LineNumber]);
  end;
end;

procedure InitMap(Map: TDebugMap);
const
  LIST_MODULES_ALL = 3;
var
  Buff: array of THandle;
  Needed: DWORD;
  I: Integer;
  FileNameBuff: array[0..MAX_PATH] of Char;
  FileName: string;
begin
  EnumProcessModulesEx(GetCurrentProcess, nil, 0, Needed, LIST_MODULES_ALL);
  SetLength(Buff, Needed shr 2);
  if EnumProcessModulesEx(GetCurrentProcess, @Buff[0], Needed, Needed, LIST_MODULES_ALL) then
  begin
    for I := 0 to Integer(Needed) - 1 do
      if Buff[I] <> 0 then
      begin
        FillChar(FileNameBuff, MAX_PATH, 0);
        GetModuleFileNameEx(GetCurrentProcess, Buff[I], @FileNameBuff[0], MAX_PATH);
        FileName := string(PChar(@FileNameBuff[0]));
        if FileExists(ChangeFileExt(FileName, '.map')) then
          Map.Init(Buff[I], FileName);
      end;
  end;
end;

function GetCallStack(FramesCount: Integer): TStringList;
var
  Map: TDebugMap;
  Symbols: TSymbols;
  Stack: array of NativeUInt;
  I: Integer;
begin
  Result := TStringList.Create;
  try
    if FramesCount <= 0 then
      Exit;
    Map := TDebugMap.Create;
    try
      Map.LoadLines := True;
      InitMap(Map);
      Symbols := TSymbols.Create(GetCurrentProcess);
      try
        SetLength(Stack, FramesCount);
        for I := 1 to RtlCaptureStackBackTrace(0, FramesCount, @Stack[0], nil) - 1 do
          Result.Add(GetDescriptionAtAddr(Stack[I], Symbols, Map));
      finally
        Symbols.Free;
      end;
    finally
      Map.Free;
    end;
  except
    FreeAndNil(Result);
    raise;
  end;
end;

end.
