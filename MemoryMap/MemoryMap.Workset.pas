////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : MemoryMap.Workset.pas
//  * Purpose   : The class collects data about the process's workset
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

unit MemoryMap.Workset;

interface

uses
  Winapi.Windows,
  Winapi.PsAPI,
  System.SysUtils,
  Generics.Collections;

type
  TShareInfo = record
    Shared: Boolean;
    SharedCount: Byte;
  end;

  TWorkset = class
  private
    FData: TDictionary<Pointer, TShareInfo>;
  protected
    procedure InitWorksetData(hProcess: THandle);
  public
    constructor Create(hProcess: THandle);
    destructor Destroy; override;
    function GetPageSharedInfo(pPage: Pointer; var Shared: Boolean;
      var SharedCount: Byte): Boolean;
  end;

implementation

{ TWorkset }

constructor TWorkset.Create(hProcess: THandle);
begin
  FData := TDictionary<Pointer, TShareInfo>.Create;
  InitWorksetData(hProcess);
end;

destructor TWorkset.Destroy;
begin
  FData.Free;
  inherited;
end;

function TWorkset.GetPageSharedInfo(pPage: Pointer; var Shared: Boolean;
  var SharedCount: Byte): Boolean;
var
  ShareInfo: TShareInfo;
begin
  Result := FData.TryGetValue(pPage, ShareInfo);
  if Result then
  begin
    Shared := ShareInfo.Shared;
    SharedCount := ShareInfo.SharedCount;
  end;
end;

procedure TWorkset.InitWorksetData(hProcess: THandle);
const
  {$IFDEF WIN64}
  AddrMask = $FFFFFFFFFFFFF000;
  {$ELSE}
  AddrMask = $FFFFF000;
  {$ENDIF}
  SharedBitMask = $100;
  SharedCountMask = $E0;

  function GetSharedCount(Value: ULONG_PTR): Byte; inline;
  begin
    Result := (Value and SharedCountMask) shr 5;
  end;

var
  WorksetBuff: array of ULONG_PTR;
  I: Integer;
  ShareInfo: TShareInfo;
begin
  SetLength(WorksetBuff, $400000);
  while not QueryWorkingSet(hProcess, @WorksetBuff[0],
    Length(WorksetBuff) * SizeOf(ULONG_PTR)) do
  begin
    if WorksetBuff[0] = 0 then Exit;
    SetLength(WorksetBuff, WorksetBuff[0] * 2);
  end;

  for I := 0 to WorksetBuff[0] - 1 do
  begin
    ShareInfo.Shared := WorksetBuff[I]  and SharedBitMask <> 0;
    ShareInfo.SharedCount := GetSharedCount(WorksetBuff[I]);
    try
      FData.AddOrSetValue(Pointer(WorksetBuff[I] and AddrMask), ShareInfo);
    except
      on E: EListError do ;
    else
      raise;
    end;
  end;
end;

end.
