////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : RawScanner.Logger.pas
//  * Purpose   : A common logger for all RawScanner modules
//  * Author    : Alexander (Rouse_) Bagel
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.2.30
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

unit RawScanner.Logger;

interface

  {$I rawscanner.inc}

uses
  SysUtils;

type
  TLogType = (ltNotify, ltInfo, ltWarning, ltError, ltFatal);

  TLogLevel = (
    llCore,
    llContext,
    llPE,
    llLoader,
    llApiSet,
    llDisasm,
    llWow64,
    llAnalizer
  );

  TOnLogEvent = reference to procedure(ALevel: TLogLevel; AType: TLogType;
    const FuncName, Description: string);

  TRawScannerLogger = class
  private
    class var FInstance: TRawScannerLogger;
    class destructor ClassDestroy;
  private
    FOnLog: TOnLogEvent;
    procedure DoLog(ALevel: TLogLevel; AType: TLogType;
      const FuncName, Description: string);
  public
    procedure Notify(ALevel: TLogLevel; const Description: string); overload;
    procedure Notify(ALevel: TLogLevel; const FuncName, Description: string); overload;
    procedure Info(ALevel: TLogLevel; const Description: string); overload;
    procedure Info(ALevel: TLogLevel; const FuncName, Description: string); overload;
    procedure Warn(ALevel: TLogLevel; const Description: string); overload;
    procedure Warn(ALevel: TLogLevel; const FuncName, Description: string); overload;
    procedure Error(ALevel: TLogLevel; const Description: string); overload;
    procedure Error(ALevel: TLogLevel; const FuncName, Description: string); overload;
    procedure Fatal(ALevel: TLogLevel; const Description: string); overload;
    procedure Fatal(ALevel: TLogLevel; const FuncName, Description: string); overload;
    property OnLog: TOnLogEvent read FOnLog write FOnLog;
  end;

  function RawScannerLogger: TRawScannerLogger;

implementation

function RawScannerLogger: TRawScannerLogger;
begin
  if TRawScannerLogger.FInstance = nil then
    TRawScannerLogger.FInstance := TRawScannerLogger.Create;
  Result := TRawScannerLogger.FInstance;
end;

{ TRawScannerLogger }

class destructor TRawScannerLogger.ClassDestroy;
begin
  FreeAndNil(FInstance);
end;

procedure TRawScannerLogger.DoLog(ALevel: TLogLevel; AType: TLogType;
  const FuncName, Description: string);
begin
  if Assigned(FOnLog) then
    FOnLog(ALevel, AType, FuncName, Description);
end;

procedure TRawScannerLogger.Error(ALevel: TLogLevel; const Description: string);
begin
  DoLog(ALevel, ltError, EmptyStr, Description);
end;

procedure TRawScannerLogger.Error(ALevel: TLogLevel; const FuncName,
  Description: string);
begin
  DoLog(ALevel, ltError, FuncName, Description);
end;

procedure TRawScannerLogger.Fatal(ALevel: TLogLevel; const Description: string);
begin
  DoLog(ALevel, ltFatal, EmptyStr, Description);
end;

procedure TRawScannerLogger.Fatal(ALevel: TLogLevel; const FuncName,
  Description: string);
begin
  DoLog(ALevel, ltFatal, FuncName, Description);
end;

procedure TRawScannerLogger.Info(ALevel: TLogLevel; const Description: string);
begin
  DoLog(ALevel, ltInfo, EmptyStr, Description);
end;

procedure TRawScannerLogger.Info(ALevel: TLogLevel; const FuncName,
  Description: string);
begin
  DoLog(ALevel, ltInfo, FuncName, Description);
end;

procedure TRawScannerLogger.Notify(ALevel: TLogLevel; const FuncName,
  Description: string);
begin
  DoLog(ALevel, ltNotify, FuncName, Description);
end;

procedure TRawScannerLogger.Notify(ALevel: TLogLevel;
  const Description: string);
begin
  DoLog(ALevel, ltNotify, EmptyStr, Description);
end;

procedure TRawScannerLogger.Warn(ALevel: TLogLevel; const Description: string);
begin
  DoLog(ALevel, ltWarning, EmptyStr, Description);
end;

procedure TRawScannerLogger.Warn(ALevel: TLogLevel; const FuncName,
  Description: string);
begin
  DoLog(ALevel, ltWarning, FuncName, Description);
end;

end.
