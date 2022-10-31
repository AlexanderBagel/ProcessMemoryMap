////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Logger.pas
//  * Purpose   : Общий логер для всех модулей RawScanner
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

unit RawScanner.Logger;

interface

uses
  SysUtils;

type
  // Типы логов
  TLogType = (ltNotify, ltInfo, ltWarning, ltError, ltFatal);

  // Уровни лога
  TLogLevel = (
    llCore,       // уведомления от базового класса
    llContext,    // уведомления от загрузчика контекста активации
    llPE,         // уведомления от загрузчика PE файлов
    llLoader,     // уведомления от загрузчика таблицы лоадера
    llApiSet,     // уведомления от парсера ApiSet таблицы
    llDisasm,     // уведомления от модуля дизасемблирования
    llWow64,      // уведомления от Wow64 хелпера
    llAnalizer    // уведомления от анализатора
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
