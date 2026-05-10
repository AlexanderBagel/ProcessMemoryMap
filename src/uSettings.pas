////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uSettings.pas
//  * Purpose   : Класс настроек
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.6.47
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uSettings;

interface

uses
  Windows, Classes, Graphics, SysUtils, Registry;

type
  TExportStatus = (esNormal, esForvarded, esRebased,
    esNoExecutable, esInvalid,
    esDebug, esDebugData, // MAP
    esCoff, esCoffData,   // COFF
    esDwarf, esDwarfData  // DWARF
    );
  PExportsStatus = ^TExportsStatus;
  TExportsStatus = set of TExportStatus;

  TScannerMode = (smNoUpdate, smDefault, smForceUpdate);

  TSettings = class
  strict private const
    RegRootKey = 'Software\ProcessMemoryMap\';
    RegKeys: array [0..7] of string = ('ImageColor', 'ImagePartColor',
      'PrivateColor', 'SharedColor', 'MappedColor', 'HeapColor',
      'ThreadColor', 'SystemColor');
  strict private
    FAutoRefresh: Boolean;
    FAutoRefreshDelay: Integer;
    FColors: array [0..7] of TColorRef;
    FCheckStackAddrPCExecutable: Boolean;
    FSearchDifferences: Boolean;
    FShowColors: Boolean;
    FShowDetailedHeap: Boolean;
    FShowFreeRegions: Boolean;
    FSuspendProcess: Boolean;
    FReconnect: Boolean;
    FUseScannerFilter: Boolean;
    FScannerMode: TScannerMode;
    FLoadLines: Boolean;
    FDemangleNames: Boolean;
    FLineSearchLimit: Integer;
    FLineSearchDown: Boolean;
    FLoadStrings: Boolean;
    FStringMinLengh: Integer;
    FShowChildFormsOnTaskBar: Boolean;
    FShowAligns: Boolean;
    FStackOverflowLimit: Integer;
    FSearchLimit: Integer;
    FExportsShowFilter: TExportsStatus;
  private
    procedure SetExportsShowFilter(const Value: TExportsStatus);
  public
    constructor Create;
    function GetColor(const Index: Integer): TColorRef;
    procedure SetColor(const Index: Integer; const Value: TColorRef);
    procedure LoadSettings;
    procedure SaveSettings;
    procedure LoadDefault;
    property AutoReconnect: Boolean read FReconnect write FReconnect;
    property AutoRefresh: Boolean read FAutoRefresh write FAutoRefresh;
    property AutoRefreshDelay: Integer read FAutoRefreshDelay write FAutoRefreshDelay;
    property ImageColor: TColorRef index 0 read GetColor write SetColor;
    property ImagePartColor: TColorRef index 1 read GetColor write SetColor;
    property PrivateColor: TColorRef index 2 read GetColor write SetColor;
    property SharedColor: TColorRef index 3 read GetColor write SetColor;
    property MappedColor: TColorRef index 4 read GetColor write SetColor;
    property HeapColor: TColorRef index 5 read GetColor write SetColor;
    property LoadLines: Boolean read FLoadLines write FLoadLines;
    property DemangleNames: Boolean read FDemangleNames write FDemangleNames;
    property ThreadColor: TColorRef index 6 read GetColor write SetColor;
    property SystemColor: TColorRef index 7 read GetColor write SetColor;
    property SearchDifferences: Boolean read FSearchDifferences write FSearchDifferences;
    property ShowColors: Boolean read FShowColors write FShowColors;
    property ShowDetailedHeap: Boolean read FShowDetailedHeap write FShowDetailedHeap;
    property ShowFreeRegions: Boolean read FShowFreeRegions write FShowFreeRegions;
    property SuspendProcess: Boolean read FSuspendProcess write FSuspendProcess;
    property UseScannerFilter: Boolean read FUseScannerFilter write FUseScannerFilter;
    property ScannerMode: TScannerMode read FScannerMode write FScannerMode;
    property LineSearchLimit: Integer read FLineSearchLimit write FLineSearchLimit;
    property LineSearchDown: Boolean read FLineSearchDown write FLineSearchDown;
    property LoadStrings: Boolean read FLoadStrings write FLoadStrings;
    property StackOverflowLimit: Integer read FStackOverflowLimit write FStackOverflowLimit;
    property StringMinLengh: Integer read FStringMinLengh write FStringMinLengh;
    property ShowChildFormsOnTaskBar: Boolean read FShowChildFormsOnTaskBar write FShowChildFormsOnTaskBar;
    property ShowAligns: Boolean read FShowAligns write FShowAligns;
    property CheckStackAddrPCExecutable: Boolean read FCheckStackAddrPCExecutable write FCheckStackAddrPCExecutable;
    property SearchLimit: Integer read FSearchLimit write FSearchLimit;

    // настройки отсутствующие в диалоге
    property ExportsShowFilter: TExportsStatus read FExportsShowFilter write SetExportsShowFilter;
  end;

  function Settings: TSettings;

var
  DebugElapsedMilliseconds, DebugInitialHeapSize: Int64;

implementation

var
  _Settings: TSettings;

function Settings: TSettings;
begin
  if _Settings = nil then
    _Settings := TSettings.Create;
  Result := _Settings;
end;

{ TSettings }

constructor TSettings.Create;
begin
  LoadSettings;
end;

function TSettings.GetColor(const Index: Integer): TColorRef;
begin
  Result := FColors[Index];
end;

procedure TSettings.LoadDefault;
begin
  ImageColor := RGB(210, 160, 255);
  ImagePartColor := RGB(157, 160, 255);
  PrivateColor := RGB(255, 204, 32);
  SharedColor := RGB(221, 238, 255);
  MappedColor := RGB(176, 215, 255);
  HeapColor := RGB(255, 150, 100);
  ThreadColor := RGB(255, 192, 128);
  SystemColor := RGB(180, 150, 149);
  AutoReconnect := True;
  SearchDifferences := False;
  ShowColors := True;
  ShowDetailedHeap := False;
  ShowFreeRegions := False;
  SuspendProcess := False;
  UseScannerFilter := False;
  ScannerMode := smDefault;
  LoadLines := True;
  LineSearchLimit := 42; // 3 * MaxOpcodeLen
  LineSearchDown := True;
  DemangleNames := True;
  LoadStrings := False;
  StackOverflowLimit := 15;
  StringMinLengh := 6;
  ShowChildFormsOnTaskBar := True;
  ShowAligns := True;
  CheckStackAddrPCExecutable := True;
  AutoRefresh := False;
  AutoRefreshDelay := 5000;
  SearchLimit := 50;
  FExportsShowFilter := [esNormal..esDwarfData];
end;

procedure TSettings.LoadSettings;
var
  R: TRegistry;
  I: Integer;
begin
  R := TRegistry.Create;
  try
    R.RootKey := HKEY_CURRENT_USER;
    if not R.OpenKeyReadOnly(RegRootKey) then
    begin
      LoadDefault;
      Exit;
    end;
    try
      LoadDefault;
      if R.ValueExists('AutoReconnect') then
        AutoReconnect := R.ReadBool('AutoReconnect');
      if R.ValueExists('LoadLines') then
        LoadLines := R.ReadBool('LoadLines');
      if R.ValueExists('DemangleNames') then
        DemangleNames := R.ReadBool('DemangleNames');
      if R.ValueExists('LoadStrings') then
        LoadStrings := R.ReadBool('LoadStrings');
      if R.ValueExists('StringMinLengh') then
        StringMinLengh := R.ReadInteger('StringMinLengh');
      SearchDifferences := R.ReadBool('SearchDifferences');
      ShowColors := R.ReadBool('ShowColors');
      ShowDetailedHeap := R.ReadBool('ShowDetailedHeap');
      ShowFreeRegions := R.ReadBool('ShowFreeRegions');
      SuspendProcess := R.ReadBool('SuspendProcess');
      UseScannerFilter := R.ReadBool('UseScannerFilter');
      ScannerMode := TScannerMode(R.ReadInteger('ScannerMode'));
      if R.ValueExists('ShowChildFormsOnTaskBar') then
        ShowChildFormsOnTaskBar := R.ReadBool('ShowChildFormsOnTaskBar');
      if R.ValueExists('ShowAligns') then
        ShowAligns := R.ReadBool('ShowAligns');
      if R.ValueExists('StackOverflowLimit') then
        StackOverflowLimit := R.ReadInteger('StackOverflowLimit');
      if R.ValueExists('LineSearchDown') then
        LineSearchDown := R.ReadBool('LineSearchDown');
      if R.ValueExists('LineSearchLimit') then
        LineSearchLimit := R.ReadInteger('LineSearchLimit');
      for I := 0 to 7 do
        FColors[I] := R.ReadInteger(RegKeys[I]);
      if R.ValueExists('CheckStackAddrPCExecutable') then
        CheckStackAddrPCExecutable := R.ReadBool('CheckStackAddrPCExecutable');
      if R.ValueExists('AutoRefresh') then
        AutoRefresh := R.ReadBool('AutoRefresh');
      if R.ValueExists('AutoRefreshDelay') then
        AutoRefreshDelay := R.ReadInteger('AutoRefreshDelay');
      if R.ValueExists('SearchLimit') then
        SearchLimit := R.ReadInteger('SearchLimit');
      if R.ValueExists('ExportsShowFilter') then
      begin
        I := R.ReadInteger('ExportsShowFilter');
        FExportsShowFilter := PExportsStatus(@I)^;
      end;
    except
      LoadDefault;
    end;
  finally
    R.Free;
  end;
end;

procedure TSettings.SaveSettings;
var
  R: TRegistry;
  I: Integer;
begin
  R := TRegistry.Create;
  try
    R.RootKey := HKEY_CURRENT_USER;
    if not R.OpenKey(RegRootKey, True) then
      RaiseLastOSError;
    R.WriteBool('AutoReconnect', AutoReconnect);
    R.WriteBool('LoadLines', LoadLines);
    R.WriteBool('DemangleNames', DemangleNames);
    R.WriteBool('LoadStrings', LoadStrings);
    R.WriteInteger('StringMinLengh', StringMinLengh);
    R.WriteBool('SearchDifferences', SearchDifferences);
    R.WriteBool('ShowColors', ShowColors);
    R.WriteBool('ShowDetailedHeap', ShowDetailedHeap);
    R.WriteBool('ShowFreeRegions', ShowFreeRegions);
    R.WriteBool('SuspendProcess', SuspendProcess);
    R.WriteBool('UseScannerFilter', UseScannerFilter);
    R.WriteInteger('ScannerMode', Integer(ScannerMode));
    R.WriteBool('ShowChildFormsOnTaskBar', ShowChildFormsOnTaskBar);
    R.WriteBool('ShowAligns', ShowAligns);
    R.WriteInteger('StackOverflowLimit', StackOverflowLimit);
    R.WriteBool('LineSearchDown', LineSearchDown);
    R.WriteInteger('LineSearchLimit', LineSearchLimit);
    for I := 0 to 7 do
      R.WriteInteger(RegKeys[I], FColors[I]);
    R.WriteBool('CheckStackAddrPCExecutable', CheckStackAddrPCExecutable);
    R.WriteBool('AutoRefresh', AutoRefresh);
    R.WriteInteger('AutoRefreshDelay', AutoRefreshDelay);
    R.WriteInteger('SearchLimit', SearchLimit);
    R.WriteInteger('ExportsShowFilter', PInteger(@FExportsShowFilter)^);
  finally
    R.Free;
  end;
end;

procedure TSettings.SetColor(const Index: Integer; const Value: TColorRef);
begin
  FColors[Index] := Value;
end;

procedure TSettings.SetExportsShowFilter(const Value: TExportsStatus);
begin
  if FExportsShowFilter <> Value then
  begin
    FExportsShowFilter := Value;
    SaveSettings;
  end;
end;

initialization

finalization

  _Settings.Free;

end.
