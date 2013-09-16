unit uRegionProperties;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, Vcl.ComCtrls, Winapi.PsAPI, Vcl.Menus,

  MemoryMap.Utils,
  MemoryMap.Core,
  MemoryMap.RegionData,
  MemoryMap.Symbols,
  MemoryMap.Threads,
  MemoryMap.NtDll;

type
  TdlgRegionProps = class(TForm)
    edProperties: TRichEdit;
    PopupMenu1: TPopupMenu;
    mnuCopy: TMenuItem;
    N1: TMenuItem;
    mnuRefresh: TMenuItem;
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure mnuCopyClick(Sender: TObject);
    procedure FormKeyPress(Sender: TObject; var Key: Char);
    procedure mnuRefreshClick(Sender: TObject);
  private
    ACloseAction: TCloseAction;
    Process: THandle;
    CurerntAddr: Pointer;
    procedure Add(const Value: string);
    procedure StartQuery(Value: Pointer);
    procedure ShowInfoFromMBI(MBI: TMemoryBasicInformation;
      Address: Pointer);
  public
    procedure ShowModalPropertyAtAddr(Value: Pointer);
    procedure ShowPropertyAtAddr(Value: Pointer);
  end;

var
  dlgRegionProps: TdlgRegionProps;

implementation

uses
  uUtils,
  uSettings,
  uHexUtils,
  uDisplayUtils;

{
w8 _KUSER_SHARED_DATA
для w7 тут
dt _KUSER_SHARED_DATA

   +0x000 TickCountLowDeprecated : Uint4B
   +0x004 TickCountMultiplier : Uint4B
   +0x008 InterruptTime    : _KSYSTEM_TIME
   +0x014 SystemTime       : _KSYSTEM_TIME
   +0x020 TimeZoneBias     : _KSYSTEM_TIME
   +0x02c ImageNumberLow   : Uint2B
   +0x02e ImageNumberHigh  : Uint2B
   +0x030 NtSystemRoot     : [260] Wchar
   +0x238 MaxStackTraceDepth : Uint4B
   +0x23c CryptoExponent   : Uint4B
   +0x240 TimeZoneId       : Uint4B
   +0x244 LargePageMinimum : Uint4B
   +0x248 AitSamplingValue : Uint4B
   +0x24c AppCompatFlag    : Uint4B
   +0x250 RNGSeedVersion   : Uint8B
   +0x258 GlobalValidationRunlevel : Uint4B
   +0x25c Reserved2        : [2] Uint4B
   +0x264 NtProductType    : _NT_PRODUCT_TYPE
   +0x268 ProductTypeIsValid : UChar
   +0x269 Reserved0        : [1] UChar
   +0x26a NativeProcessorArchitecture : Uint2B
   +0x26c NtMajorVersion   : Uint4B
   +0x270 NtMinorVersion   : Uint4B
   +0x274 ProcessorFeatures : [64] UChar
   +0x2b4 Reserved1        : Uint4B
   +0x2b8 Reserved3        : Uint4B
   +0x2bc TimeSlip         : Uint4B
   +0x2c0 AlternativeArchitecture : _ALTERNATIVE_ARCHITECTURE_TYPE
   +0x2c4 AltArchitecturePad : [1] Uint4B
   +0x2c8 SystemExpirationDate : _LARGE_INTEGER
   +0x2d0 SuiteMask        : Uint4B
   +0x2d4 KdDebuggerEnabled : UChar
   +0x2d5 MitigationPolicies : UChar
   +0x2d5 NXSupportPolicy  : Pos 0, 2 Bits
   +0x2d5 SEHValidationPolicy : Pos 2, 2 Bits
   +0x2d5 CurDirDevicesSkippedForDlls : Pos 4, 2 Bits
   +0x2d5 Reserved         : Pos 6, 2 Bits
   +0x2d6 Reserved6        : [2] UChar
   +0x2d8 ActiveConsoleId  : Uint4B
   +0x2dc DismountCount    : Uint4B
   +0x2e0 ComPlusPackage   : Uint4B
   +0x2e4 LastSystemRITEventTickCount : Uint4B
   +0x2e8 NumberOfPhysicalPages : Uint4B
   +0x2ec SafeBootMode     : UChar
   +0x2ed Reserved12       : [3] UChar
   +0x2f0 SharedDataFlags  : Uint4B
   +0x2f0 DbgErrorPortPresent : Pos 0, 1 Bit
   +0x2f0 DbgElevationEnabled : Pos 1, 1 Bit
   +0x2f0 DbgVirtEnabled   : Pos 2, 1 Bit
   +0x2f0 DbgInstallerDetectEnabled : Pos 3, 1 Bit
   +0x2f0 DbgLkgEnabled    : Pos 4, 1 Bit
   +0x2f0 DbgDynProcessorEnabled : Pos 5, 1 Bit
   +0x2f0 DbgConsoleBrokerEnabled : Pos 6, 1 Bit
   +0x2f0 SpareBits        : Pos 7, 25 Bits
   +0x2f4 DataFlagsPad     : [1] Uint4B
   +0x2f8 TestRetInstruction : Uint8B
   +0x300 Reserved9        : Uint4B
   +0x304 Reserved10       : Uint4B
   +0x308 SystemCallPad    : [3] Uint8B
   +0x320 TickCount        : _KSYSTEM_TIME
   +0x320 TickCountQuad    : Uint8B
   +0x320 ReservedTickCountOverlay : [3] Uint4B
   +0x32c TickCountPad     : [1] Uint4B
   +0x330 Cookie           : Uint4B
   +0x334 CookiePad        : [1] Uint4B
   +0x338 ConsoleSessionForegroundProcessId : Int8B
   +0x340 TimeUpdateSequence : Uint8B
   +0x348 LastTimeUpdateQpcValue : Uint8B
   +0x350 LastInterruptTimeUpdateQpcValue : Uint8B
   +0x358 QpcTimeIncrement : Uint8B
   +0x360 QpcTimeIncrement32 : Uint4B
   +0x364 Reserved8        : [7] Uint4B
   +0x380 UserModeGlobalLogger : [16] Uint2B
   +0x3a0 ImageFileExecutionOptions : Uint4B
   +0x3a4 LangGenerationCount : Uint4B
   +0x3a8 InterruptTimeBias : Uint8B
   +0x3b0 TscQpcBias       : Uint8B
   +0x3b8 ActiveProcessorCount : Uint4B
   +0x3bc ActiveGroupCount : UChar
   +0x3bd QpcTimeIncrementShift : UChar
   +0x3be TscQpcData       : Uint2B
   +0x3be TscQpcEnabled    : UChar
   +0x3bf TscQpcShift      : UChar
   +0x3c0 XState           : _XSTATE_CONFIGURATION
}

{$R *.dfm}

{ TdlgRegionProps }

procedure TdlgRegionProps.Add(const Value: string);
begin
  edProperties.Lines.Add(Value);
end;

procedure TdlgRegionProps.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  Action := ACloseAction;
end;

procedure TdlgRegionProps.FormKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #27 then Close;
end;

procedure TdlgRegionProps.mnuCopyClick(Sender: TObject);
begin
  edProperties.CopyToClipboard;
end;

procedure TdlgRegionProps.mnuRefreshClick(Sender: TObject);
begin
  edProperties.Lines.BeginUpdate;
  try
    edProperties.Lines.Clear;
    StartQuery(CurerntAddr);
  finally
    edProperties.Lines.EndUpdate;;
  end;
end;

procedure TdlgRegionProps.ShowInfoFromMBI(MBI: TMemoryBasicInformation;
  Address: Pointer);
var
  OwnerName: array [0..MAX_PATH - 1] of Char;
  Path, DescriptionAtAddr: string;
  Symbols: TSymbols;
begin
  Add('AllocationBase: ' + UInt64ToStr(ULONG_PTR(MBI.AllocationBase)));
  Add('RegionSize: ' + SizeToStr(MBI.RegionSize));
  Add('Type: ' + ExtractRegionTypeString(MBI));
  Add('Access: ' + ExtractAccessString(MBI.Protect));
  Add('Initail Access: ' + ExtractInitialAccessString(MBI.AllocationProtect));
  if GetMappedFileName(Process, MBI.AllocationBase,
    @OwnerName[0], MAX_PATH) > 0 then
  begin
    Path := NormalizePath(string(OwnerName));
    Add('Mapped file: ' + Path);
    if CheckPEImage(Process, MBI.AllocationBase) then
      Add('    Executable');
    Symbols := TSymbols.Create(Process);
    try
      DescriptionAtAddr := Symbols.GetDescriptionAtAddr(
        ULONG_PTR(Address), ULONG_PTR(MBI.AllocationBase), Path);
      if DescriptionAtAddr <> '' then
        Add('Function: ' + DescriptionAtAddr);
    finally
      Symbols.Free;
    end;
  end;
end;

procedure TdlgRegionProps.ShowModalPropertyAtAddr(Value: Pointer);
begin
  ACloseAction := caHide;
  StartQuery(Value);
  ShowModal;
  Close;
end;

procedure TdlgRegionProps.ShowPropertyAtAddr(Value: Pointer);
begin
  ACloseAction := caFree;
  StartQuery(Value);
  Show;
end;

procedure TdlgRegionProps.StartQuery(Value: Pointer);
var
  MBI: TMemoryBasicInformation;
  dwLength: Cardinal;
  ProcessLock: TProcessLockHandleList;
  Index: Integer;
  ARegion: TRegionData;
begin
  CurerntAddr := Value;
  ProcessLock := nil;
  Process := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ or
    PROCESS_VM_OPERATION, False, MemoryMapCore.PID);
  if Process = 0 then
    RaiseLastOSError;
  try
    edProperties.Lines.Add('Info at address: ' + UInt64ToStr(ULONG_PTR(Value)));
    if Settings.SuspendProcess then
      ProcessLock := SuspendProcess(MemoryMapCore.PID);
    try
      dwLength := SizeOf(TMemoryBasicInformation);
      if VirtualQueryEx(Process,
         Pointer(Value), MBI, dwLength) <> dwLength then
         RaiseLastOSError;
       ShowInfoFromMBI(MBI, Value);
       if Value = MemoryMapCore.PebBaseAddress then
       begin
         Add(DumpPEBWow64(Process, Value));
         Exit;
       end;
       if MemoryMapCore.GetRegionIndex(Value, Index) then
       begin
         ARegion := MemoryMapCore.GetRegionAtUnfilteredIndex(Index);
         if (ARegion.RegionType = rtThread) and
           (ARegion.Thread.Flag = tiExceptionList) then
         begin
           Add(DumpThreadWow64(Process, Value));
           Exit;
         end;
       end;
       Add(DumpMemory(Process, Value));
    finally
      edProperties.SelStart := 0;
      if Settings.SuspendProcess then
        ResumeProcess(ProcessLock);
    end;
  finally
    CloseHandle(Process);
  end;
end;

end.
