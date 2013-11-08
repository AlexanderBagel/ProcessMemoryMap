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
  uDumpDisplayUtils,
  uDisplayUtils;

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
var
  ThumbPos: Integer;
begin
  edProperties.Lines.BeginUpdate;
  try
    ThumbPos := SendMessage(edProperties.Handle, EM_GETFIRSTVISIBLELINE, 0, 0);
    edProperties.Lines.Clear;
    StartQuery(CurerntAddr);
    SendMessage(edProperties.Handle, EM_LINESCROLL, 0, ThumbPos);
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
const
  KUSER_SHARED_DATA_ADDR = Pointer($7FFE0000);
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

      if Value = KUSER_SHARED_DATA_ADDR then
      begin
        Add(DumpKUserSharedData(Process, Value));
        Exit;
      end;

      {$IFDEF WIN64}
      if Value = MemoryMapCore.PebWow64BaseAddress then
      begin
        Add(DumpPEB32(Process, Value));
        Exit;
      end;
      {$ENDIF}

      if Value = MemoryMapCore.PebBaseAddress then
      begin
        {$IFDEF WIN32}
        Add(DumpPEB32(Process, Value));
        {$ELSE}
        Add(DumpPEB64(Process, Value));
        {$ENDIF}
        Exit;
      end;

      if CheckPEImage(Process, Value) then
      begin
        Add(DumpPEHeader(Process, Value));
        Exit;
      end;

      if MemoryMapCore.GetRegionIndex(Value, Index) then
      begin
        ARegion := MemoryMapCore.GetRegionAtUnfilteredIndex(Index);
        if (ARegion.RegionType = rtThread) and
          (ARegion.Thread.Flag = tiTEB) then
        begin
          {$IFDEF WIN32}
          Add(DumpThread32(Process, Value));
          {$ELSE}
          if ARegion.Thread.Wow64 then
            Add(DumpThread32(Process, Value))
          else
            Add(DumpThread64(Process, Value));
          {$ENDIF}
          Exit;
        end;
      end;

      {$IFDEF WIN64}
      if Value = Pointer(MemoryMapCore.PEBWow64.ProcessParameters) then
      begin
        Add(DumpProcessParameters32(Process, Value));
        Exit;
      end;
      {$ENDIF}

      if Value = MemoryMapCore.PEB.ProcessParameters then
      begin
        {$IFDEF WIN32}
        Add(DumpProcessParameters32(Process, Value));
        {$ELSE}
        Add(DumpProcessParameters64(Process, Value));
        {$ENDIF}
        Exit;
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
