program ProcessMM;

uses
  Winapi.Windows,
  Winapi.Messages,
  Vcl.Forms,
  System.SysUtils,
  uProcessMM in 'uProcessMM.pas' {dlgProcessMM},
  uSelectProcess in 'uSelectProcess.pas' {dlgSelectProcess},
  uExportList in 'uExportList.pas' {dlgExportList},
  uSettings in 'uSettings.pas' {dlgSettings},
  uUtils in 'uUtils.pas',
  uDisplayUtils in 'uDisplayUtils.pas',
  uRegionProperties in 'uRegionProperties.pas' {dlgRegionProps},
  uSelectAddress in 'uSelectAddress.pas' {dlgSelectAddress},
  uFindData in 'uFindData.pas' {dlgFindData},
  uComparator in 'uComparator.pas' {dlgComparator},
  uProgress in 'uProgress.pas' {dlgProgress},
  uDump in 'uDump.pas',
  uDumpDisplayUtils in 'uDumpDisplayUtils.pas',
  uIPC in 'uIPC.pas',
  MemoryMap.Core in 'MemoryMap\MemoryMap.Core.pas',
  MemoryMap.Heaps in 'MemoryMap\MemoryMap.Heaps.pas',
  MemoryMap.NtDll in 'MemoryMap\MemoryMap.NtDll.pas',
  MemoryMap.PEImage in 'MemoryMap\MemoryMap.PEImage.pas',
  MemoryMap.RegionData in 'MemoryMap\MemoryMap.RegionData.pas',
  MemoryMap.Symbols in 'MemoryMap\MemoryMap.Symbols.pas',
  MemoryMap.Threads in 'MemoryMap\MemoryMap.Threads.pas',
  MemoryMap.Utils in 'MemoryMap\MemoryMap.Utils.pas',
  MemoryMap.Workset in 'MemoryMap\MemoryMap.Workset.pas';

{$R *.res}

// ƒиректива SINGLE_INSTANCE не дает запускать 32 битному приложению 64 битный аналог
// —угубо дл€ отладки
{$IFDEF SINGLE_INSTANCE}
begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TdlgProcessMM, dlgProcessMM);
  Application.Run;

{$ELSE}

{$IFDEF WIN32}

  {$IFDEF DEBUG}
    {$R 'win64debug.res' 'win64debug.rc'}
  {$ELSE}
    {$R 'win64release.res' 'win64release.rc'}
  {$ENDIF}

var
  IPC: TIPCServer;
  New64AppHandle: THandle;
  Msg: TMsg;
  Path: string;
{$ENDIF} // {$IFDEF WIN32}
begin
  {$IFDEF WIN32}
  if Is64OS then
  begin
    // ≈сли OS 64-битна€, то запускаем соответствующее приложение,
    // а сами остаемс€ висеть чтобы отдавать ему данные о 32-битных
    // нит€х и кучах.
    // ѕравда если 64-битное приложение перезапуститс€ из под админа
    // то доступа к нему мы уже иметь не будем, придетс€ закрыватьс€.
    // ѕотом этот механизм пересмотрю как нибудь по нормальному.
    IPC := TIPCServer.Create;
    try
      Path := ExtractFilePath(ParamStr(0)) + 'processmm64.exe';
      New64AppHandle := Run64App(Path, IPC.MMFName);
      if New64AppHandle <> 0 then
      try
        while WaitForSingleObject(New64AppHandle, 50) = WAIT_TIMEOUT do
        begin
          while PeekMessage(Msg, 0, 0, 0, PM_REMOVE) do
          begin
            TranslateMessage(Msg);
            DispatchMessage(Msg);
          end;
        end;
      finally
        CloseHandle(New64AppHandle);
      end;
    finally
      DeleteFile(Path);
      IPC.Free;
    end;
    if New64AppHandle <> 0 then Exit;
  end;
  {$ENDIF} // {$IFDEF WIN32}
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TdlgProcessMM, dlgProcessMM);
  Application.Run;
{$ENDIF} // {$IFDEF SINGLE_INSTANCE} -> {$ELSE}
end.
