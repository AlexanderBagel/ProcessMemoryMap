////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : ProcessMM.dpr
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2022.
//  * Version   : 1.0.14
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

program ProcessMM;

uses
  Winapi.Windows,
  Winapi.Messages,
  Vcl.Forms,
  System.SysUtils,
  uProcessMM in 'src\gui\uProcessMM.pas' {dlgProcessMM},
  uSelectProcess in 'src\gui\uSelectProcess.pas' {dlgSelectProcess},
  uExportList in 'src\gui\uExportList.pas' {dlgExportList},
  uSettings in 'src\gui\uSettings.pas' {dlgSettings},
  uUtils in 'src\uUtils.pas',
  uDisplayUtils in 'src\uDisplayUtils.pas',
  uRegionProperties in 'src\gui\uRegionProperties.pas' {dlgRegionProps},
  uSelectAddress in 'src\gui\uSelectAddress.pas' {dlgSelectAddress},
  uFindData in 'src\gui\uFindData.pas' {dlgFindData},
  uComparator in 'src\gui\uComparator.pas' {dlgComparator},
  uProgress in 'src\gui\uProgress.pas' {dlgProgress},
  uDump in 'src\uDump.pas',
  uDumpDisplayUtils in 'src\uDumpDisplayUtils.pas',
  uIPC in 'src\uIPC.pas',
  MemoryMap.Core in 'MemoryMap\MemoryMap.Core.pas',
  MemoryMap.Heaps in 'MemoryMap\MemoryMap.Heaps.pas',
  MemoryMap.NtDll in 'MemoryMap\MemoryMap.NtDll.pas',
  MemoryMap.PEImage in 'MemoryMap\MemoryMap.PEImage.pas',
  MemoryMap.RegionData in 'MemoryMap\MemoryMap.RegionData.pas',
  MemoryMap.Symbols in 'MemoryMap\MemoryMap.Symbols.pas',
  MemoryMap.Threads in 'MemoryMap\MemoryMap.Threads.pas',
  MemoryMap.Utils in 'MemoryMap\MemoryMap.Utils.pas',
  MemoryMap.Workset in 'MemoryMap\MemoryMap.Workset.pas',
  uAbout in 'src\gui\uAbout.pas' {dlgAbout},
  uMemoryMapListInfo in 'src\gui\uMemoryMapListInfo.pas' {dlgMemoryMapListInfo},
  uMemoryMapListInfoSettings in 'src\gui\uMemoryMapListInfoSettings.pas' {dlgMemoryMapListInfoSettings},
  distorm in 'distorm\distorm.pas',
  MemoryMap.DebugMapData in 'MemoryMap\MemoryMap.DebugMapData.pas',
  uProcessReconnect in 'src\uProcessReconnect.pas',
  MemoryMap.ImageHlp in 'MemoryMap\MemoryMap.ImageHlp.pas',
  mnemonics in 'distorm\mnemonics.pas',
  uKnownData in 'src\gui\uKnownData.pas' {dlgKnownData},
  uPatchDetect in 'src\gui\uPatchDetect.pas' {dlgPatches},
  RawScanner.Analyzer in 'RawScanner\RawScanner.Analyzer.pas',
  RawScanner.ApiSet in 'RawScanner\RawScanner.ApiSet.pas',
  RawScanner.Disassembler in 'RawScanner\RawScanner.Disassembler.pas',
  RawScanner.Filter in 'RawScanner\RawScanner.Filter.pas',
  RawScanner.LoaderData in 'RawScanner\RawScanner.LoaderData.pas',
  RawScanner.Logger in 'RawScanner\RawScanner.Logger.pas',
  RawScanner.Image.Pe in 'RawScanner\RawScanner.Image.Pe.pas',
  RawScanner.Types in 'RawScanner\RawScanner.Types.pas',
  RawScanner.Utils in 'RawScanner\RawScanner.Utils.pas',
  RawScanner.Wow64 in 'RawScanner\RawScanner.Wow64.pas',
  RawScanner.Core in 'RawScanner\RawScanner.Core.pas',
  RawScanner.SymbolStorage in 'RawScanner\RawScanner.SymbolStorage.pas',
  RawScanner.ActivationContext in 'RawScanner\RawScanner.ActivationContext.pas',
  FWProgressBar in 'Controls\FWProgressBar.pas',
  pmm_plugin in 'plugins\include\pmm_plugin.pas',
  uPluginManager in 'src\uPluginManager.pas',
  uDebugInfoDlg in 'src\gui\uDebugInfoDlg.pas' {dlgDbgInfo},
  Shell.TaskBarListProgress in 'Controls\Shell.TaskBarListProgress.pas',
  RawScanner.X64Gates in 'RawScanner\RawScanner.X64Gates.pas',
  uStringsViewer in 'src\gui\uStringsViewer.pas' {dlgStringsViewer},
  ScaledCtrls in 'Controls\ScaledCtrls.pas',
  uBaseForm in 'src\gui\uBaseForm.pas' {BaseAppForm},
  RawScanner.CoffDwarf in 'RawScanner\RawScanner.CoffDwarf.pas',
  uCallStack in 'src\gui\uCallStack.pas' {dlgCallStack},
  RawScanner.Elf in 'RawScanner\RawScanner.Elf.pas',
  RawScanner.Image.Elf in 'RawScanner\RawScanner.Image.Elf.pas',
  RawScanner.MapGenerator in 'RawScanner\RawScanner.MapGenerator.pas',
  RawScanner.AbstractImage in 'RawScanner\RawScanner.AbstractImage.pas',
  RawScanner.Image.Coff in 'RawScanner\RawScanner.Image.Coff.pas';

{$R *.res}

// Директива SINGLE_INSTANCE не дает запускать 32 битному приложению 64 битный аналог
// Сугубо для отладки
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
  if Is64OS and not FindCmdLineSwitch('32', ['x'], True) then
  begin
    // Если OS 64-битная, то запускаем соответствующее приложение,
    // а сами остаемся висеть чтобы отдавать ему данные о 32-битных кучах.
    // Правда если 64-битное приложение перезапустится из под админа
    // то доступа к нему мы уже иметь не будем, придется закрываться.
    // Потом этот механизм пересмотрю как нибудь по нормальному.
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
