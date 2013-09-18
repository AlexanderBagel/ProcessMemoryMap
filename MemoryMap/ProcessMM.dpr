program ProcessMM;

uses
  Vcl.Forms,
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

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TdlgProcessMM, dlgProcessMM);
  Application.Run;
end.
