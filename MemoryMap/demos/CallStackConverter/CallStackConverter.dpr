program CallStackConverter;

uses
  Vcl.Forms,
  Unit1 in 'Unit1.pas' {dlgStackConverter},
  MemoryMap.DebugMapData in '..\..\MemoryMap.DebugMapData.pas',
  MemoryMap.ImageHlp in '..\..\MemoryMap.ImageHlp.pas',
  MemoryMap.NtDll in '..\..\MemoryMap.NtDll.pas',
  MemoryMap.PEImage in '..\..\MemoryMap.PEImage.pas',
  MemoryMap.Utils in '..\..\MemoryMap.Utils.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TdlgStackConverter, dlgStackConverter);
  Application.Run;
end.
