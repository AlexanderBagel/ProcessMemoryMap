program CallStackCapture;

uses
  Vcl.Forms,
  Unit1 in 'Unit1.pas' {Form1},
  CallStackTraceUtils in 'CallStackTraceUtils.pas',
  MemoryMap.DebugMapData in '..\..\MemoryMap.DebugMapData.pas',
  MemoryMap.PEImage in '..\..\MemoryMap.PEImage.pas',
  MemoryMap.Utils in '..\..\MemoryMap.Utils.pas',
  MemoryMap.ImageHlp in '..\..\MemoryMap.ImageHlp.pas',
  MemoryMap.NtDll in '..\..\MemoryMap.NtDll.pas',
  MemoryMap.Symbols in '..\..\MemoryMap.Symbols.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
