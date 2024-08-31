program ShowInitOrder;

uses
  Vcl.Forms,
  Unit1 in 'Unit1.pas' {frmShowInitOrder},
  UnitInitOrderTracer in 'UnitInitOrderTracer.pas',
  MemoryMap.DebugMapData in '..\..\MemoryMap\MemoryMap.DebugMapData.pas',
  MemoryMap.ImageHlp in '..\..\MemoryMap\MemoryMap.ImageHlp.pas',
  MemoryMap.NtDll in '..\..\MemoryMap\MemoryMap.NtDll.pas',
  MemoryMap.PEImage in '..\..\MemoryMap\MemoryMap.PEImage.pas',
  MemoryMap.Symbols in '..\..\MemoryMap\MemoryMap.Symbols.pas',
  MemoryMap.Utils in '..\..\MemoryMap\MemoryMap.Utils.pas',
  RawScanner.CoffDwarf in '..\..\RawScanner\RawScanner.CoffDwarf.pas',
  RawScanner.Disassembler in '..\..\RawScanner\RawScanner.Disassembler.pas',
  RawScanner.SymbolStorage in '..\..\RawScanner\RawScanner.SymbolStorage.pas',
  RawScanner.Types in '..\..\RawScanner\RawScanner.Types.pas',
  distorm in '..\..\distorm\distorm.pas',
  mnemonics in '..\..\distorm\mnemonics.pas',
  RawScanner.Logger in '..\..\RawScanner\RawScanner.Logger.pas',
  RawScanner.Utils in '..\..\RawScanner\RawScanner.Utils.pas',
  RawScanner.Wow64 in '..\..\RawScanner\RawScanner.Wow64.pas',
  RawScanner.X64Gates in '..\..\RawScanner\RawScanner.X64Gates.pas',
  RawScanner.ApiSet in '..\..\RawScanner\RawScanner.ApiSet.pas',
  RawScanner.Image.Pe in '..\..\RawScanner\RawScanner.Image.Pe.pas',
  RawScanner.AbstractImage in '..\..\RawScanner\RawScanner.AbstractImage.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TfrmShowInitOrder, frmShowInitOrder);
  Application.Run;
end.
