**English** | [Русский](README.RU.md)

Show Delphi/Lazarus Unit Init Order
================

A demonstration of working with the TDebugMap, TRawPEImage, TRawScannerSymbolStorage and TDisassembler classes.
The demo outputs the list of used units in the order of their initialization, including calls to class constructors/destructors.

### Appearance:

![1](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/CommonDemo/ShowInitOrder/img/1.png?raw=true "Appearance")

### How it works

Delphi debug information, specifically the MAP file, does not contain the address of the unit initialization table, so the LoadDelphiUnitInitOrder function is implemented.
It disassembles the application entry point and searches for a call to the "@InitExe" or "SysInit.@InitExe" function.
That function receives the address of the initialization table header as its input; once it is obtained, the table is parsed.

In the Lazarus version (the LoadLazarusUnitInitOrder function), the address of the initialization table is available from the start in the COFF debug symbols under the name "INITFINAL".
However, unlike Delphi, this initialization table does not contain calls to class constructors/destructors.
They are located in the initialization function of the unit where the class is declared. Therefore, to detect class constructor calls, each
initialization/finalization procedure is disassembled in order to search for such calls.
For now, the analysis is based only on COFF information, and calls to ordinary class constructors/destructors may end up in the result by mistake.
Once the full DWARF information package is connected, such erroneous calls should be excluded.
