program raw_image;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  Windows,
  System.SysUtils,
  Classes,
  MMSystem,
  Math,
  System.TypInfo,
  Generics.Collections,
  RawScanner.ModulesData in '..\RawScanner.ModulesData.pas',
  RawScanner.Analyzer in '..\RawScanner.Analyzer.pas',
  RawScanner.Wow64 in '..\RawScanner.Wow64.pas',
  RawScanner.LoaderData in '..\RawScanner.LoaderData.pas',
  RawScanner.Types in '..\RawScanner.Types.pas',
  RawScanner.Utils in '..\RawScanner.Utils.pas',
  distorm in '..\..\distorm\distorm.pas',
  mnemonics in '..\..\distorm\mnemonics.pas',
  RawScanner.Disassembler in '..\RawScanner.Disassembler.pas',
  RawScanner.ApiSet in '..\RawScanner.ApiSet.pas',
  RawScanner.Logger in '..\RawScanner.Logger.pas',
  RawScanner.Filter in '..\RawScanner.Filter.pas',
  display_utils in 'display_utils.pas',
  RawScanner.ActivationContext in '..\RawScanner.ActivationContext.pas',
  RawScanner.Core in '..\RawScanner.Core.pas',
  RawScanner.SymbolStorage in '..\RawScanner.SymbolStorage.pas',
  RawScanner.X64Gates in '..\RawScanner.X64Gates.pas',
  RawScanner.CoffDwarf in '..\RawScanner.CoffDwarf.pas';

var
  AProcessID: DWORD;
  I: Integer;
begin
  Writeln(Win32MajorVersion, '.', Win32MinorVersion, '.', Win32BuildNumber, '.',
    Win32Platform, ' ', Win32CSDVersion);

  // заменить PID на любой другой сторонний процесс!!!
  AProcessID := GetCurrentProcessId;

  RawScannerLogger.OnLog := OnLog;

  RawScannerCore.InitFromProcess(AProcessID);

  Writeln('Loader32: ', RawScannerCore.InitializationResult.Loader32);
  Writeln('Loader64: ', RawScannerCore.InitializationResult.Loader64);
  Writeln('Use64AddrMode: ', Wow64Support.Use64AddrMode);


  for I := 0 to RawScannerCore.Modules.Items.Count - 1 do
    ShowModuleInfo(I, RawScannerCore.Modules.Items[I]);

  Filter := TFilter.Create;
  try

    try
      RawScannerCore.Analizer.Analyze(
        // обработка вывода перехваченых таблиц импорта/экспорта
        ProcessTableHook,
        // обработка вывода перехватчиков установленых непосредственно в коде функций
        ProcessCodeHook
        );

    except
      on E: Exception do
        Writeln(E.ClassName, ': ', E.Message);
    end;

    Writeln;

    // вывод результатов работы фильтра
    var UncheckedCount := Filter.GetUncheckedCount;
    Writeln('Total filtered: ', GlobalFiltered);
    Writeln('Total filter unchecked: ', UncheckedCount);
    Writeln('Total filter checked: ', GlobalChecked);

  finally
    Filter.Free;
  end;

  Writeln;
  Writeln('DONE!');
  readln;
end.


