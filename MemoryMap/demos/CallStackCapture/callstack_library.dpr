library callstack_library;

{ Important note about DLL memory management: ShareMem must be the
  first unit in your library's USES clause AND your project's (select
  Project-View Source) USES clause if your DLL exports any procedures or
  functions that pass strings as parameters or function results. This
  applies to all strings passed to and from your DLL--even those that
  are nested in records and classes. ShareMem is the interface unit to
  the BORLNDMM.DLL shared memory manager, which must be deployed along
  with your DLL. To avoid using BORLNDMM.DLL, pass string information
  using PChar or ShortString parameters. }

uses
  Windows,
  System.SysUtils,
  System.Classes,
  CallStackTraceUtils in 'CallStackTraceUtils.pas',
  MemoryMap.DebugMapData in '..\..\MemoryMap.DebugMapData.pas',
  MemoryMap.ImageHlp in '..\..\MemoryMap.ImageHlp.pas',
  MemoryMap.NtDll in '..\..\MemoryMap.NtDll.pas',
  MemoryMap.PEImage in '..\..\MemoryMap.PEImage.pas',
  MemoryMap.Symbols in '..\..\MemoryMap.Symbols.pas',
  MemoryMap.Utils in '..\..\MemoryMap.Utils.pas';

{$R *.res}

procedure InternalShowCallStack;
var
  S: TStringList;
begin
  S := GetCallStack;
  try
    MessageBox(0, PChar(S.Text), '', MB_ICONINFORMATION);
  finally
    S.Free;
  end;
end;

procedure ShowCallStack; stdcall;
begin
  InternalShowCallStack;
end;

exports
  ShowCallStack;

begin
end.
