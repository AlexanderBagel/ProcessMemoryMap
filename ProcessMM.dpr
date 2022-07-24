////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : ProcessMM.dpr
//  * Author    : ��������� (Rouse_) ������
//  * Copyright : � Fangorn Wizards Lab 1998 - 2022.
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
  MemoryMap.Workset in 'MemoryMap\MemoryMap.Workset.pas',
  uAbout in 'uAbout.pas' {dlgAbout},
  uMemoryMapListInfo in 'uMemoryMapListInfo.pas' {dlgMemoryMapListInfo},
  uMemoryMapListInfoSettings in 'uMemoryMapListInfoSettings.pas' {dlgMemoryMapListInfoSettings},
  distorm in 'distorm\distorm.pas',
  MemoryMap.DebugMapData in 'MemoryMap\MemoryMap.DebugMapData.pas',
  uProcessReconnect in 'uProcessReconnect.pas',
  MemoryMap.ImageHlp in 'MemoryMap\MemoryMap.ImageHlp.pas',
  mnemonics in 'distorm\mnemonics.pas',
  uKnownData in 'uKnownData.pas' {dlgKnownData};

{$R *.res}

// ��������� SINGLE_INSTANCE �� ���� ��������� 32 ������� ���������� 64 ������ ������
// ������ ��� �������
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
    // ���� OS 64-������, �� ��������� ��������������� ����������,
    // � ���� �������� ������ ����� �������� ��� ������ � 32-������ �����.
    // ������ ���� 64-������ ���������� �������������� �� ��� ������
    // �� ������� � ���� �� ��� ����� �� �����, �������� �����������.
    // ����� ���� �������� ���������� ��� ������ �� �����������.
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
