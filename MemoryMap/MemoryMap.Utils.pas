////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : MemoryMap
//  * Unit Name : MemoryMap.Utils
//  * Purpose   : Различные вспомогательные процедуры и функции
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2013.
//  * Version   : 1.0
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit MemoryMap.Utils;

interface

uses
  Winapi.Windows,
  Winapi.ImageHlp,
  Winapi.TlHelp32,
  Generics.Collections,
  MemoryMap.NtDll;

  function IsWow64(hProcess: THandle): BOOL;
  function Is64OS: Boolean;
  function NormalizePath(const Value: string): string;
  function AlignedSectionSize(const ImageInfo: LOADED_IMAGE;
    const Value: NativeUInt): NativeUInt;
  function CheckAddr(Value: NativeUInt): Boolean; overload;
  function CheckAddr(Value: Pointer): Boolean; overload;
  function IsExecute(const Value: DWORD): Boolean;
  function IsWrite(const Value: DWORD): Boolean;
  function CheckPEImage(hProcess: THandle; ImageBase: Pointer): Boolean;

type
  TProcessLockHandleList = TList<THandle>;
  function SuspendProcess(PID: DWORD): TProcessLockHandleList;
  procedure ResumeProcess(Value: TProcessLockHandleList);

implementation


function IsWow64(hProcess: THandle): BOOL;
var
  IsWow64Process: function(hProcess: THandle; var Wow64Process: BOOL): BOOL; stdcall;
begin
  Result := False;
  IsWow64Process := GetProcAddress(GetModuleHandle(kernel32), 'IsWow64Process');
  if Assigned(IsWow64Process) then
    if not IsWow64Process(hProcess, Result) then
      Result := False;
end;

function Is64OS: Boolean;
{$IFDEF WIN64}
begin
  Result := True;
{$ELSE}
asm
  xor eax, eax
  mov  ecx, fs:[$c0]
  test ecx, ecx
  setnz al
{$ENDIF}
end;


function NormalizePath(const Value: string): string;
const
  OBJ_CASE_INSENSITIVE         = $00000040;
  STATUS_SUCCESS               = 0;
  FILE_SYNCHRONOUS_IO_NONALERT = $00000020;
  FILE_READ_DATA = 1;
  ObjectNameInformation = 1;
  DriveNameSize = 4;
  VolumeCount = 26;
  DriveTotalSize = DriveNameSize * VolumeCount;
var
  US: UNICODE_STRING;
  OA: OBJECT_ATTRIBUTES;
  IO: IO_STATUS_BLOCK;
  hFile: THandle;
  NTSTAT, dwReturn: DWORD;
  ObjectNameInfo: TOBJECT_NAME_INFORMATION;
  Buff, Volume: string;
  I, Count, dwQueryLength: Integer;
  lpQuery: array [0..MAX_PATH - 1] of Char;
  AnsiResult: AnsiString;
begin
  Result := Value;
  // Подготавливаем параметры для вызова ZwOpenFile
  RtlInitUnicodeString(@US, StringToOleStr(Value));
  // Аналог макроса InitializeObjectAttributes
  FillChar(OA, SizeOf(OBJECT_ATTRIBUTES), #0);
  OA.Length := SizeOf(OBJECT_ATTRIBUTES);
  OA.ObjectName := @US;
  OA.Attributes := OBJ_CASE_INSENSITIVE;
  // Функция ZwOpenFile спокойно открывает файлы, путь к которым представлен
  // с использованием символьных ссылок, например:
  // \SystemRoot\System32\ntdll.dll
  // \??\C:\Windows\System32\ntdll.dll
  // \Device\HarddiskVolume1\WINDOWS\system32\ntdll.dll
  // Поэтому будем использовать ее для получения хэндла
  NTSTAT := ZwOpenFile(@hFile, FILE_READ_DATA or SYNCHRONIZE, @OA, @IO,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,
    FILE_SYNCHRONOUS_IO_NONALERT);
  if NTSTAT = STATUS_SUCCESS then
  try
    // Файл открыт, теперь смотрим его формализованный путь
    NTSTAT := NtQueryObject(hFile, ObjectNameInformation,
      @ObjectNameInfo, MAX_PATH * 2, @dwReturn);
    if NTSTAT = STATUS_SUCCESS then
    begin
      SetLength(AnsiResult, MAX_PATH);
      WideCharToMultiByte(CP_ACP, 0,
        @ObjectNameInfo.Name.Buffer[ObjectNameInfo.Name.MaximumLength -
        ObjectNameInfo.Name.Length {$IFDEF WIN64} + 4{$ENDIF}],
        ObjectNameInfo.Name.Length, @AnsiResult[1],
        MAX_PATH, nil, nil);
      Result := string(PAnsiChar(AnsiResult));
      // Путь на открытый через ZwOpenFile файл
      // возвращается в виде \Device\HarddiskVolumeХ\бла-бла
      // Осталось только его сопоставить с реальным диском
      SetLength(Buff, DriveTotalSize);
      Count := GetLogicalDriveStrings(DriveTotalSize, @Buff[1]) div DriveNameSize;
      for I := 0 to Count - 1 do
      begin
        Volume := PChar(@Buff[(I * DriveNameSize) + 1]);
        Volume[3] := #0;
        // Преобразуем имя каждого диска в символьную ссылку и
        // сравниваем с формализированным путем
        QueryDosDevice(PChar(Volume), @lpQuery[0], MAX_PATH);
        dwQueryLength := Length(string(lpQuery));
        if Copy(Result, 1, dwQueryLength) = string(lpQuery) then
        begin
          Volume[3] := '\';
          if lpQuery[dwQueryLength - 1] <> '\' then
            Inc(dwQueryLength);
          Delete(Result, 1, dwQueryLength);
          Result := Volume + Result;
          Break;
        end;
      end;
    end;
  finally
    ZwClose(hFile);
  end;
end;

//  Функция возвращает размер секции с учетом выравнивания,
//  указанного в PE заголовка.
//  Вообще, правильней еще смотреть флаги IMAGE_SCN_ALIGN_ХХХBYTES у секции,
//  которые выставляют индивидуальное выравнивание, но лениво...
// =============================================================================
function AlignedSectionSize(const ImageInfo: LOADED_IMAGE;
  const Value: NativeUInt): NativeUInt;
begin
  if Value = 0 then
  begin
    Result := 0;
    Exit;
  end;
  with ImageInfo.FileHeader^.OptionalHeader do
  begin
    if SectionAlignment mod Value = 0 then
      Result := Value
    else
    begin
      Result := Value div SectionAlignment;
      Inc(Result);
      Result := Result * SectionAlignment;
    end;
  end;
end;

function CheckAddr(Value: NativeUInt): Boolean;
begin
  Result := Value > $10000;
end;

function CheckAddr(Value: Pointer): Boolean;
begin
  Result := CheckAddr(NativeUInt(Value));
end;

//  Функция проверяет характеристики секции и возвращает флаг,
//  содержит ли секция исполяемый код
// =============================================================================
function IsExecute(const Value: DWORD): Boolean;
begin
  Result := False;
  if (Value and IMAGE_SCN_CNT_CODE) =
    IMAGE_SCN_CNT_CODE then Result := True;
  if (Value and IMAGE_SCN_MEM_EXECUTE) =
    IMAGE_SCN_MEM_EXECUTE then Result := True;
end;

//  Функция проверяет характеристики секции и возвращает флаг,
//  доступна ли секция на запись или
//  содержит ли секция неинициализированные данные
// =============================================================================
function IsWrite(const Value: DWORD): Boolean;
begin
  Result := False;
  if (Value and IMAGE_SCN_CNT_UNINITIALIZED_DATA) =
    IMAGE_SCN_CNT_UNINITIALIZED_DATA then Result := True;
  if (Value and IMAGE_SCN_MEM_WRITE) = IMAGE_SCN_MEM_WRITE then
    Result := True;
end;

function CheckPEImage(hProcess: THandle; ImageBase: Pointer): Boolean;
var
  ReturnLength: NativeUInt;
  IDH: TImageDosHeader;
  NT: TImageNtHeaders;
begin
  Result := False;
  if not ReadProcessMemory(hProcess, ImageBase,
    @IDH, SizeOf(TImageDosHeader), ReturnLength) then Exit;
  if IDH.e_magic <> IMAGE_DOS_SIGNATURE then Exit;
  ImageBase := Pointer(NativeInt(ImageBase) + IDH._lfanew);
  if not ReadProcessMemory(hProcess, ImageBase,
    @NT, SizeOf(TImageNtHeaders), ReturnLength) then Exit;
  Result := NT.Signature = IMAGE_NT_SIGNATURE;
end;

function SuspendProcess(PID: DWORD): TProcessLockHandleList;
const
  THREAD_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED or SYNCHRONIZE or $3FF;
  ThreadBasicInformation = 0;
  ThreadQuerySetWin32StartAddress = 9;
var
  hSnap, hThread: THandle;
  ThreadEntry: TThreadEntry32;
begin
  Result := TProcessLockHandleList.Create;
  if PID = GetCurrentProcessID then Exit;
  hSnap := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, PID);
  if hSnap <> INVALID_HANDLE_VALUE then
  try
    ThreadEntry.dwSize := SizeOf(TThreadEntry32);
    if Thread32First(hSnap, ThreadEntry) then
    repeat
      if ThreadEntry.th32OwnerProcessID <> PID then Continue;
      hThread := OpenThread(THREAD_ALL_ACCESS,
        False, ThreadEntry.th32ThreadID);
      if hThread <> 0 then
      begin
        SuspendThread(hThread);
        Result.Add(hThread);
      end;
    until not Thread32Next(hSnap, ThreadEntry);
  finally
     CloseHandle(hSnap);
  end;
end;

procedure ResumeProcess(Value: TProcessLockHandleList);
var
  hThread: THandle;
begin
  for hThread in Value do
  begin
    ResumeThread(hThread);
    CloseHandle(hThread);
  end;
  Value.Free;
end;

end.
