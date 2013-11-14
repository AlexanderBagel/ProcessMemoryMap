////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : MemoryMap
//  * Unit Name : MemoryMap.Heaps.pas
//  * Purpose   : Класс собирает данные о кучах процесса
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

unit MemoryMap.Heaps;

interface

uses
  Winapi.Windows,
  Generics.Collections,
  Winapi.TlHelp32;

type
  THeapEntry = record
    Address: ULONG_PTR;
    Size: SIZE_T;
    Flags: ULONG;
  end;

  THeapData = record
    ID: DWORD;
    Wow64: Boolean;
    Entry: THeapEntry;
  end;

  THeap = class
  private
    FData: TList<THeapData>;
  protected
    procedure Update(PID: Cardinal; hProcess: THandle);
  public
    constructor Create; overload;
    constructor Create(PID: Cardinal; hProcess: THandle); overload;
    destructor Destroy; override;
    property Data: TList<THeapData> read FData;
  end;

implementation

uses
  MemoryMap.Core,
  MemoryMap.NtDll;

{ THeap }

constructor THeap.Create(PID: Cardinal; hProcess: THandle);
begin
  Create;
  Update(PID, hProcess);
end;

constructor THeap.Create;
begin
  FData := TList<THeapData>.Create;
end;

destructor THeap.Destroy;
begin
  FData.Free;
  inherited;
end;

procedure THeap.Update(PID: Cardinal; hProcess: THandle);
const
  RTL_HEAP_BUSY = 1;
  RTL_HEAP_SEGMENT = 2;
  RTL_HEAP_SETTABLE_VALUE = $10;
  RTL_HEAP_SETTABLE_FLAG1 = $20;
  RTL_HEAP_SETTABLE_FLAG2 = $40;
  RTL_HEAP_SETTABLE_FLAG3 = $80;
  RTL_HEAP_SETTABLE_FLAGS = $E0;
  RTL_HEAP_UNCOMMITTED_RANGE = $100;
  RTL_HEAP_PROTECTED_ENTRY = $200;
  RTL_HEAP_FIXED = (RTL_HEAP_BUSY or RTL_HEAP_SETTABLE_VALUE or
    RTL_HEAP_SETTABLE_FLAG2 or RTL_HEAP_SETTABLE_FLAG3 or
    RTL_HEAP_SETTABLE_FLAGS or RTL_HEAP_PROTECTED_ENTRY);

  function CheckSmallBuff(Value: DWORD): Boolean;
  const
    STATUS_NO_MEMORY = $C0000017;
    STATUS_BUFFER_TOO_SMALL = $C0000023;
  begin
    Result := (Value = STATUS_NO_MEMORY) or (Value = STATUS_BUFFER_TOO_SMALL);
  end;

var
  I, A: Integer;
  pDbgBuffer: PRtlDebugInformation;
  pHeapInformation: PRtlHeapInformation;
  pHeapEntry: PRtrHeapEntry;
  dwAddr, dwLastSize: ULONG_PTR;
  hit_seg_count: Integer;
  HeapData: THeapData;
  BuffSize: NativeUInt;
begin
  // Т.к. связка Heap32ListFirst, Heap32ListNext, Heap32First, Heap32Next
  // работает достаточно медленно, из-за постоянного вызова
  // RtlQueryProcessDebugInformation на каждой итерации, мы заменим ее вызов
  // аналогичным кодом без ненужного дубляжа
  // Создаем отладочный буффер
  BuffSize := $400000;
  pDbgBuffer := RtlCreateQueryDebugBuffer(BuffSize, False);
  // Запрашиваем информацию по списку куч процесса
  while CheckSmallBuff(RtlQueryProcessDebugInformation(PID,
    RTL_QUERY_PROCESS_HEAP_SUMMARY or RTL_QUERY_PROCESS_HEAP_ENTRIES,
    pDbgBuffer)) do
  begin
    // если размера буфера не хватает, увеличиваем...
    RtlDestroyQueryDebugBuffer(pDbgBuffer);
    BuffSize := BuffSize shl 1;
    pDbgBuffer := RtlCreateQueryDebugBuffer(BuffSize, False);
  end;

  if pDbgBuffer <> nil then
  try
    // Запрашиваем информацию по списку куч процесса
    if RtlQueryProcessDebugInformation(PID,
      RTL_QUERY_PROCESS_HEAP_SUMMARY or RTL_QUERY_PROCESS_HEAP_ENTRIES,
      pDbgBuffer) = STATUS_SUCCESS then
    begin
      // Получаем указатель на кучу по умолчанию
      pHeapInformation := @pDbgBuffer^.Heaps^.Heaps[0];
      // перечисляем все ее блоки...
      for I := 0 to pDbgBuffer^.Heaps^.NumberOfHeaps - 1 do
      begin

        HeapData.ID := I;

        // начиная с самого первого
        pHeapEntry := pHeapInformation^.Entries;
        dwAddr := DWORD(pHeapEntry^.u.s2.FirstBlock) +
          pHeapInformation^.EntryOverhead;
        dwLastSize := 0;

        A := 0;
        while A < Integer(pHeapInformation^.NumberOfEntries) do
        try
          hit_seg_count := 0;

          while (pHeapEntry^.Flags and RTL_HEAP_SEGMENT) = RTL_HEAP_SEGMENT do
          begin
            // Если блок отмечен флагом RTL_HEAP_SEGMENT,
            // то рассчитываем новый адрес на основе EntryOverhead
            dwAddr := DWORD(pHeapEntry^.u.s2.FirstBlock) +
              pHeapInformation^.EntryOverhead;
            Inc(pHeapEntry);
            Inc(A);
            Inc(hit_seg_count);
            // проверка выхода за границы блоков
            if A + hit_seg_count >=
              Integer(pHeapInformation^.NumberOfEntries - 1) then
              Continue;
          end;

          // Если блок не самый первый в сегменте, то текущий адрес блока равен,
          // адресу предыдущего блока + размер предыдущего блока
          if hit_seg_count = 0 then
            Inc(dwAddr, dwLastSize);

          // Выставляем флаги
          if pHeapEntry^.Flags and RTL_HEAP_FIXED <> 0 then
            pHeapEntry^.Flags := LF32_FIXED
          else
            if pHeapEntry^.Flags and RTL_HEAP_SETTABLE_FLAG1 <> 0 then
              pHeapEntry^.Flags := LF32_MOVEABLE
            else
              if pHeapEntry^.Flags and RTL_HEAP_UNCOMMITTED_RANGE <> 0 then
                pHeapEntry^.Flags := LF32_FREE;
          if pHeapEntry^.Flags = 0 then
            pHeapEntry^.Flags := LF32_FIXED;

          // Добавляем результат к списку
          HeapData.Entry.Address := dwAddr;
          HeapData.Entry.Size := pHeapEntry^.Size;
          HeapData.Entry.Flags := pHeapEntry^.Flags;
          HeapData.Wow64 := False;
          FData.Add(HeapData);

         // Запоминаем адрес последнего блока
         dwLastSize := pHeapEntry^.Size;
         // Переходим к следующему блоку
         Inc(pHeapEntry);
        finally
          Inc(A);
        end;
        // Переходим к следующей куче
        Inc(pHeapInformation);
      end;
    end;
  finally
    RtlDestroyQueryDebugBuffer(pDbgBuffer);
  end;
end;

end.
