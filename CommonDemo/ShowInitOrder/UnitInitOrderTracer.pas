////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Unit Name : UnitInitOrderTracer
//  * Purpose   : Implementation of listing the loaded modules in initialization order
//  * Author    : Alexander (Rouse_) Bagel
//  * Version   : 1.01
//  ****************************************************************************
//

unit UnitInitOrderTracer;

interface

uses
  Classes,
  SysUtils,
  Generics.Collections;

type
  // list types
  // [ru] типы списка

  TOrderListType = (
    oltDelphi,                 // old Delphi versions
                               // [ru] старые варианты Delphi

    oltDelphiWithNamespaces,   // new Delphi versions (namespaces, class constructors)
                               // [ru] новые версии дельфи (нэймспейсы, класс конструкторы)

    oltLazarus                 // Lazarus + FPC
    );

  TUnitData = record
    UnitName: string;
    InitializarionVA,
    FinalizationVA: UInt64;

    // flag that the record was obtained as a result
    // of disassembling the initialization
    // or finalization handler of an FPC unit

    // [ru] флаг, что запись получена в результате
    // дизассемблирования обработчика инициализации
    // или финализации FPC-модуля

    FpcClass: Boolean;
  end;

  TUnitInitOrderList = TList<TUnitData>;

  function GetUnitInitOrderList(const FilePath: string;
    out ListType: TOrderListType): TUnitInitOrderList;

implementation

uses
  MemoryMap.DebugMapData,
  RawScanner.AbstractImage,
  RawScanner.Image.Pe,
  RawScanner.Disassembler,
  RawScanner.SymbolStorage,
  RawScanner.CoffDwarf;

procedure LoadLazarusUnitInitOrder(APEImage: TRawPEImage;
  AData: TUnitInitOrderList);
var
  P: PByte;

  function ReadChunk: UInt64;
  begin
    if APEImage.Image64 then
    begin
      Result := PUint64(P)^;
      Inc(P, 8);
    end
    else
    begin
      Result := PCardinal(P)^;
      Inc(P, 4);
    end;
  end;

  function GetDescriptionAtAddrVA(AddrVA: UInt64; UnitNameOnly: Boolean): string;
  var
    I, Count: Integer;
    SymbolData: TSymbolData;
  begin
    Result := '';
    if AddrVA = 0 then Exit;
    Count := SymbolStorage.GetDataCountAtAddr(AddrVA);
    for I := 0 to Count - 1 do
      if SymbolStorage.GetDataAtAddr(AddrVA, SymbolData, I) and (SymbolData.DataType = sdtCoffFunction) then
      begin
        Result := APEImage.CoffDebugInfo.CoffStrings[SymbolData.Binary.ListIndex].DisplayName;
        if Result.StartsWith('[') then
        begin
          if UnitNameOnly then
            Result := Copy(Result, 2, Pos(']', Result) - 2);
          Break;
        end;
      end;
  end;

  procedure FillClassOperations(AddrVA: UInt64; ABuff: PByte; Init: Boolean);
  var
    DisAsm: TDisassembler;
    Inst: TInstructionArray;
    I: Integer;
    FirstCallFound: Boolean;

    procedure ProcessInst(const Inst: TInstruction);
    var
      UnitData: TUnitData;
    begin
      UnitData.UnitName := GetDescriptionAtAddrVA(Inst.JmpAddrVa, False);

      // we add only calls of class constructors/destructors
      // their names always contain a dot!

      // [ru] добавляем только вызовы классовых конструкторов/деструкторов
      // у них в имени обязательно будет точка!

      if Pos('.', UnitData.UnitName) = 0 then Exit;
      UnitData.FpcClass := True;
      if Init then
      begin
        UnitData.InitializarionVA := Inst.JmpAddrVa;
        UnitData.FinalizationVA := 0;
      end
      else
      begin
        UnitData.InitializarionVA := 0;
        UnitData.FinalizationVA := Inst.JmpAddrVa;
      end;
      AData.Add(UnitData);
    end;

  begin
    if AddrVA = 0 then Exit;    
    DisAsm := TDisassembler.Create(0, AddrVA, 4096, APEImage.Image64);
    try

      // we move to the RAW address of the initialization/finalization function
      // [ru] становимся на RAW адрес функции инициализации/финализации

      Inc(ABuff, APEImage.VaToRaw(AddrVA));

      // we disassemble
      // [ru] дизассемблируем

      Inst := DisAsm.DecodeBuff(ABuff, dmUntilRet, True);
    finally
      DisAsm.Free;
    end;

    // and we look for all primary CALLs in which there will be class constructor calls
    // [ru] и ищем все первичные CALL-ы, в которых будут вызовы классовых конструкторов

    FirstCallFound := False;

    // in initialization functions the class constructor calls come very first
    // [ru] в функциях инициализации вызовы классовых конструкторов идут самыми первыми

    if Init then
    begin
      for I := 0 to Length(Inst) - 1 do
      begin
        case Inst[I].InstType of
          itCall:
          begin
            FirstCallFound := True;
            ProcessInst(Inst[I]);
          end;
        else
          if FirstCallFound then
            Break;
        end;
      end;
    end;

    // and in finalization they come very last
    // [ru] а в финализации самыми последними

    for I := Length(Inst) - 1 downto 0 do
    begin
      case Inst[I].InstType of
        itCall:
        begin
          FirstCallFound := True;
          ProcessInst(Inst[I]);
        end;
      else
        if FirstCallFound then
          Break;
      end;
    end;

  end;

var
  I, Index: Integer;
  InitTableHeaderVA,    // address of the initialization table header
                        // [ru] адрес заголовка таблицы инициализации

  InitTableLen: UInt64; // number of initialization records
                        // [ru] количество записей инициализации
  M: TMemoryStream;
  UnitData: TUnitData;
begin
  Index := APEImage.CoffDebugInfo.SymbolAtName('INITFINAL');
  if Index < 0 then
    raise Exception.Create('INITFINAL not found.');

  // mandatory preparation of the symbol table
  // [ru] обязательная подготовка таблицы символов

  SymbolStorage.PrepareForWork;

  M := TMemoryStream.Create;
  try
    M.LoadFromFile(APEImage.ImagePath);
    P := M.Memory;

    // COFF immediately knows the address of the initialization table,
    // so we can move to it without unnecessary effort

    // [ru] COFF сразу знает об адресе таблицы инициализации,
    // поэтому можем встать на неё без лишних телодвижений

    InitTableHeaderVA := APEImage.CoffDebugInfo.CoffStrings[Index].FuncAddrVA;
    Inc(P, APEImage.VaToRaw(InitTableHeaderVA));

    // the header simply contains two counters
    // with the number of record pairs

    // [ru] в заголовке просто два счетчика
    // с количеством пар записей

    InitTableLen := ReadChunk;

    // and the number of processed ones, initialized with zero in the image, so we skip it
    // [ru] и количеством обработанных, в образе инициализировано нулем, поэтому пропускаем

    ReadChunk;

    // and now all that is left is to load the records themselves
    // [ru] ну и осталось только загрузить сами записи

    for I := 0 to InitTableLen - 1 do
    begin
      UnitData.FpcClass := False;
      UnitData.InitializarionVA := ReadChunk;
      UnitData.FinalizationVA := ReadChunk;

      // the table may well contain empty records, we just skip them
      // [ru] в таблице спокойно могут быть пустые записи, такие просто пропускаем

      if (UnitData.InitializarionVA = 0) and (UnitData.FinalizationVA = 0) then
        Continue;

      UnitData.UnitName := GetDescriptionAtAddrVA(UnitData.InitializarionVA, True);
      if UnitData.UnitName = '' then
        UnitData.UnitName := GetDescriptionAtAddrVA(UnitData.FinalizationVA, True);
      AData.Add(UnitData);
      FillClassOperations(UnitData.InitializarionVA, M.Memory, True);
      FillClassOperations(UnitData.FinalizationVA, M.Memory, False);
    end;

  finally
    M.Free;
  end;
end;

function GetDelphiInitTableHeaderAddr(ABuff: PByte;
  APEImage: TRawPEImage; InitAddrVA: UInt64): UInt64;
var
  DisAsm: TDisassembler;
  P: PByte;
  Inst: TInstructionArray;
  I: Integer;
begin
  Result := 0;
  DisAsm := TDisassembler.Create(0, APEImage.EntryPoint, 4096, APEImage.Image64);
  try

    // we move to the RAW address of the entry point
    // [ru] становимся на RAW адрес точки входа

    P := ABuff;
    Inc(P, APEImage.VaToRaw(APEImage.EntryPoint));

    // we disassemble the entry point
    // [ru] дизассемблируем точку входа

    Inst := DisAsm.DecodeBuff(P, dmUntilRet, True);

    // and we look for a CALL to the address of InitExe determined earlier
    // [ru] и ищем CALL по адресу определенного ранее InitExe

    for I := 0 to Length(Inst) - 1 do
      if (Inst[I].InstType = itCall) and
        ( (Inst[I].JmpAddrVa = InitAddrVA) or    // call xxx
          (Inst[I].RipAddrVA = InitAddrVA)) then // call [rip+xxx]
      begin

        // if we found it - then the previous instruction will
        // contain the address of the initialization table header

        // [ru] если нашли - то предыдущая инструкция будет
        // содержать адрес заголовка таблицы инициализации

        Result := Inst[I - 1].RipAddrVA;
        if Result = 0 then
          Result := Inst[I - 1].JmpAddrVa;
        Break;
      end;
  finally
    DisAsm.Free;
  end;
end;

function LoadDelphiUnitInitOrder(APEImage: TRawPEImage;
  AData: TUnitInitOrderList): TOrderListType;
var
  P: PByte;

  function ReadChunk: UInt64;
  begin
    if APEImage.Image64 then
    begin
      Result := PUint64(P)^;
      Inc(P, 8);
    end
    else
    begin
      Result := PCardinal(P)^;
      Inc(P, 4);
    end;
  end;

var
  DebugMap: TDebugMap;
  InitExeVA,            // address of the application initialization function
                        // [ru] адрес функции инициализации приложения

  InitTableHeaderVA,    // address of the initialization table header
                        // [ru] адрес заголовка таблицы инициализации

  InitTableVA,          // address of the initialization table
                        // [ru] адрес таблицы инициализации

  InitTableLen: UInt64; // table size
                        // [ru] размер таблицы
  M: TMemoryStream;
  I: Integer;
  UnitData: TUnitData;
begin
  DebugMap := TDebugMap.Create;
  try

    // we load the debug information and look for the address of InitExe,
    // which is responsible for module initialization

    // [ru] загружаем отладочную и ищем адрес InitExe,
    // который отвечает за инициализацию модулей

    DebugMap.Init(APEImage.ImageBase, APEImage.ImagePath);

    // we look for the old variant of the function name
    // [ru] ищем старый вариант названия функции

    Result := oltDelphi;
    InitExeVA := DebugMap.GetAddrFromDescription('@InitExe');
    if InitExeVA = 0 then
    begin

      // and if we have new Delphi versions, then by the new name
      // [ru] а если у нас новые Delphi, тогда по новому названию

      Result := oltDelphiWithNamespaces;
      InitExeVA := DebugMap.GetAddrFromDescription('SysInit.@InitExe');
    end;
    if InitExeVA = 0 then
      raise Exception.Create('@InitExe not found.');

    // we look for the address of the initialization table
    // [ru] ищем адрес таблицы инициализации

    M := TMemoryStream.Create;
    try
      M.LoadFromFile(APEImage.ImagePath);
      InitTableHeaderVA := GetDelphiInitTableHeaderAddr(M.Memory, APEImage, InitExeVA);
      if InitTableHeaderVA = 0 then
        raise Exception.Create('InitTable not found.');

      // we read the header
      // [ru] читаем заголовок

      P := M.Memory;
      Inc(P, APEImage.VaToRaw(InitTableHeaderVA));

      InitTableLen := ReadChunk;
      InitTableVA := ReadChunk;

      // we load the table, represented by pairs of VA addresses
      // initialization address + finalization address

      // [ru] загружаем таблицу, представленную парами VA адресов
      // адрес инициализации + адрес финализации

      P := M.Memory;
      Inc(P, APEImage.VaToRaw(InitTableVA));

      for I := 0 to InitTableLen - 1 do
      begin
        UnitData.InitializarionVA := ReadChunk;
        UnitData.FinalizationVA := ReadChunk;

        // the table may well contain empty records, we just skip them
        // [ru] в таблице спокойно могут быть пустые записи, такие просто пропускаем

        if (UnitData.InitializarionVA = 0) and (UnitData.FinalizationVA = 0) then
          Continue;

        UnitData.UnitName := DebugMap.GetDescriptionAtAddr(UnitData.InitializarionVA, False);
        if UnitData.UnitName = '' then
          UnitData.UnitName := DebugMap.GetDescriptionAtAddr(UnitData.FinalizationVA, False);
        AData.Add(UnitData);
      end;

    finally
      M.Free;
    end;

  finally
    DebugMap.Free;
  end;
end;

function GetUnitInitOrderList(const FilePath: string;
  out ListType: TOrderListType): TUnitInitOrderList;
var
  PEImage: TRawPEImage;
begin
  Result := TUnitInitOrderList.Create;

  // loading strings from the image is not needed, we disable it
  // [ru] загрузка строк из образа не нужна, отключаем

  TRawPEImage.DisableLoadStrings := True;

  // we clear the symbols loaded earlier
  // [ru] чистим загруженные ранее символы

  SymbolStorage.Clear;

  // we load the image itself
  // [ru] грузим сам образ

  PEImage := TRawPEImage.Create(FilePath, iltFull);
  try

    // if the image contains debug COFF symbols,
    // then this is most likely Lazarus/FPC, we check for the "INITFINAL" table
    // and if it exists - then it can be output right away

    // [ru] если в образе присутствуют отладочные COFF-символы,
    // значит это скорее всего Lazarus/FPC, проверяем наличие таблицы "INITFINAL"
    // и если есть - тогда можно её сразу выводить

    if ditCoff in PEImage.DebugData then
    begin
      ListType := oltLazarus;
      LoadLazarusUnitInitOrder(PEImage, Result);
      Exit;
    end;

    // otherwise we look for the table by disassembling the entry point
    // with debug symbols connected

    // [ru] в противном случае ищем таблицу через дизассемблирование точки входа
    // с подключением отладочных символов

    ListType := LoadDelphiUnitInitOrder(PEImage, Result);
  finally
    PEImage.Free;
  end;
end;


end.
