////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Unit Name : UnitInitOrderTracer
//  * Purpose   : Реализация вывода списка используемых модулей в порядке инициализации
//  * Author    : Александр (Rouse_) Багель
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
  // типы списка
  TOrderListType = (
    oltDelphi,                 // старые варианты Delphi
    oltDelphiWithNamespaces,   // новые версии дельфи (нэймспейсы, класс конструкторы)
    oltLazarus                 // Lazarus + FPC
    );

  TUnitData = record
    UnitName: string;
    InitializarionVA,
    FinalizationVA: UInt64;
    FpcClass: Boolean;         // флаг что запись получена в результате
                               // дизассемблирования обработчика инициализации
                               // или финализации FPC модуля
  end;

  TUnitInitOrderList = TList<TUnitData>;

  function GetUnitInitOrderList(const FilePath: string;
    out ListType: TOrderListType): TUnitInitOrderList;

implementation

uses
  MemoryMap.DebugMapData,
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
      // добавляем только вызовы классовых конструкторов/деструкторов
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
      // становимся на RAW адрес функции инициализации/финализации
      Inc(ABuff, APEImage.VaToRaw(AddrVA));
      // дизассемблируем
      Inst := DisAsm.DecodeBuff(ABuff, dmUntilRet, True);
    finally
      DisAsm.Free;
    end;

    // и ищем все первичные CALL-ы в которых буду вызовы классовых конструкторов
    FirstCallFound := False;

    // в функциях инициализации вызовы классовых конструкторов идут самыми первыми
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

    // а в финализации самыми последними
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
  InitTableHeaderVA,    // адрес заголовка таблицы инициализации
  InitTableLen: UInt64; // количество записей инициализации
  M: TMemoryStream;
  UnitData: TUnitData;
begin
  Index := APEImage.CoffDebugInfo.SymbolAtName('INITFINAL');
  if Index < 0 then
    raise Exception.Create('INITFINAL not found.');

  // обязательная подготовка таблицы символов
  SymbolStorage.PrepareForWork;

  M := TMemoryStream.Create;
  try
    M.LoadFromFile(APEImage.ImagePath);
    P := M.Memory;

    // COFF сразу знает об адресе таблицы инициализации,
    // поэтому можем встать на неё без лишних телодвижений
    InitTableHeaderVA := APEImage.CoffDebugInfo.CoffStrings[Index].FuncAddrVA;
    Inc(P, APEImage.VaToRaw(InitTableHeaderVA));

    // в заголовке просто два счетчика
    // с количеством пар записей
    InitTableLen := ReadChunk;
    // и количеством обработанных, в образе инициализировано нулем, поэтому пропускаем
    ReadChunk;

    // ну и осталось только загрузить сами записи
    for I := 0 to InitTableLen - 1 do
    begin
      UnitData.FpcClass := False;
      UnitData.InitializarionVA := ReadChunk;
      UnitData.FinalizationVA := ReadChunk;

      // в таблице спокойно могут быть пустые записи, такие просто пропускаем
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
    // становимся на RAW адрес точки входа
    P := ABuff;
    Inc(P, APEImage.VaToRaw(APEImage.EntryPoint));
    // дизассемблируем точку входа
    Inst := DisAsm.DecodeBuff(P, dmUntilRet, True);
    // и ищем CALL по адресу определенного ранее InitExe
    for I := 0 to Length(Inst) - 1 do
      if (Inst[I].InstType = itCall) and
        ( (Inst[I].JmpAddrVa = InitAddrVA) or    // call xxx
          (Inst[I].RipAddrVA = InitAddrVA)) then // call [rip+xxx]
      begin
        // если нашли - то предыдущая инструкция будет
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
  InitExeVA,            // адрес функции инициализации приложения
  InitTableHeaderVA,    // адрес заголовка таблицы инициализации
  InitTableVA,          // адрес таблицы цинициализации
  InitTableLen: UInt64; // размер таблицы
  M: TMemoryStream;
  I: Integer;
  UnitData: TUnitData;
begin
  DebugMap := TDebugMap.Create;
  try
    // загружаем отладочкую и ищем адрес InitExe
    // который отвечает за инициализацию модулей
    DebugMap.Init(APEImage.ImageBase, APEImage.ImagePath);

    // ищем старый вариант названия функции
    Result := oltDelphi;
    InitExeVA := DebugMap.GetAddrFromDescription('@InitExe');
    if InitExeVA = 0 then
    begin
      // а если у нас новые Delphi, тогда по новому названию
      Result := oltDelphiWithNamespaces;
      InitExeVA := DebugMap.GetAddrFromDescription('SysInit.@InitExe');
    end;
    if InitExeVA = 0 then
      raise Exception.Create('@InitExe not found.');

    // ищем адрес таблицы инициализации
    M := TMemoryStream.Create;
    try
      M.LoadFromFile(APEImage.ImagePath);
      InitTableHeaderVA := GetDelphiInitTableHeaderAddr(M.Memory, APEImage, InitExeVA);
      if InitTableHeaderVA = 0 then
        raise Exception.Create('InitTable not found.');

      // читаем заголовок
      P := M.Memory;
      Inc(P, APEImage.VaToRaw(InitTableHeaderVA));

      InitTableLen := ReadChunk;
      InitTableVA := ReadChunk;

      // загружаем таблицу представленную парами VA адресов
      // адрес инициализации + адрес финализации
      P := M.Memory;
      Inc(P, APEImage.VaToRaw(InitTableVA));

      for I := 0 to InitTableLen - 1 do
      begin
        UnitData.InitializarionVA := ReadChunk;
        UnitData.FinalizationVA := ReadChunk;

        // в таблице спокойно могут быть пустые записи, такие просто пропускаем
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

  // загрузка строк из образа не нужна, отключаем
  TRawPEImage.DisableLoadStrings := True;

  // чистим загруженые ранее символы
  SymbolStorage.Clear;

  // грузим сам образ
  PEImage := TRawPEImage.Create(FilePath, False);
  try
    // если в образе присутствует отладочные COFF символы,
    // значит это скорее всего Lazarus/FPC, проверяем наличие таблицы "INITFINAL"
    // и если есть - тогда можно её сразу выводить
    if ditCoff in PEImage.DebugData then
    begin
      ListType := oltLazarus;
      LoadLazarusUnitInitOrder(PEImage, Result);
      Exit;
    end;

    // в противном случае ищем таблицу через дизассемблирование точки входа
    // с подключением отладочных символов
    ListType := LoadDelphiUnitInitOrder(PEImage, Result);
  finally
    PEImage.Free;
  end;
end;


end.
