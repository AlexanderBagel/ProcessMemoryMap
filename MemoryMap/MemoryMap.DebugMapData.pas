////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : MemoryMap
//  * Unit Name : MemoryMap.DebugMapData.pas
//  * Purpose   : Класс для работы с отладочным MAP файлом.
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.4.34
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit MemoryMap.DebugMapData;

interface

uses
  Winapi.Windows,
  System.Classes,
  System.Hash,
  System.SysUtils,
  Generics.Collections,
  Generics.Defaults;

type
  TDebugMapItem = record
    Address: NativeUInt;
    ModuleName,
    FunctionName: string;
    Executable: Boolean;
  end;

  TDebugMap = class
  private type
    TSectionData = record
      Index: Integer;
      StartAddr: DWORD;
      Length: DWORD;
      Executable: Boolean;
    end;
    TLineData = record
      UnitIndex: Integer;
      LineNumber: Integer;
    end;
  private
    FItems: TList<TDebugMapItem>;
    FLoadLines: Boolean;
    FLoadedMap: TStringList;
    FUnits: TDictionary<Integer, string>;
    FLines: TDictionary<ULONG_PTR, TLineData>;
    function StrHash(const Value: string): Integer;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Clear;
    procedure Init(BaseAddress: ULONG_PTR; const ModulePath: string);
    function GetAddrFromDescription(const Value: string): ULONG_PTR;
    function GetDescriptionAtAddr(Address: ULONG_PTR;
      AddModuleName: Boolean = True): string;
    function GetDescriptionAtAddrWithOffset(Address: ULONG_PTR;
      const CheckModuleName: string; AddModuleName: Boolean = True): string;
    function GetLineNumberAtAddr(BaseAddress: ULONG_PTR;
      var AUnitName: string): Integer;
    function GetLineNumberAtAddrForced(BaseAddress: ULONG_PTR;
      Limit: Integer; var UnitName: string): Integer;
    procedure GetExportFuncList(const ModuleName: string; Value: TStringList;
      Executable: Boolean);
    function ModuleLoaded(const ModuleName: string): Boolean;
    property Items: TList<TDebugMapItem> read FItems;
    property Lines: TDictionary<ULONG_PTR, TLineData> read FLines;
    property LoadLines: Boolean read FLoadLines write FLoadLines;
    property LoadedMap: TStringList read FLoadedMap;
    property Units: TDictionary<Integer, string> read FUnits;
  end;

implementation

uses
  MemoryMap.PEImage;

{ TDebugMap }

procedure TDebugMap.Clear;
begin
  FItems.Clear;
  FLoadedMap.Clear;
  FUnits.Clear;
  FLines.Clear;
end;

constructor TDebugMap.Create;
begin
  FItems := TList<TDebugMapItem>.Create(
   TComparer<TDebugMapItem>.Construct(
    function (const A, B: TDebugMapItem): Integer
    begin
      if A.Address < B.Address then
        Result := -1
      else
        if A.Address = B.Address then
          Result := 0
        else
          Result := 1;
    end)
   );
  FLoadedMap := TStringList.Create;
  FUnits := TDictionary<Integer, string>.Create;
  FLines := TDictionary<ULONG_PTR, TLineData>.Create;
end;

destructor TDebugMap.Destroy;
begin
  FLines.Free;
  FUnits.Free;
  FLoadedMap.Free;
  FItems.Free;
  LoadLines := False;
  inherited;
end;

function TDebugMap.GetAddrFromDescription(const Value: string): ULONG_PTR;
var
  CheckNameOnly: Boolean;
  CheckName: string;
begin
  Result := 0;
  CheckNameOnly := Pos('!', Value) = 0;
  for var I := 0 to FItems.Count - 1 do
  begin
    if CheckNameOnly then
      CheckName := FItems.List[I].FunctionName
    else
      CheckName := FItems.List[I].ModuleName + '!' + FItems.List[I].FunctionName;
    if AnsiSameText(Value, CheckName) then
      Exit(FItems.List[I].Address);
  end;
end;

function TDebugMap.GetDescriptionAtAddr(Address: ULONG_PTR;
  AddModuleName: Boolean): string;
var
  I: Integer;
  Item: TDebugMapItem;
begin
  Result := '';
  Item.Address := Address;
  if FItems.BinarySearch(Item, I) then
    if I >= 0 then
      if AddModuleName then
        Result := FItems.List[I].ModuleName + '!' + FItems.List[I].FunctionName
      else
        Result := FItems.List[I].FunctionName
end;

function TDebugMap.GetDescriptionAtAddrWithOffset(Address: ULONG_PTR;
  const CheckModuleName: string; AddModuleName: Boolean): string;
var
  I: Integer;
  Item: TDebugMapItem;
  EarlierAddr: Boolean;
begin
  Result := '';
  Item.Address := Address;

  // если адрес не нашелся, результатом будет позиция,
  // где этот адрес должен был бы находится, т.е. для оффсета надо
  // взять за базу адрес предыдущей функции от найденой позиции
  if not FItems.BinarySearch(Item, I) then
    Dec(I);

  EarlierAddr := I < 0;
  if EarlierAddr then
    I := 0;

  // проверка на выход за диапазон
  if I >= FItems.Count then Exit;

  if not AnsiSameText(ExtractFileName(CheckModuleName),
    FItems.List[I].ModuleName) then Exit;

  if AddModuleName then
    Result := FItems.List[I].ModuleName + '!' + FItems.List[I].FunctionName
  else
    Result := FItems.List[I].FunctionName;
  if FItems.List[I].Address <> Address then
  begin
    if EarlierAddr then
      Result := Result +
        '-0x' + IntToHex(FItems.List[I].Address - Address, 1)
    else
      Result := Result +
        '+0x' + IntToHex(Address - FItems.List[I].Address, 1);
  end;
end;

procedure TDebugMap.GetExportFuncList(const ModuleName: string;
  Value: TStringList; Executable: Boolean);
var
  I: Integer;
begin
  for I := 0 to FItems.Count - 1 do
    if FItems[I].ModuleName = ModuleName then
      if FItems[I].Executable = Executable then
        Value.AddObject(FItems[I].FunctionName, Pointer(FItems[I].Address));
end;

function TDebugMap.GetLineNumberAtAddr(BaseAddress: ULONG_PTR;
  var AUnitName: string): Integer;
var
  Data: TLineData;
begin
  if FLines.TryGetValue(BaseAddress, Data) then
  begin
    AUnitName := FUnits[Data.UnitIndex];
    Result := Data.LineNumber;
  end
  else
    Result := -1;
end;

function TDebugMap.GetLineNumberAtAddrForced(BaseAddress: ULONG_PTR;
  Limit: Integer; var UnitName: string): Integer;
var
  I: Integer;
begin
  Result := -1;
  for I := 0 to Limit do
  begin
    Result := GetLineNumberAtAddr(BaseAddress + ULONG_PTR(I), UnitName);
    if Result > 0 then
      Break;
  end;
end;

procedure TDebugMap.Init(BaseAddress: ULONG_PTR; const ModulePath: string);
var
  I, Count: Integer;
  Line: string;
  MapFile: TStringList;

  function NextLine: Boolean;
  begin
    Inc(I);
    Result := I < Count;
    if Result then
      Line := Trim(MapFile[I]);
  end;

  procedure SkipEmptyLines;
  begin
    while NextLine do
      if Line <> '' then
        Break;
  end;

  function GetSeparatorPos: Integer;
  var
    Index: Integer;
  begin
    Result := Pos(' ', Line);
    Index := Pos(':', Line);
    if Result = 0 then
      Result := Index
    else
      if (Result > Index) and (Index > 0) then
        Result := Index;
  end;

  procedure SkipNextTag;
  var
    Index: Integer;
  begin
    Index := GetSeparatorPos;
    if Index > 0 then
    begin
      Delete(Line, 1, Index);
      Line := TrimLeft(Line);
    end
    else
      Line := '';
  end;

  function GetIntTag: Integer;
  begin
    TryStrToInt(Line, Result);
    SkipNextTag;
  end;

  function GetPtrTag: ULONG_PTR;
  var
    Tmp: UInt64;
  begin
    TryStrToUInt64('0x' + Line, Tmp);
    Result := Tmp;
    SkipNextTag;
  end;

  function GetStrTag: string;
  var
    Index: Integer;
  begin
    Index := GetSeparatorPos;
    if Index > 0 then
    begin
      Result := Copy(Line, 1, Index - 1);
      Delete(Line, 1, Index);
      Line := TrimLeft(Line);
    end
    else
    begin
      Result := Line;
      Line := '';
    end;
  end;

var
  PEImage: TPEImage;
  SectionDataList: TList<TSectionData>;
  A, StartPosition, SpacePos, SectionIndex: Integer;
  MapPath, SectionName, SectionClass, AUnitName: string;
  Section: TSectionData;
  FoundTable: Boolean;
  SectionAddress, LineAddress: ULONG_PTR;
  DebugMapItem: TDebugMapItem;
  LineData: TLineData;
begin
  StartPosition := FItems.Count;
  try
    MapFile := TStringList.Create;
    try

      MapPath := ChangeFileExt(ModulePath, '.map');
      if not FileExists(MapPath) then
        raise Exception.CreateFmt('"%s" not found.', [MapPath]);

      if FLoadedMap.IndexOf(MapPath) >= 0 then Exit;
      FLoadedMap.Add(MapPath);

      MapFile.LoadFromFile(MapPath);
      DebugMapItem.ModuleName := ExtractFileName(ModulePath);

      SectionDataList := TList<TSectionData>.Create;
      try
        PEImage := TPEImage.Create(0);
        try
          PEImage.GetInfoFromImage(ModulePath, nil, 0);

          I := 0;
          Count := MapFile.Count;

          // ищем начало таблицы секций
          Line := Trim(MapFile[I]);
          while not Line.StartsWith('Start') do
            if not NextLine then Exit;

          // получаем номер секции и ее имя
          SkipEmptyLines;
          while Line <> '' do
          begin
            Section.Index := GetIntTag;
            SkipNextTag;
            SkipNextTag;
            SectionName := GetStrTag;
            if SectionName = '' then
            begin
              if NextLine then
                Continue
              else
                Exit;
            end;

            // в старых версиях дельфи в РЕ файле имя секции называлось по имени ее класса
            // поэтому будем искать правильную секцию опираясь на этот момент
            SectionClass := Line;

            // убираем декорирование (MS VC++ Debug MAP)
            SpacePos := Pos('$', SectionName);
            if SpacePos > 0 then
              SectionName := Copy(SectionName, 1, SpacePos - 1);

            // если секция содержит код, заносим ее в список
            for A := 0 to PEImage.Sections.Count - 1 do
              if (PEImage.Sections[A].Caption = ShortString(SectionName)) or
                (PEImage.Sections[A].Caption = ShortString(SectionClass)) then
              begin
                Section.StartAddr := PEImage.Sections[A].Address + BaseAddress;
                Section.Length := PEImage.Sections[A].Size;
                Section.Executable := PEImage.Sections[A].IsCode;
                SectionDataList.Add(Section);
                Break;
              end;

            if not NextLine then
              Exit;
          end;
        finally
          PEImage.Free;
        end;

        // ищем начало таблицы "Publics by Value"
        FoundTable := False;
        SkipEmptyLines;
        while not FoundTable do
        begin
          while not Line.StartsWith('Address') do
            if not NextLine then Exit;

          SkipNextTag;
          FoundTable := Line.StartsWith('Publics by Value');
        end;

        // парсим таблицу "Publics by Value"
        SkipEmptyLines;
        if I >= Count then Exit;
        while Line <> '' do
        begin
          SectionIndex := GetIntTag;
          SectionAddress := $FFFFFFFF;
          for A := 0 to SectionDataList.Count - 1 do
            if SectionDataList[A].Index = SectionIndex then
            begin
              SectionAddress := SectionDataList[A].StartAddr;
              DebugMapItem.Executable := SectionDataList[A].Executable;
              Break;
            end;
          if SectionAddress = $FFFFFFFF then
          begin
            if NextLine then
              Continue
            else
              Break;
          end;
          DebugMapItem.Address := SectionAddress + GetPtrTag;
          DebugMapItem.FunctionName := GetStrTag;
          FItems.Add(DebugMapItem);
          if not NextLine then
            Break;
        end;

        // парсим все "Line numbers for"
        if LoadLines then
        begin
          SkipEmptyLines;
          while I < Count do
          begin
            while not Line.StartsWith('Line numbers for ', True) do
              if not NextLine then Break;

            SpacePos := Pos('(', Line);
            Delete(Line, 1, SpacePos);
            SpacePos := Pos(')', Line);
            AUnitName := Copy(Line, 1, SpacePos - 1);
            LineData.UnitIndex := StrHash(AUnitName);
            FUnits.TryAdd(LineData.UnitIndex, AUnitName);

            SkipEmptyLines;
            if I >= Count then
              Break;

            // загружаем данные по каждому модулю
            while Line <> '' do
            begin
              while Line <> '' do
              begin

                // Line
                LineData.LineNumber := GetIntTag;
                // Section
                SectionIndex := GetIntTag;
                SectionAddress := $FFFFFFFF;
                for A := 0 to SectionDataList.Count - 1 do
                  if SectionDataList[A].Index = SectionIndex then
                  begin
                    SectionAddress := SectionDataList[A].StartAddr;
                    Break;
                  end;
                if SectionAddress = $FFFFFFFF then
                begin
                  SkipNextTag;
                  Continue;
                end;

                LineAddress := GetPtrTag;
                FLines.TryAdd(SectionAddress + LineAddress, LineData);
              end;
              if not NextLine then
                Break;
            end;
            SkipEmptyLines;
          end;
        end;

      finally
        SectionDataList.Free;
      end;
    finally
      MapFile.Free;
    end;

    FItems.Sort;
  except
    // если не смогли распарсить - выкидываем все из массива данных
    for I := FItems.Count - 1 downto StartPosition do
      FItems.Delete(I);
  end;
end;

function TDebugMap.ModuleLoaded(const ModuleName: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 0 to FItems.Count - 1 do
    if FItems[I].ModuleName = ModuleName then
    begin
      Result := True;
      Break;
    end;
end;

function TDebugMap.StrHash(const Value: string): Integer;
begin
  Result := THashBobJenkins.GetHashValue(Value);
end;

end.

