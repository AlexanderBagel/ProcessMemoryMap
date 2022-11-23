////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uRichParser.pas
//  * Purpose   : Классы для парсинга Rich заголовков
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2022.
//  * Version   : 1.0
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uRichParser;

interface

uses
  Windows,
  Classes,
  SysUtils,
  Generics.Collections,
  pmm_plugin;

type
  // типы данных в том порядке в каком они обычно идут в заголовке
  TRichItemType =
    (
      ritDosStub,      // 16-битный DOS стаб
      ritBeginProdId,  // начало списка идентификаторов с контрольной суммой
      ritObject,       // идентификаторы продуктов со счетчиками
      ritEndProdId,    // конец списка идентификаторов с XOR ключем
      ritNull          // пустые элементы для выравнивания
    );

  TProdItem = record
    AddrVA: ULONG64;
    Size: DWORD;
    ProdId: DWORD; // Product identity
    Count: DWORD;  // Count of objects built with that product
    ItemType: TRichItemType;
  end;

  TPeRichSignReader = class
  private const
    tagBegID = $68636952;
    tagEndID = $536E6144;
    SizeOfDefaultDosStub = $40;
  private
    FData: TList<TProdItem>;
    FValid: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Load(const FilePath: string; AInstance: ULONG64);
    property Items: TList<TProdItem> read FData;
    property Valid: Boolean read FValid;
  end;

  TRawData = record
    NameSpace,
    Caption,
    Description: string;
    Size: DWORD;
  end;

  TRichManager = class
  private
    FSignReader: TPeRichSignReader;
    FData: TList<TProdItem>;
    procedure AppenData(Value: TList<TProdItem>);
  public
    constructor Create;
    destructor Destroy; override;
    procedure OpenProcess(AModuleList: PProcessModule);
    function GetDescriptorData(const Index: Integer;
      var Data: TRawData): Boolean;
    property Items: TList<TProdItem> read FData;
  end;

implementation

{ TPeRichSignReader }

constructor TPeRichSignReader.Create;
begin
  FData := TList<TProdItem>.Create;
end;

destructor TPeRichSignReader.Destroy;
begin
  FData.Free;
  inherited;
end;

procedure TPeRichSignReader.Load(const FilePath: string; AInstance: ULONG64);
var
  Cursor: Integer;
  Buff: array of Byte;

  function ReadDWORD: DWORD;
  begin
    Dec(Cursor, 4);
    if Cursor >= 0 then;
      Result := PDWORD(@Buff[Cursor])^;
  end;

var
  Size, Index: Integer;
  Item: TProdItem;
  Mask: DWORD;
  AStream: TFileStream;
  idh: TImageDosHeader;
begin
  FValid := False;
  FData.Clear;

  // Зачитываем все целиком, так как искать будем с конца
  // За одно при нахождении маркера tagEndID автоматом рассчитаем
  // размер MS-DOS стаба
  AStream := TFileStream.Create(FilePath, fmShareDenyWrite);
  try
    if AStream.Read(idh, SizeOf(TImageDosHeader)) <> SizeOf(TImageDosHeader) then
      Exit;
    Size := idh._lfanew - SizeOf(TImageDosHeader);
    Cursor := Size;
    SetLength(Buff, Size);
    if AStream.Read(Buff[0], Size) <> Size then
      Exit;
  finally
    AStream.Free;
  end;

  // Rich идет сразу за DOS заголовком, учитываем его
  Inc(AInstance, SizeOf(TImageDosHeader));

  // Ищем начало
  Mask := 0;
  while Cursor > 0 do
  begin
    Item.Count := ReadDWORD;
    Item.ProdId := ReadDWORD;
    Item.AddrVA := AInstance + Cardinal(Cursor);
    Item.Size := 8;
    if Item.ProdId = tagBegID then
    begin
      Item.ItemType := ritBeginProdId;
      Mask := Item.Count;
      FData.Insert(0, Item);
      Break;
    end
    else
      Item.ItemType := ritNull;
    FData.Insert(0, Item);
  end;

  // зачитываем все элементы с последнего по первый
  Index := 0;
  while Cursor > 0 do
  begin
    Inc(Index);
    Item.ItemType := ritObject;
    Item.Count := ReadDWORD xor Mask;
    Item.ProdId := ReadDWORD xor Mask;
    Item.AddrVA := AInstance + UINT(Cursor);
    Item.Size := 8;
    if Item.ProdId = tagEndID then
    begin
      Item.ItemType := ritEndProdId;
      FData.Insert(0, Item);
      Break;
    end
    else
      FData.Insert(0, Item);
  end;

  // проверка - все ли правильно?
  FValid :=
    (Index <> 0) and
    (Items.Count > 2) and
    (Items.List[Index].ProdId = tagBegID) and
    (Items.List[Index].Count <> 0) and // контрольная сумма заголовка с расшифрованным Rich
    (Items.List[0].ProdId = tagEndID) and
    (Items.List[0].Count = 0) and
    (FData.List[1].ProdId = 0) and
    (FData.List[1].Count = 0){ and
    (Cursor = SizeOfDefaultDosStub)};

  // если все правильно, курсор расположен в самом конце
  // 16-битной MS-DOS заглушки, которую тоже добавляем в список
  // (если под неё осталось место)
  if FValid and (Cursor > 0) then
  begin
    Item.ItemType := ritDosStub;
    Item.AddrVA := AInstance;
    Item.Size := Cursor;
    Item.ProdId := 0;
    Item.Count := 0;
    FData.Insert(0, Item);
  end;
end;

{ TRichManager }

procedure TRichManager.AppenData(Value: TList<TProdItem>);
begin
  for var Item in Value do
    FData.Add(Item);
end;

constructor TRichManager.Create;
begin
  FData := TList<TProdItem>.Create;
  FSignReader := TPeRichSignReader.Create;
end;

destructor TRichManager.Destroy;
begin
  FSignReader.Free;
  FData.Free;
  inherited;
end;

function TRichManager.GetDescriptorData(const Index: Integer;
  var Data: TRawData): Boolean;
var
  Item: TProdItem;

  function GetItemVersion: string;
  begin
    Result := Format('Id: %.3d Build: %d Count: %d', [
      HiWord(Item.ProdId), LoWord(Item.ProdId), Item.Count]);
  end;

  // https://bytepointer.com/articles/the_microsoft_rich_header.htm
  function GetItemDescription: string;
  var
    HiStr, LoStr: string;
  begin
    HiStr := EmptyStr;
    case HiWord(Item.ProdId) of
      1: HiStr := 'Total count of imported DLL functions referenced';
      2: HiStr := 'LINK 5.10 (Visual Studio 97 SP3)';
      3: HiStr := 'LINK 5.10 (Visual Studio 97 SP3) OMF to COFF conversion';
      4: HiStr := 'LINK 6.00 (Visual Studio 98)';
      5: HiStr := 'LINK 6.00 (Visual Studio 98) OMF to COFF conversion';
      6: HiStr := 'CVTRES 5.00';
      7: HiStr := 'VB 5.0 native code';
      8: HiStr := 'VC++ 5.0 C/C++';
      9: HiStr := 'VB 6.0 native code';
      10: HiStr := 'VC++ 6.0 C';
      11: HiStr := 'VC++ 6.0 C++';
      12: HiStr := 'ALIASOBJ.EXE (CRT Tool that builds OLDNAMES.LIB)';
      13: HiStr := 'VB 6.0 generated object';
      14: HiStr := 'MASM 6.13';
      15: HiStr := 'MASM 7.01';
      16: HiStr := 'LINK 5.11';
      17: HiStr := 'LINK 5.11 OMF to COFF conversion';
      18: HiStr := 'MASM 6.14 (MMX2 support)';
      19: HiStr := 'LINK 5.12';
      20: HiStr := 'LINK 5.12 OMF to COFF conversion';
      42: HiStr := 'MASM 6.15';
    end;
    LoStr := EmptyStr;

    // https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.21
    case LoWord(Item.ProdId) of
      7299: LoStr := 'MASM 6.13';
      8444: LoStr := 'MASM 6.14';
      8803: LoStr := 'MASM 6.15';

      8169: LoStr := 'Visual Basic 6.0';
      8495: LoStr := 'Visual Basic 6.0 SP3';
      8877: LoStr := 'Visual Basic 6.0 SP4';
      8964: LoStr := 'Visual Basic 6.0 SP5';

      8168: LoStr := 'Visual Studio 6.0 (RTM)';
      8447: LoStr := 'Visual Studio 6.0 SP3';

      8799: LoStr := 'Visual Studio 6.0 SP4';
      8966: LoStr := 'Visual Studio 6.0 SP5';
      9044: LoStr := 'Visual Studio 6.0 SP5 Processor Pack';
      9782: LoStr := 'Visual Studio 6.0 SP6';
      9030: LoStr := 'Visual Studio 7.0 2000 (BETA 1)';
      9254: LoStr := 'Visual Studio 7.0 2001 (BETA 2)';
      9466: LoStr := 'Visual Studio 7.0 2002';
      9955: LoStr := 'Visual Studio 7.0 2002 SP1';
      3077: LoStr := 'Visual Studio 7.1 2003 (cl.exe 13.10.3077)';
      3052: LoStr := 'Visual Studio 7.1 2003 Free Toolkit ';
      4035: LoStr := 'Visual Studio 7.1 2003 (cl.exe 13.10.4035)';
      6030: LoStr := 'Visual Studio 7.1 2003 SP1';
      50327: LoStr := 'Visual Studio 8.0 2005 (Beta)';
      50727: LoStr := 'Visual Studio 8.0 2005';
      21022: LoStr := 'Visual Studio 9.0 2008';
      30411: LoStr := 'Visual Studio 9.0 2008 ?';
      30729: LoStr := 'Visual Studio 9.0 2008 SP1';
      30319: LoStr := 'Visual Studio 10.0 2010';
      40219: LoStr := 'Visual Studio 10.0 2010 SP1';
      //50727: LoStr := 'Visual Studio 11.0 2012 (cl.exe 17.00.50727)';
      51025: LoStr := 'Visual Studio 11.0 2012';
      51106: LoStr := 'Visual Studio 11.0 2012 update 1';
      60315: LoStr := 'Visual Studio 11.0 2012 update 2';
      60610: LoStr := 'Visual Studio 11.0 2012 update 3';
      61030: LoStr := 'Visual Studio 11.0 2012 update 4';
      21005: LoStr := 'Visual Studio 12.0 2013';
      30501: LoStr := 'Visual Studio 12.0 2013 update 2';
      31101: LoStr := 'Visual Studio 12.0 2013 update 4';
      40629: LoStr := 'Visual Studio 12.0 2013 SP5';
      40660: LoStr := 'Visual Studio 12.0 2013 SP?';
      22215: LoStr := 'Visual Studio 14.0 2015 (cl.exe 19.00.22215 Preview)';
      23026: LoStr := 'Visual Studio 14.0 2015 (cl.exe 19.00.23026.0)';
      23506: LoStr := 'Visual Studio 14.0 2015 SP1';
      23824: LoStr := 'Visual Studio 14.0 2015 update 2';
      23918, 24212: LoStr := 'Visual Studio 14.0 2015';
      24215: LoStr := 'Visual Studio 14.0 2015 (cl.exe 19.00.24215.1)';
      24218: LoStr := 'Visual Studio 14.0 2015 (cl.exe 19.00.24218.2)';
      25017: LoStr := 'Visual Studio 14.? 2017';
      25019: LoStr := 'Visual Studio 14.1 2017';
      29112: LoStr := 'Visual Studio 14.27 2019';
      30133: LoStr := 'Visual Studio 16.? 2019';
      31630: LoStr := 'Visual Studio 17.3 2022';
    end;
    Result := Trim(HiStr + ' ' + LoStr);
  end;

const
  RichSignData = 'Microsoft Linker ID Statistics';
begin
  Result := (Index >= 0) and (Index < Items.Count);
  if not Result then Exit;
  Item := Items[Index];
  Data.Size := Item.Size;
  if Item.ItemType <> ritDosStub then
    Data.NameSpace := RichSignData;
  case Item.ItemType of
    ritDosStub:
    begin
      Data.NameSpace := 'MS-DOS Stub';
      Data.Caption := EmptyStr;
      Data.Description := EmptyStr;
    end;
    ritBeginProdId:
    begin
      Data.Caption := 'Begin ProductID (RichSign)';
      Data.Description := 'Mask = ' + IntToHex(Item.Count);
    end;
    ritObject:
    begin
      if (Item.ProdId = 0) and (Item.Count = 0) then
      begin
        Data.Caption := ' '; // пробелом указываем что описание есть, но пустое!
        Data.Description := 'end of tallies (Masked)';
      end
      else
      begin
        Data.Caption := GetItemVersion;
        Data.Description := GetItemDescription;
      end;
    end;
    ritEndProdId:
    begin
      Data.Caption := 'End ProductID';
      Data.Description := 'start of tallies (Masked)';
    end;
  else
    // ritNull
    Data.Caption := EmptyStr;
    Data.Description := EmptyStr;
  end;
end;

procedure TRichManager.OpenProcess(AModuleList: PProcessModule);
begin
  FData.Clear;
  while AModuleList <> nil do
  begin
    FSignReader.Load(AModuleList.ImagePath, AModuleList.Instance);
    if FSignReader.Valid then
      AppenData(FSignReader.Items);
    AModuleList := AModuleList.FLink;
  end;
end;

end.
