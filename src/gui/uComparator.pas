////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uComparator.pas
//  * Purpose   : Диалог отображает результаты сравнения двух карт памяти процесса
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2013, 2023.
//  * Version   : 1.4.30
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uComparator;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.ComCtrls, System.TypInfo,
  Generics.Collections, Winapi.RichEdit, Vcl.Menus,

  MemoryMap.Core,
  MemoryMap.RegionData,
  MemoryMap.Heaps,
  MemoryMap.Threads,
  MemoryMap.PEImage,
  ScaledCtrls,

  uBaseForm;

type
  TChangeType = (ctAdd, ctChange, ctDel);
  TdlgComparator = class(TBaseAppForm)
    Panel1: TPanel;
    Button1: TButton;
    btnSave: TButton;
    SaveDialog: TSaveDialog;
    PopupMenu: TPopupMenu;
    mnuCopy: TMenuItem;
    edChanges: TRichEdit;
    SelectAll1: TMenuItem;
    procedure btnSaveClick(Sender: TObject);
    procedure mnuCopyClick(Sender: TObject);
    procedure SelectAll1Click(Sender: TObject);
  private
    FOldMM, FNewMM: TMemoryMap;
    TotalChanges: Integer;
    OnProgressDelta: Integer;
    RTF: string;
    RegionAdded: Boolean;
    OldRegion, NewRegion: TRegionData;
    procedure AddChanged(const Value: string;
      ChangeType: TChangeType = ctChange);
    procedure AddData(Value: string; ChangeType: TChangeType);
    procedure AddRegionInfo(ARegion: TRegionData; ChangeType: TChangeType);
    procedure AddSplit;
    function ComparePtr(A, B: Pointer): Integer;
    procedure CompareContains(OldValue, NewValue: TList<TContainItem>);
    procedure CompareDirectories(OldValue, NewValue: TList<TDirectory>);
    procedure CompareHeap(OldValue, NewValue: THeapData);
    procedure CompareRegion;
    procedure CompareSystem(OldValue, NewValue: TSystemData);
    procedure CompareThread(OldValue, NewValue: TThreadData);
    procedure CompareValues(const Description: string; OldValue, NewValue: string);
    procedure RegionChanged(ARegion: TRegionData;
      ChangeType: TChangeType);
  protected
    procedure DoProgress(Value: TMemoryStream);
  public
    function CompareMemoryMaps(OldMM, NewMM: TMemoryMap): Boolean;
  end;

var
  dlgComparator: TdlgComparator;

implementation

uses
  uUtils,
  uProgress,
  uDisplayUtils;

{$R *.dfm}

{ TdlgComparator }

procedure TdlgComparator.AddChanged(const Value: string;
  ChangeType: TChangeType);
begin
  if not RegionAdded then
  begin
    RegionAdded := True;
    Inc(TotalChanges);
    AddRegionInfo(OldRegion, ctChange);
  end;
  AddData(Value, ChangeType);
end;

procedure TdlgComparator.AddData(Value: string; ChangeType: TChangeType);
const
  ChangeTypeColor: array [TChangeType] of string = ('\cf1 ', '\cf2 ', '\cf3 ');
begin
  // RTF формируем самостоятельно, бо построчное добавление
  // в RichEdit тормозит шибко
  Value := StringReplace(Value, '\', '\\', [rfReplaceAll]);
  if RTF = '' then
  begin
    RTF :=
      '{\rtf1\ansi\ansicpg1251\deff0\deflang1049{\fonttbl{\f0\fnil\fcharset204 Tahoma;}}' + sLineBreak +
      '{\colortbl ;\red118\green146\blue50;\red220\green136\blue0;\red204\green0\blue102;}' + sLineBreak +
      '\viewkind4\uc1\pard' + Trim(ChangeTypeColor[ChangeType]) + '\b\f0\fs16 ' +
      Value + '\cf0\par' +  sLineBreak;
  end
  else
    RTF := RTF + ChangeTypeColor[ChangeType] + Value + '\cf0\par' + sLineBreak;
end;

procedure TdlgComparator.AddRegionInfo(ARegion: TRegionData;
  ChangeType: TChangeType);
const
  ChangeTypeStr: array [TChangeType] of string =
    ('added', 'changed', 'removed');
begin
  AddData(IntToStr(TotalChanges) +  ': Region ' +
    ChangeTypeStr[ChangeType] + ' at address: ' +
    UInt64ToStr(ARegion.MBI.BaseAddress), ChangeType);
  if ARegion.RegionVisible then
  begin
    AddData('Region Type: ' + Trim(GetLevel1RegionTypeString(ARegion)), ChangeType);
    AddData('Region size: ' + SizeToStr2(ARegion.TotalRegionSize), ChangeType);
  end
  else
  begin
    AddData('Region Type: ' + Trim(GetLevel2RegionTypeString(ARegion)), ChangeType);
    AddData('Region size: ' + SizeToStr2(ARegion.MBI.RegionSize), ChangeType);
  end;
  AddData('Last region address: ' +
    UInt64ToStr(NativeUInt(ARegion.MBI.BaseAddress) +
    ARegion.MBI.RegionSize - 1), ChangeType);
end;

procedure TdlgComparator.AddSplit;
begin
  RTF := RTF + '\par' + sLineBreak;
end;

procedure TdlgComparator.btnSaveClick(Sender: TObject);
var
  SavePath, TempPath: string;
  Y, M, D, h, mm, s, ms: Word;
begin
  DecodeDate(Now, Y, M, D);
  DecodeTime(Now, h, mm, s, ms);
  SavePath := MemoryMapCore.ProcessName;
  if Copy(SavePath, Length(SavePath) - 3, 4) = ' *32' then
    Delete(SavePath, Length(SavePath) - 3, 4);
  TempPath := Format('.compare %d %s %d %d-%d-%d.rtf', [D,
    FormatDateTime('mmm', Now), Y, h, mm, s]);
  SaveDialog.FileName := ChangeFileExt(SavePath, TempPath);
  if SaveDialog.Execute then
  begin
    edChanges.Lines.SaveToFile(SaveDialog.FileName);
    // помимо результатов сравнения сохраняем также обе карты памяти
    // дабы можно было потом поизучать изменения более подробно
    SavePath := SaveDialog.FileName;
    TempPath := ChangeFileExt(SavePath, '.oldmap.pmm');
    FOldMM.SaveToFile(TempPath);
    TempPath := ChangeFileExt(SavePath, '.newmap.pmm');
    FNewMM.SaveToFile(TempPath);
    Close;
  end;
end;

type
  PCookie = ^TCookie;
  TCookie = record
    Dialog: TdlgComparator;
    Stream: TMemoryStream;
  end;

function EditStreamCallBack(Cookie: PCookie; pbBuff: PByte;
  cb: Longint; var pcb: Longint): Longint; stdcall;
begin
  Result := 0;
  try
    pcb := Cookie^.Stream.Read(pbBuff^, cb);
    Cookie^.Dialog.DoProgress(Cookie^.Stream);
  except
    Result := 1;
  end;
end;

procedure TdlgComparator.CompareValues(const Description: string; OldValue,
  NewValue: string);
begin
  if OldValue <> NewValue then
  begin
    if Trim(OldValue) = '' then
      OldValue := '""';
    if Trim(NewValue) = '' then
      NewValue := '""';
    AddChanged(Description + ' changed: ' + OldValue + ' -> ' + NewValue);
  end;
end;

procedure TdlgComparator.CompareContains(OldValue,
  NewValue: TList<TContainItem>);
var
  Dict: TDictionary<string, TContainItem>;
  OldCont, NewCont: TContainItem;
  Address: NativeUInt;
begin
  Address := 0;
  Dict := TDictionary<string, TContainItem>.Create(NewValue.Count);
  try
    // сначала собираем данные по новым значениям
    for NewCont in NewValue do
      Dict.Add(NewCont.Hash, NewCont);

    // теперь делаем сверку по старым значениям
    for OldCont in OldValue do
    begin

      // если значение из старого листа присутствует в новом, удаляем его из списка
      if Dict.TryGetValue(OldCont.Hash, NewCont) then
      begin
        case OldCont.ItemType of
          itHeapBlock: CompareHeap(OldCont.Heap, NewCont.Heap);
          itThreadData: CompareThread(OldCont.ThreadData, NewCont.ThreadData);
          itSystem: CompareSystem(OldCont.System, NewCont.System);
        end;
        Dict.Remove(OldCont.Hash);
        Continue;
      end;

      // в противном случае говорим что значение удалено
      case OldCont.ItemType of
        itHeapBlock: Address := OldCont.Heap.Entry.Address;
        itThreadData: Address := NativeUInt(OldCont.ThreadData.Address);
        itSystem: Address := NativeUInt(OldCont.System.Address);
      end;
      AddChanged(
        GetEnumName(TypeInfo(TContainItemType), Integer(OldCont.ItemType)) +
        '" removed at address: ' + UInt64ToStr(Address), ctDel);

    end;

    // все что осталось в словаре - добавленные значения
    for NewCont in Dict.Values do
    begin
      case NewCont.ItemType of
        itHeapBlock: Address := NewCont.Heap.Entry.Address;
        itThreadData: Address := NativeUInt(NewCont.ThreadData.Address);
        itSystem: Address := NativeUInt(NewCont.System.Address);
      end;
      AddChanged(
        GetEnumName(TypeInfo(TContainItemType), Integer(NewCont.ItemType)) +
        '" added at address: ' + UInt64ToStr(Address), ctAdd);
    end;
  finally
    Dict.Free;
  end;
end;

procedure TdlgComparator.CompareDirectories(OldValue,
  NewValue: TList<TDirectory>);
var
  Dict: TDictionary<ShortString, TDirectory>;
  OldDir, NewDir: TDirectory;
begin
  Dict := TDictionary<ShortString, TDirectory>.Create(NewValue.Count);
  try
    // сначала собираем данные по новым директориям
    for NewDir in NewValue do
      Dict.Add(NewDir.Caption, NewDir);

    // теперь делаем сверку по старым
    for OldDir in OldValue do
    begin

      // если директория из старого листа присутствует в новом, удаляем ее из списка
      if Dict.TryGetValue(OldDir.Caption, NewDir) then
      begin
        CompareValues('Directory "' + string(OldDir.Caption) + '" address',
          UInt64ToStr(OldDir.Address),
          UInt64ToStr(NewDir.Address));
        CompareValues('Directory "' + string(OldDir.Caption) + '" size',
          SizeToStr2(OldDir.Size),
          SizeToStr2(NewDir.Size));
        Dict.Remove(OldDir.Caption);
        Continue;
      end;

      // в противном случае говорим что директория удалена
      AddChanged('Directory "' + string(OldDir.Caption) +
        '" removed at address: ' + UInt64ToStr(OldDir.Address), ctDel);
      AddChanged('Directory size: ' + SizeToStr2(OldDir.Size), ctDel);

    end;

    // все что осталось в словаре - добавленные директории
    for NewDir in Dict.Values do
    begin
      AddChanged('Directory "' + string(NewDir.Caption) +
        '" added at address: ' + UInt64ToStr(NewDir.Address), ctAdd);
      AddChanged('Directory size: ' + SizeToStr2(NewDir.Size), ctAdd);
    end;

  finally
    Dict.Free;
  end;
end;

procedure TdlgComparator.CompareHeap(OldValue, NewValue: THeapData);
begin
  CompareValues('Heap.ID', IntToStr(OldValue.ID), IntToStr(NewValue.ID));
  CompareValues('Heap.Entry.Address',
    UInt64ToStr(OldValue.Entry.Address),
    UInt64ToStr(NewValue.Entry.Address));
  CompareValues('Heap.Entry.Size',
    SizeToStr2(OldValue.Entry.Size),
    SizeToStr2(NewValue.Entry.Size));
  CompareValues('Heap.Entry.Flags',
    ExtractHeapEntryString(OldValue.Entry.Flags),
    ExtractHeapEntryString(NewValue.Entry.Flags));
end;

function TdlgComparator.CompareMemoryMaps(OldMM, NewMM: TMemoryMap): Boolean;
var
  OldIndex, NewIndex: Integer;
  ProgressDelta: NativeInt;

  procedure IncSearchPos(Value: Integer);
  begin
    if TotalChanges > 0 then
    begin
      dlgProgress.lblProgress.Caption := 'Found changes: ' + IntToStr(TotalChanges);
      dlgProgress.ProgressBar.Position := Value div ProgressDelta;
      if not dlgProgress.Visible then
        dlgProgress.Show;
      Application.ProcessMessages;
    end;
  end;

var
  M: TMemoryStream;
  ARtf: AnsiString;
  Param: TEditStream;
  Cookie: TCookie;
begin
  OldIndex := 0;
  NewIndex := 0;
  ProgressDelta := OldMM.TotalCount div 100;
  FOldMM := OldMM;
  FNewMM := NewMM;
  dlgProgress := TdlgProgress.Create(nil);
  try
    while OldIndex < OldMM.TotalCount do
    begin
      IncSearchPos(OldIndex);
      OldRegion := OldMM.GetRegionAtUnfilteredIndex(OldIndex);

      // если новых регионов больше нет, значит все старые удалены
      if NewIndex >= NewMM.TotalCount then
      begin
        RegionChanged(OldRegion, ctDel);
        Inc(OldIndex);
        Continue;
      end;

      NewRegion := NewMM.GetRegionAtUnfilteredIndex(NewIndex);

      case ComparePtr(OldRegion.MBI.BaseAddress, NewRegion.MBI.BaseAddress) of
        // Если адреса регионов совпали - сравниваем их
        0: CompareRegion;

        // если адрес нового региона больше текущего - текущий удален
       -1:
        begin
          // и все регионы, которые были расположены до этого адреса тоже удалены
          repeat
            RegionChanged(OldRegion, ctDel);
            Inc(OldIndex);
            OldRegion := OldMM.GetRegionAtUnfilteredIndex(OldIndex);
          until ComparePtr(OldRegion.MBI.BaseAddress, NewRegion.MBI.BaseAddress) >= 0;
          Continue;
        end;

        // а если адрес нового региона меньше текущего - то добавился новый регион
        1:
        begin
          // причем добавленных может быть также несколько
          repeat
            RegionChanged(NewRegion, ctAdd);
            Inc(NewIndex);
            NewRegion := NewMM.GetRegionAtUnfilteredIndex(NewIndex);
          until ComparePtr(OldRegion.MBI.BaseAddress, NewRegion.MBI.BaseAddress) <= 0;
          Continue;
        end;
      end;
      Inc(OldIndex);
      Inc(NewIndex);
    end;

    // если остались новые регионы, то они все добавленные
    while NewIndex < NewMM.TotalCount do
    begin
      NewRegion := NewMM.GetRegionAtUnfilteredIndex(NewIndex);
      RegionChanged(NewRegion, ctAdd);
      Inc(NewIndex);
      Continue;
    end;

    Result := TotalChanges = 0;
    if not Result then
    begin
      dlgProgress.lblProgress.Caption :=
        dlgProgress.lblProgress.Caption + '. Loading...';
      // загружаем RTF руками через API, ибо Lines.LoadFromStream
      // периодически грузит данные криво
      RTF := RTF + '}' + #0;
      M := TMemoryStream.Create;
      try
        ARtf := AnsiString(RTF);
        M.Write(ARtf[1], Length(ARtf));
        M.Position := 0;
        OnProgressDelta := M.Size div 100;
        Cookie.Dialog := Self;
        Cookie.Stream := M;
        Param.dwCookie := DWORD_PTR(@Cookie);
        Param.dwError := 0;
        Param.pfnCallback := @EditStreamCallBack;
        SendMessage(edChanges.Handle, EM_STREAMIN, SF_RTF, LPARAM(@Param));
      finally
        M.Free;
      end;
    end;
  finally
    dlgProgress.Free;
  end;
  if not Result then
    ShowModal;
end;

function TdlgComparator.ComparePtr(A, B: Pointer): Integer;
begin
  if ULONG_PTR(A) = ULONG_PTR(B) then
    Exit(0);
  if ULONG_PTR(A) > ULONG_PTR(B) then
    Result := 1
  else
    Result := -1;
end;

procedure TdlgComparator.CompareRegion;
begin
  RegionAdded := False;
  CompareValues('RegionType',
    GetEnumName(TypeInfo(TRegionType), Integer(OldRegion.RegionType)),
    GetEnumName(TypeInfo(TRegionType), Integer(NewRegion.RegionType)));
  CompareValues('MBI.AllocationBase',
    UInt64ToStr(OldRegion.MBI.AllocationBase),
    UInt64ToStr(NewRegion.MBI.AllocationBase));
  CompareValues('MBI.AllocationProtect',
    ExtractInitialAccessString(OldRegion.MBI.AllocationProtect),
    ExtractInitialAccessString(NewRegion.MBI.AllocationProtect));
  CompareValues('MBI.RegionSize',
    SizeToStr2(OldRegion.MBI.RegionSize),
    SizeToStr2(NewRegion.MBI.RegionSize));
  CompareValues('MBI.State',
    ExtractRegionTypeString(OldRegion.MBI),
    ExtractRegionTypeString(NewRegion.MBI));
  CompareValues('MBI.Protect',
    ExtractAccessString(OldRegion.MBI.Protect),
    ExtractAccessString(NewRegion.MBI.Protect));
  CompareValues('Details',
    OldRegion.Details,
    NewRegion.Details);
  CompareValues('RegionVisible',
    BoolToStr(OldRegion.RegionVisible, True),
    BoolToStr(NewRegion.RegionVisible, True));
  CompareValues('HiddenRegionCount',
    IntToStr(OldRegion.HiddenRegionCount),
    IntToStr(NewRegion.HiddenRegionCount));
  CompareValues('TotalRegionSize',
    SizeToStr2(OldRegion.TotalRegionSize),
    SizeToStr2(NewRegion.TotalRegionSize));
  CompareValues('Shared',
    BoolToStr(OldRegion.Shared, True),
    BoolToStr(NewRegion.Shared, True));
  CompareValues('SharedCount',
    IntToStr(OldRegion.SharedCount),
    IntToStr(NewRegion.SharedCount));
  CompareValues('Section.Caption',
    string(OldRegion.Section.Caption),
    string(NewRegion.Section.Caption));
  CompareValues('Section.Address',
    UInt64ToStr(OldRegion.Section.Address),
    UInt64ToStr(NewRegion.Section.Address));
  CompareValues('Section.Size',
    SizeToStr2(OldRegion.Section.Size),
    SizeToStr2(NewRegion.Section.Size));
  CompareValues('Section.IsCode',
    BoolToStr(OldRegion.Section.IsCode, True),
    BoolToStr(NewRegion.Section.IsCode, True));
  CompareValues('Section.IsData',
    BoolToStr(OldRegion.Section.IsData, True),
    BoolToStr(NewRegion.Section.IsData, True));
  CompareHeap(OldRegion.Heap, NewRegion.Heap);
  CompareThread(OldRegion.Thread, NewRegion.Thread);
  CompareSystem(OldRegion.SystemData, NewRegion.SystemData);
  CompareDirectories(OldRegion.Directory, NewRegion.Directory);
  CompareContains(OldRegion.Contains, NewRegion.Contains);
  if RegionAdded then
    AddSplit;
end;

procedure TdlgComparator.CompareSystem(OldValue, NewValue: TSystemData);
begin
  CompareValues('SystemData.Description',
    string(OldValue.Description),
    string(NewValue.Description));
  CompareValues('SystemData.Address',
    UInt64ToStr(OldValue.Address),
    UInt64ToStr(NewValue.Address));
end;

procedure TdlgComparator.CompareThread(OldValue, NewValue: TThreadData);
begin
  CompareValues('Thread.Flag',
    GetEnumName(TypeInfo(TThreadInfo), Integer(OldValue.Flag)),
    GetEnumName(TypeInfo(TThreadInfo), Integer(NewValue.Flag)));
  CompareValues('Thread.ThreadID',
    IntToStr(OldValue.ThreadID),
    IntToStr(NewValue.ThreadID));
  CompareValues('Thread.Address',
    UInt64ToStr(OldValue.Address),
    UInt64ToStr(NewValue.Address));
end;

procedure TdlgComparator.DoProgress(Value: TMemoryStream);
begin
  dlgProgress.ProgressBar.Position := Value.Position div OnProgressDelta;
  Application.ProcessMessages;
end;

procedure TdlgComparator.mnuCopyClick(Sender: TObject);
begin
  edChanges.CopyToClipboard;
end;

procedure TdlgComparator.RegionChanged(ARegion: TRegionData;
  ChangeType: TChangeType);
begin
  Inc(TotalChanges);
  AddRegionInfo(ARegion, ChangeType);
  AddSplit;
end;

procedure TdlgComparator.SelectAll1Click(Sender: TObject);
begin
  edChanges.SelectAll;
end;

end.
