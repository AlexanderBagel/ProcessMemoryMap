unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, System.StrUtils, Vcl.ComCtrls, Vcl.ExtCtrls, Vcl.ClipBrd,
  System.Actions, Vcl.ActnList, Vcl.Menus,

  MemoryMap.DebugMapData;

type
  TdlgStackConverter = class(TForm)
    btnOpen: TButton;
    OpenDialog: TOpenDialog;
    memStack: TMemo;
    btnConvert: TButton;
    pnTop: TPanel;
    Splitter: TSplitter;
    lvStack: TListView;
    pnBottom: TPanel;
    edBase: TLabeledEdit;
    lvPopupMenu: TPopupMenu;
    ActionList: TActionList;
    memPopupMenu: TPopupMenu;
    PasteCollStack1: TMenuItem;
    pnPaste: TPanel;
    btnPaste: TButton;
    acConvert: TAction;
    acCopyAddr: TAction;
    acCopyLine: TAction;
    acCopyAll: TAction;
    acPaste: TAction;
    acCopyAddr1: TMenuItem;
    acCopyLine1: TMenuItem;
    acCopyAll1: TMenuItem;
    N1: TMenuItem;
    procedure FormDestroy(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure lvStackCustomDrawItem(Sender: TCustomListView; Item: TListItem;
      State: TCustomDrawState; var DefaultDraw: Boolean);
    procedure lvStackInfoTip(Sender: TObject; Item: TListItem;
      var InfoTip: string);
    procedure btnOpenClick(Sender: TObject);
    procedure acConvertUpdate(Sender: TObject);
    procedure acConvertExecute(Sender: TObject);
    procedure acPasteUpdate(Sender: TObject);
    procedure acPasteExecute(Sender: TObject);
    procedure acCopyAddrUpdate(Sender: TObject);
    procedure acCopyAddrExecute(Sender: TObject);
    procedure acCopyLineUpdate(Sender: TObject);
    procedure acCopyLineExecute(Sender: TObject);
    procedure acCopyAllUpdate(Sender: TObject);
    procedure acCopyAllExecute(Sender: TObject);
    procedure edBaseChange(Sender: TObject);
  private
    FDebugMap: TDebugMap;
    function IsBaseEditValid: Boolean;
    procedure Reinit;
    procedure DoConvert;
    procedure UpdateColumnMaxLen;
    function GetLineText(AItem:TListItem): string;
  end;

var
  dlgStackConverter: TdlgStackConverter;

implementation

uses
  Math;

const
  AppTitle = 'Sysinternals Process Explorer Call Stack Converter';

{$R *.dfm}

procedure TdlgStackConverter.acConvertExecute(Sender: TObject);
begin
  DoConvert;
end;

procedure TdlgStackConverter.acConvertUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled :=
    (memStack.Lines.Count > 0) and
    (FDebugMap.Items.Count > 0) and
    IsBaseEditValid;
end;

procedure TdlgStackConverter.acCopyAddrExecute(Sender: TObject);
begin
  Clipboard.AsText := lvStack.Selected.Caption;
end;

procedure TdlgStackConverter.acCopyAddrUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled :=
    (lvStack.Selected <> nil) and
    (lvStack.Selected.Caption <> '');
end;

procedure TdlgStackConverter.acCopyAllExecute(Sender: TObject);
var
  Buff: string;
  AItem: TListItem;
begin
  Buff := '';
  for AItem in lvStack.Items do
    Buff := Buff + GetLineText(AItem) + sLineBreak;
  Clipboard.AsText := TrimRight(Buff);
end;

procedure TdlgStackConverter.acCopyAllUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := lvStack.Items.Count > 0;
end;

procedure TdlgStackConverter.acCopyLineExecute(Sender: TObject);
begin
  Clipboard.AsText := GetLineText(lvStack.Selected);
end;

procedure TdlgStackConverter.acCopyLineUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := lvStack.Selected <> nil;
end;

procedure TdlgStackConverter.acPasteExecute(Sender: TObject);
begin
  memStack.Text := Clipboard.AsText;
  pnPaste.Visible := False;
end;

procedure TdlgStackConverter.acPasteUpdate(Sender: TObject);
begin
  TAction(Sender).Enabled := Clipboard.HasFormat(CF_TEXT);
end;

procedure TdlgStackConverter.FormDestroy(Sender: TObject);
begin
  FreeAndNil(FDebugMap);
end;

function TdlgStackConverter.GetLineText(AItem: TListItem): string;
var
  I: Integer;
begin
  Result :=
    Format('%' + IntToStr(lvStack.Columns[0].Tag) + 's |', [AItem.Caption]);
  for I := 0 to AItem.SubItems.Count - 1 do
    Result := Result +
      Format('%' + IntToStr(lvStack.Columns[I + 1].Tag) + 's |', [AItem.SubItems[I]]);
end;

function TdlgStackConverter.IsBaseEditValid: Boolean;
var
  Tmp: UInt64;
begin
  Result := TryStrToUInt64('0x' + edBase.Text, Tmp);
end;

procedure TdlgStackConverter.lvStackCustomDrawItem(Sender: TCustomListView; Item: TListItem;
  State: TCustomDrawState; var DefaultDraw: Boolean);
begin
  case Integer(Item.Data) of
    1: Sender.Canvas.Brush.Color := $00C7C7FE;
    2: Sender.Canvas.Brush.Color := $00B4F5FF;
    3: Sender.Canvas.Brush.Color := $00C1E5C4;
  end;
end;

procedure TdlgStackConverter.lvStackInfoTip(Sender: TObject; Item: TListItem;
  var InfoTip: string);
begin
  InfoTip := memStack.Lines[Item.Index];
end;

procedure TdlgStackConverter.Reinit;
begin
  FDebugMap.Free;
  FDebugMap := TDebugMap.Create;
  FDebugMap.LoadLines := True;
end;

procedure TdlgStackConverter.UpdateColumnMaxLen;
var
  I, A: Integer;
  Item: TListItem;
begin
  for I := 0 to lvStack.Columns.Count - 1 do
    lvStack.Columns[I].Tag := 0;
  for I := 0 to lvStack.Items.Count - 1 do
  begin
    Item := lvStack.Items[I];
    with lvStack.Columns[0] do
      Tag := Max(Tag, Length(Item.Caption) + 1);
    for A := 0 to Item.SubItems.Count - 1 do
      with lvStack.Columns[A + 1] do
        Tag := Max(Tag, Length(Item.SubItems[A]) + 1);
  end;
end;

procedure TdlgStackConverter.btnOpenClick(Sender: TObject);
begin
  if not IsBaseEditValid then
    raise Exception.CreateFmt('Invalid Image Base: "%s"', [edBase.Text]);
  if OpenDialog.Execute  then
    FDebugMap.Init(StrToUInt64('0x' + edBase.Text), OpenDialog.FileName);
  lvStack.Items.BeginUpdate;
  try
    lvStack.Items.Clear;
  finally
    lvStack.Items.EndUpdate;
  end;
  Caption := Format('%s [%s]', [AppTitle, OpenDialog.FileName]);
end;

procedure TdlgStackConverter.DoConvert;

  function GetFunction(const Value: string): string;
  var
    Index: Integer;
  begin
    Index := Pos('+', Value);
    if Index > 0 then
      Result := Trim(Copy(Value, 1, Index - 1))
    else
      Result := '';
  end;

  function Module(const Value: string): string;
  var
    Index: Integer;
  begin
    Index := Pos('!', Value);
    if Index > 0 then
      Result := Copy(Value, 1, Index - 1)
    else
      Result := GetFunction(Value);
  end;

var
  ExportList,
  BaseExport: TStringList;

  function GetFunctionAddr(const FuncName: string): ULONG_PTR;
  var
    I, Index: Integer;
  begin
    Result := 0;
    if FuncName = '' then
      Exit(StrToUInt64('0x' + edBase.Text));
    Index := BaseExport.IndexOf(FuncName);
    if Index >= 0 then
      Exit(ULONG_PTR(BaseExport.Objects[Index]));
    for I := 0 to ExportList.Count - 1 do
      if ExportList[I].EndsWith(FuncName, True) then
      begin
        Result := FDebugMap.GetAddrFromDescription(ExportList[I]);
        BaseExport.AddObject(FuncName, Pointer(Result));
      end;
  end;

var
  I, LineNumber: Integer;
  FuncAddr, BaseAddr: UINT_PTR;
  FuncOffset: Cardinal;
  BinaryFileName, Line, ModuleName, FuncName, AUnitName: string;
  Item: TListItem;
  Failed: Boolean;
begin
  lvStack.Items.BeginUpdate;
  try
    lvStack.Items.Clear;
    BinaryFileName := ExtractFileName(OpenDialog.FileName);
    BaseExport := TStringList.Create;
    try
      BaseExport.Sorted := True;
      ExportList := TStringList.Create;
      try
        FDebugMap.GetExportFuncList(BinaryFileName, ExportList, True);
        for I := 0 to memStack.Lines.Count - 1 do
        begin
          Item := lvStack.Items.Add;
          Line := Trim(memStack.Lines[I]);
          ModuleName := Module(Line);
          if ModuleName = '' then
          begin
            Item.Caption := Line;
            Continue;
          end;
          if AnsiSameText(BinaryFileName, ModuleName) then
          begin
            Delete(Line, 1, Length(ModuleName) + 1);
            FuncName := GetFunction(Line);
            BaseAddr := GetFunctionAddr(FuncName);
            Delete(Line, 1, Length(FuncName) + 1);
            Failed := not TryStrToUInt(Line, FuncOffset);
            Item.SubItems.Add(ModuleName);
            if Failed then
            begin
              Item.SubItems.Add(EmptyStr);
              Item.SubItems.Add(FuncName + ' + ' + Line);
              Item.Data := Pointer(1);
              Continue;
            end;
            FuncAddr := BaseAddr + FuncOffset;
            Item.Caption := '0x' + IntToHex(FuncAddr);
            LineNumber := FDebugMap.GetLineNumberAtAddr(FuncAddr, AUnitName);
            FuncName := FDebugMap.GetDescriptionAtAddrWithOffset(FuncAddr, BinaryFileName, False);
            if LineNumber <= 0 then
            begin
              Item.SubItems.Add(EmptyStr);
              Item.SubItems.Add(FuncName);
              if FuncName = '' then
                Item.Data := Pointer(1)
              else
                Item.Data := Pointer(2);
            end
            else
            begin
              FuncName := GetFunction(FuncName);
              Item.SubItems.Add(AUnitName);
              Item.SubItems.Add(FuncName);
              Item.SubItems.Add(IntToStr(LineNumber));
              Item.Data := Pointer(3);
            end;
          end
          else
          begin
            Item.SubItems.Add(ModuleName);
            Item.SubItems.Add(EmptyStr);
            Delete(Line, 1, Length(ModuleName) + 1);
            Item.SubItems.Add(Line);
          end;
        end;
      finally
        ExportList.Free;
      end;
    finally
      BaseExport.Free;
    end;
  finally
    lvStack.Items.EndUpdate;
  end;
  UpdateColumnMaxLen;
end;

procedure TdlgStackConverter.edBaseChange(Sender: TObject);
begin
  if IsBaseEditValid then
    edBase.EditLabel.Font.Color := clWindowText
  else
    edBase.EditLabel.Font.Color := clRed;
end;

procedure TdlgStackConverter.FormCreate(Sender: TObject);
begin
  Reinit;
end;

end.
