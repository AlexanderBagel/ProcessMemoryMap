unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.ComCtrls,
  Vcl.Menus, Clipbrd;

type
  TfrmShowInitOrder = class(TForm)
    lePath: TLabeledEdit;
    btnBrowse: TButton;
    btnLoad: TButton;
    OpenDialog: TOpenDialog;
    lvReport: TListView;
    memLog: TMemo;
    pmCopy: TPopupMenu;
    mnuCopyLine: TMenuItem;
    mnuCopyUnit: TMenuItem;
    mnuCopyInit: TMenuItem;
    mnuCopyFin: TMenuItem;
    N1: TMenuItem;
    CopyUnitInitializationOrder1: TMenuItem;
    mnuCopyAll: TMenuItem;
    CopyAll2: TMenuItem;
    procedure lePathChange(Sender: TObject);
    procedure btnBrowseClick(Sender: TObject);
    procedure btnLoadClick(Sender: TObject);
    procedure lvReportCustomDrawItem(Sender: TCustomListView; Item: TListItem;
      State: TCustomDrawState; var DefaultDraw: Boolean);
    procedure pmCopyPopup(Sender: TObject);
    procedure mnuCopyLineClick(Sender: TObject);
    procedure mnuCopyUnitClick(Sender: TObject);
    procedure CopyUnitInitializationOrder1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure mnuCopyAllClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  frmShowInitOrder: TfrmShowInitOrder;

implementation

uses
  UnitInitOrderTracer;

{$R *.dfm}

procedure TfrmShowInitOrder.btnBrowseClick(Sender: TObject);
begin
  if OpenDialog.Execute(Handle) then
    lePath.Text := OpenDialog.FileName;
end;

procedure TfrmShowInitOrder.btnLoadClick(Sender: TObject);
var
  List: TUnitInitOrderList;
  ListType: TOrderListType;
  AUnit: TUnitData;
  CenterIndex: Integer;
  UnitName, AType: string;
  AItem: TListItem;
begin
  memLog.Clear;
  memLog.Lines.Add('Process: ' + lePath.Text);
  try
    List := GetUnitInitOrderList(lePath.Text, ListType);
    try
      lvReport.Items.BeginUpdate;
      try
        lvReport.Clear;
        for AUnit in List do
        begin
          UnitName := AUnit.UnitName;
          AType := 'Unit';

          case ListType of
            oltDelphi:
            begin
              if AUnit.InitializarionVA = 0 then
                AType := 'System'
            end;
            oltDelphiWithNamespaces:
            begin
              // для модулей процедура инициализации выглядит как "имя модуля"."имя модуля"
              // поэтому просто сверяем по центральной точке совпадение обоих частей и
              // если совпало - убираем лишнее
              CenterIndex := Length(UnitName) div 2;
              if Copy(UnitName, 1, CenterIndex) = Copy(UnitName, CenterIndex + 2, CenterIndex) then
                SetLength(UnitName, CenterIndex)
              else
                if (UnitName <> '') and (UnitName[Length(UnitName)] = '@') then
                  AType := 'Class'
                else
                  AType := 'System';
            end;
            oltLazarus:
            begin
              if AUnit.FpcClass then
                if Pos('.', AUnit.UnitName) > 0 then
                  AType := 'Class'
                else
                  AType := 'System';
            end;
          end;

          AItem := lvReport.Items.Add;
          AItem.Caption := IntToStr(lvReport.Items.Count);
          AItem.SubItems.Add(UnitName);
          AItem.SubItems.Add(AType);
          AItem.SubItems.Add('0x' + IntToHex(AUnit.InitializarionVA, 1));
          AItem.SubItems.Add('0x' + IntToHex(AUnit.FinalizationVA, 1));
        end;
      finally
        lvReport.Items.EndUpdate;
      end;
    finally
      List.Free;
    end;
  except
    on E: Exception do
      memLog.Lines.Add(E.ClassName + ': ' + E.Message);
  end;
  memLog.Lines.Add('Done. Count: ' + IntToStr(lvReport.Items.Count));
end;

procedure TfrmShowInitOrder.CopyUnitInitializationOrder1Click(Sender: TObject);
var
  S: string;
begin
  for var Item in lvReport.Items do
    if Item.SubItems[1] = 'Unit' then
      S := S + sLineBreak + Item.SubItems[0];
  Clipboard.AsText := Trim(S);
end;

procedure TfrmShowInitOrder.FormCreate(Sender: TObject);
begin
  if IsDebuggerPresent then
    lePath.Text := ParamStr(0);
end;

procedure TfrmShowInitOrder.lePathChange(Sender: TObject);
begin
  btnLoad.Enabled := FileExists(lePath.Text);
end;

procedure TfrmShowInitOrder.lvReportCustomDrawItem(Sender: TCustomListView;
  Item: TListItem; State: TCustomDrawState; var DefaultDraw: Boolean);
begin
  if Item.SubItems[1] = 'System' then
    lvReport.Canvas.Brush.Color := $B092EC;
  if Item.SubItems[1] = 'Class' then
    lvReport.Canvas.Brush.Color := $E4C4CF;
end;

procedure TfrmShowInitOrder.mnuCopyAllClick(Sender: TObject);
var
  S: string;
begin
  for var Item in lvReport.Items do
  begin
    S := S + sLineBreak + Format('%s'#9'%s'#9'%s'#9'%s'#9'%s',
      [
        Item.Caption,
        Item.SubItems[0],
        Item.SubItems[1],
        Item.SubItems[2],
        Item.SubItems[3]
      ]);
  end;
  Clipboard.AsText := Trim(S);
end;

procedure TfrmShowInitOrder.mnuCopyLineClick(Sender: TObject);
begin
  Clipboard.AsText := Format('%s'#9'%s'#9'%s'#9'%s'#9'%s',
    [
      lvReport.Selected.Caption,
      lvReport.Selected.SubItems[0],
      lvReport.Selected.SubItems[1],
      lvReport.Selected.SubItems[2],
      lvReport.Selected.SubItems[3]
    ]);
end;

procedure TfrmShowInitOrder.mnuCopyUnitClick(Sender: TObject);
begin
  Clipboard.AsText := lvReport.Selected.SubItems[TMenuItem(Sender).Tag];
end;

procedure TfrmShowInitOrder.pmCopyPopup(Sender: TObject);
begin
  mnuCopyLine.Enabled := lvReport.Selected <> nil;
  mnuCopyUnit.Enabled := mnuCopyLine.Enabled;
  mnuCopyInit.Enabled := mnuCopyLine.Enabled;
  mnuCopyFin.Enabled := mnuCopyLine.Enabled;
end;

end.
