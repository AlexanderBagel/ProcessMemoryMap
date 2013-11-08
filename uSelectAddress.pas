unit uSelectAddress;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls;

type
  TdlgSelectAddress = class(TForm)
    Label1: TLabel;
    Label2: TLabel;
    edInt: TEdit;
    Label3: TLabel;
    edHex: TEdit;
    btnCancel: TButton;
    btnOk: TButton;
    edSize: TEdit;
    lblSizeInt: TLabel;
    lblSize: TLabel;
    procedure edIntKeyPress(Sender: TObject; var Key: Char);
    procedure edIntChange(Sender: TObject);
    procedure edHexChange(Sender: TObject);
    procedure edHexKeyPress(Sender: TObject; var Key: Char);
  private
    InChange: Boolean;
  public
    function ShowDlg(ShowSize: Boolean): TModalResult;
  end;

var
  dlgSelectAddress: TdlgSelectAddress;

implementation

uses
  uUtils;

{$R *.dfm}

function TrimZeros(const Value: string): string;
var
  I: Integer;
begin
  Result := '';
  for I := 1 to Length(Value) do
    if Value[I] <> '0' then
    begin
      Result := Copy(Value, I, Length(Value));
      Break;
    end;
  if Result = '' then
    Result := '0';
end;

procedure TdlgSelectAddress.edHexChange(Sender: TObject);
var
  I: Int64;
begin
  if InChange then Exit;
  InChange := True;
  try
    if edHex.Text = '' then
      edHex.Text := '0';
    if not TryStrToInt64('$' + edHex.Text, I) then
    begin
      ShowErrorHint(edHex.Handle);
      edHex.Text := '0';
    end;
    edInt.Text := IntToStr(StrToInt64Def('$' + edHex.Text, 0));
  finally
    InChange := False;
  end;
end;

procedure TdlgSelectAddress.edHexKeyPress(Sender: TObject; var Key: Char);
begin
  if not CharInSet(Key, [#8, #22, '0'..'9', 'a'..'f', 'A'..'F']) then
  begin
    Key := #0;
    ShowErrorHint(edHex.Handle);
  end;
end;

procedure TdlgSelectAddress.edIntChange(Sender: TObject);
var
  I: Int64;
  Edit: TEdit;
begin
  if InChange then Exit;
  InChange := True;
  try
    Edit := Sender as TEdit;
    if Edit.Text = '' then
      Edit.Text := '0';
    if not TryStrToInt64(Edit.Text, I) then
    begin
      ShowErrorHint(Edit.Handle);
      Edit.Text := '0';
    end;
    if Edit = edInt then
      edHex.Text := TrimZeros(IntToHex(StrToInt64Def(Edit.Text, 0), 16));
  finally
    InChange := False;
  end;
end;

procedure TdlgSelectAddress.edIntKeyPress(Sender: TObject; var Key: Char);
begin
  if not CharInSet(Key, [#8, #22, '0'..'9']) then
  begin
    Key := #0;
    ShowErrorHint((Sender as TEdit).Handle);
  end;
end;

function TdlgSelectAddress.ShowDlg(ShowSize: Boolean): TModalResult;
var
  Offset: Integer;
begin
  if ShowSize then
  begin
    Caption := 'Process Memory Map - Dump Address';
    lblSize.Visible := True;
    lblSizeInt.Visible := True;
    edSize.Visible := True;
    Offset := edSize.Top - edHex.Top;
    btnOk.Top := btnOk.Top + Offset;
    btnCancel.Top := btnCancel.Top + Offset;
    Height := Height + Offset;
  end;
  Result := ShowModal;
end;

end.
