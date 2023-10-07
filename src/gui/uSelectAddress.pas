////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uSelectAddress.pas
//  * Purpose   : Диалог для выбора адреса
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2016, 2023.
//  * Version   : 1.4.30
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uSelectAddress;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, uBaseForm;

type
  TCaptionType = (ctDump, ctHighLight, ctQuery);
  TdlgSelectAddress = class(TBaseAppForm)
    Label1: TLabel;
    Label2: TLabel;
    edInt: TEdit;
    lblHex: TLabel;
    edHex: TEdit;
    btnCancel: TButton;
    btnOk: TButton;
    edSize: TEdit;
    lblSizeInt: TLabel;
    lblSize: TLabel;
    procedure edIntKeyPress(Sender: TObject; var Key: Char);
    procedure edIntChange(Sender: TObject);
    procedure edHexChange(Sender: TObject);
  private
    InChange: Boolean;
  public
    function ShowDlg(CaptionType: TCaptionType; ASelectAddress: UInt64 = 0): TModalResult;
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
  TmpValue: string;
  Index: Integer;
  Valid: Boolean;
  CalculatedAddr, LeftVal, RightVal: Int64;
begin
  if InChange then Exit;
  InChange := True;
  try
    TmpValue := edHex.Text;
    if TmpValue = '' then
    begin
      edHex.Text := '0';
      btnOk.Enabled := True;
      Exit;
    end;

    CalculatedAddr := 0;
    TmpValue := StringReplace(TmpValue, ' ', '', [rfReplaceAll]);

    Valid := HexValueToInt64(TmpValue, LeftVal);
    if Valid then
      CalculatedAddr := LeftVal
    else
    begin

      // минимальный набор адресной арифметики для быстрого перехода по оффсету

      Index := Pos('+', TmpValue);
      if Index > 0 then
      begin
        Valid :=
          HexValueToInt64(Copy(TmpValue, 1, Index - 1), LeftVal) and
          HexValueToInt64(Copy(TmpValue, Index + 1, Length(TmpValue)), RightVal);
        CalculatedAddr := LeftVal + RightVal;
      end
      else
      begin
        Index := Pos('-', TmpValue);
        if Index > 0 then
        begin
          Valid :=
            HexValueToInt64(Copy(TmpValue, 1, Index - 1), LeftVal) and
            HexValueToInt64(Copy(TmpValue, Index + 1, Length(TmpValue)), RightVal);
          CalculatedAddr := LeftVal - RightVal;
        end;
      end;
    end;

    if Valid then
      lblHex.Font.Color := clWindowText
    else
      lblHex.Font.Color := clRed;

    edInt.Text := IntToStr(CalculatedAddr);

  finally
    InChange := False;
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
    begin
      edHex.Text := TrimZeros(IntToHex(StrToInt64Def(Edit.Text, 0), 16));
      lblHex.Font.Color := clWindowText;
    end;
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

function TdlgSelectAddress.ShowDlg(CaptionType: TCaptionType;
  ASelectAddress: UInt64): TModalResult;
var
  Offset: Integer;
begin
  if ASelectAddress <> 0 then
  begin
    InChange := True;
    try
      edHex.Text := TrimZeros(IntToHex(ASelectAddress, 16));
      edInt.Text := IntToStr(ASelectAddress);
    finally
      InChange := False;
    end;
  end;
  if CaptionType = ctHighLight then
    Caption := 'Process Memory Map - HighLight Address';
  if CaptionType = ctDump then
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
