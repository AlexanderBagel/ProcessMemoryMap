unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls;

type
  TForm1 = class(TForm)
    Button1: TButton;
    procedure Button1Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

uses
  CallStackTraceUtils;

{$R *.dfm}

procedure TForm1.Button1Click(Sender: TObject);
var
  S: TStringList;
begin
  S := GetCallStack;
  try
    ShowMessage(S.Text);
  finally
    S.Free;
  end;
end;

end.
