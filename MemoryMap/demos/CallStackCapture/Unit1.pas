unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls;

type
  TShowCallStack = procedure; stdcall;

  TForm1 = class(TForm)
    Button1: TButton;
    Button2: TButton;
    procedure Button1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure Button2Click(Sender: TObject);
  private
    LibShowCallStack: TShowCallStack;
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

procedure TForm1.Button2Click(Sender: TObject);
begin
  LibShowCallStack;
end;

procedure TForm1.FormCreate(Sender: TObject);
var
  hLib: THandle;
begin
  hLib := LoadLibrary('callstack_library.dll');
  @LibShowCallStack := GetProcAddress(hLib, 'ShowCallStack');
  Button2.Enabled := Assigned(LibShowCallStack);
end;

end.
