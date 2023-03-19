unit ScaledCtrls;

interface

uses
  Windows,
  Graphics,
  Controls,
  ComCtrls;

type
  TScaledIcon = class(TIcon)
  protected
    procedure Draw(ACanvas: TCanvas; const Rect: TRect); override;
  end;

  TRichEdit = class(ComCtrls.TRichEdit)
  protected
    function DefaultScalingFlags: TScalingFlags; override;
  end;

implementation

{ TScaledIcon }

procedure TScaledIcon.Draw(ACanvas: TCanvas; const Rect: TRect);
begin
  if (Rect.Width = Width) and (Rect.Height = Height) then
    inherited
  else
    with Rect do
      DrawIconEx(ACanvas.Handle, Left, Top, Handle,
        Rect.Width, Rect.Height, 0, 0, DI_NORMAL);
end;

{ TRichEdit }

function TRichEdit.DefaultScalingFlags: TScalingFlags;
begin
  Result := inherited + [sfFont];
end;

end.
