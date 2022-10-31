////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Unit Name : FWProgressBar.pas
//  * Purpose   : Простенький прогрессбар взамен штатного
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2022.
//  * Version   : 1.0
//  ****************************************************************************
//

unit FWProgressBar;

interface

uses
  Windows,
  Messages,
  Controls,
  Graphics,
  Classes,
  Consts,
  GraphUtil;

type
  TFWProgressBar = class(TCustomControl)
  private const
    TimerID = 5;
  private
    FAnimationBitmap: TBitmap;
    FAnimationOffset, FMin, FMax, FPosition: Integer;
    FTimeHandle: THandle;
    FProgressColor: TColor;
    FBackGroundColor: TColor;
    FTimerStarted: Boolean;
    FProgressHeight: Integer;
    procedure SetMax(const Value: Integer);
    procedure SetMin(const Value: Integer);
    procedure SetPosition(const Value: Integer);
    procedure TimerStart; virtual;
    procedure TimerStop; virtual;
    procedure TimerWndProc(var Message: TMessage);
    procedure UpdateAnimationBitmap;
    procedure SetBackGroundColor(const Value: TColor);
    procedure SetParams(APosition, AMin, AMax: Integer);
    procedure SetProgressColor(const Value: TColor);
    procedure SetProgressHeight(const Value: Integer);
  protected
    procedure Paint; override;
    procedure Resize; override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  published
    property BackGroundColor: TColor read FBackGroundColor write SetBackGroundColor;
    property ProgressColor: TColor read FProgressColor write SetProgressColor default $D47800;
    property ProgressHeight: Integer read FProgressHeight write SetProgressHeight default 6;
    property Max: Integer read FMax write SetMax default 100;
    property Min: Integer read FMin write SetMin default 0;
    property Position: Integer read FPosition write SetPosition default 0;
    property Visible;
  end;

implementation

{ TFWProgressBar }

constructor TFWProgressBar.Create(AOwner: TComponent);
begin
  inherited;
  DoubleBuffered := True;
  Width := 100;
  Height := 21;
  FMax := 100;
  FProgressHeight := 6;
  FBackGroundColor := $B6B6B6;
  FProgressColor := $D47800;
  FAnimationBitmap := TBitmap.Create;
  FAnimationBitmap.PixelFormat := pf24bit;
  FTimeHandle := AllocateHWnd(TimerWndProc);
end;

destructor TFWProgressBar.Destroy;
begin
  TimerStop;
  DeallocateHWnd(FTimeHandle);
  FAnimationBitmap.Free;
  inherited;
end;

procedure TFWProgressBar.Paint;

  procedure DrawRounded(ARect: TRect; AColor: TColor;
    DrawAnimation: Boolean);
  var
    hReg: HRGN;
    P: TPoint;
    PaintWidth, CWidth: Integer;
  begin
    hReg := CreateRoundRectRgn(ARect.Left, ARect.Top, ARect.Right,
      ARect.Bottom, Round(ARect.Height / 3), ARect.Height);
    GetWindowOrgEx(Canvas.Handle, P);
    OffsetRgn(hReg, -P.X, -P.Y);
    SelectClipRgn(Canvas.Handle, hReg);
    Canvas.Brush.Color := AColor;
    Canvas.FillRect(ARect);

    if DrawAnimation then
    begin
      PaintWidth := FAnimationOffset;
      if PaintWidth > ARect.Width then
        PaintWidth := ARect.Width;
      CWidth := ClientWidth;
      if FAnimationOffset < CWidth then
        BitBlt(Canvas.Handle, ARect.Left, ARect.Top, PaintWidth, ARect.Height,
          FAnimationBitmap.Canvas.Handle, CWidth - FAnimationOffset, 0, SRCCOPY)
      else
      begin
        ARect.Left := ARect.Left + FAnimationOffset - CWidth;
        BitBlt(Canvas.Handle, ARect.Left, ARect.Top, ARect.Width, ARect.Height,
          FAnimationBitmap.Canvas.Handle, 0, 0, SRCCOPY);
      end;
    end;

    SelectClipRgn(Canvas.Handle, 0);
    DeleteObject(hReg);
  end;

var
  R: TRect;
begin
  inherited;
  // фон
  Canvas.Brush.Color := Color;
  R := ClientRect;
  Canvas.FillRect(R);

  InflateRect(R, 0, -((R.Height - ProgressHeight) div 2));
  R.Height := ProgressHeight;

  // бэкграунд
  DrawRounded(R, BackGroundColor, False);

  // сам прогресс с анимацией
  if Position > 0 then
  begin
    R.Right := R.Left + Trunc(R.Width * (Position / (Max - Min))) + 1;
    if R.Right > 0 then
      DrawRounded(R, ProgressColor, True);
  end;
end;

procedure TFWProgressBar.Resize;
begin
  inherited;
  UpdateAnimationBitmap;
end;

procedure TFWProgressBar.SetBackGroundColor(const Value: TColor);
begin
  if BackGroundColor <> Value then
  begin
    FBackGroundColor := Value;
    Invalidate;
  end;
end;

procedure TFWProgressBar.SetMax(const Value: Integer);
begin
  if Value >= Min then
    SetParams(Position, Min, Value);
end;

procedure TFWProgressBar.SetMin(const Value: Integer);
begin
  if Value <= Max then
    SetParams(Position, Value, Max);
end;

procedure TFWProgressBar.SetParams(APosition, AMin, AMax: Integer);
var
  Changed: Boolean;
begin
  Changed := False;
  if AMax < AMin then
    raise EInvalidOperation.CreateFmt(SPropertyOutOfRange, [Self.Classname]);
  if APosition < AMin then APosition := AMin;
  if APosition > AMax then APosition := AMax;
  if (FMin <> AMin) then
  begin
    FMin := AMin;
    Changed := True;
  end;
  if (FMax <> AMax) then
  begin
    FMax := AMax;
    Changed := True;
  end;
  if FPosition <> APosition then
  begin
    FPosition := APosition;
    if Position = 0 then
      TimerStop
    else
      TimerStart;
    Changed := True;
  end;
  if Changed then
    Invalidate;
end;

procedure TFWProgressBar.SetPosition(const Value: Integer);
begin
  SetParams(Value, Min, Max);
end;

procedure TFWProgressBar.SetProgressColor(const Value: TColor);
begin
  if ProgressColor <> Value then
  begin
    FProgressColor := Value;
    Invalidate;
  end;
end;

procedure TFWProgressBar.SetProgressHeight(const Value: Integer);
begin
  if (Value >= 3) and (ProgressHeight <> Value) then
  begin
    FProgressHeight := Value;
    Invalidate;
  end;
end;

procedure TFWProgressBar.TimerStart;
begin
  if csDesigning in ComponentState then Exit;
  if not FTimerStarted then
  begin
    SetTimer(FTimeHandle, TimerID, 10, nil);
    FTimerStarted := True;
  end;
end;

procedure TFWProgressBar.TimerStop;
begin
  if csDesigning in ComponentState then Exit;
  if FTimerStarted then
  begin
    KillTimer(FTimeHandle, TimerID);
    FAnimationOffset := 0;
    FTimerStarted := False;
  end;
end;

procedure TFWProgressBar.TimerWndProc(var Message: TMessage);
begin
  if csDesigning in ComponentState then Exit;
  case Message.Msg of
    WM_TIMER:
    begin
      if TWMTimer(Message).TimerID = TimerID then
      begin
        if FAnimationOffset = 0 then
          SetTimer(FTimeHandle, TimerID, 10, nil);
        Inc(FAnimationOffset, 5);
        if FAnimationOffset >= ClientWidth * 2 then
        begin
          FAnimationOffset := 0;
          SetTimer(FTimeHandle, TimerID, 750, nil);
        end;
        Invalidate;
      end;
    end;
  end;
end;

procedure TFWProgressBar.UpdateAnimationBitmap;
var
  R, GradientRect: TRect;
  MiddleColor: TColor;
begin
  R := ClientRect;
  FAnimationBitmap.SetSize(R.Width, R.Height);
  MiddleColor := RGB(
    GetRValue(ProgressColor) + (255 - GetRValue(ProgressColor)) div 3 * 2,
    GetGValue(ProgressColor) + (255 - GetGValue(ProgressColor)) div 3 * 2,
    GetBValue(ProgressColor) + (255 - GetBValue(ProgressColor)) div 3 * 2);
  GradientRect := R;
  GradientRect.Width := GradientRect.Width div 2;
  GradientFillCanvas(FAnimationBitmap.Canvas,
    ProgressColor, MiddleColor, GradientRect, gdHorizontal);
  GradientRect.Left := GradientRect.Right;
  GradientRect.Right := R.Right;
  GradientFillCanvas(FAnimationBitmap.Canvas,
    MiddleColor, ProgressColor, GradientRect, gdHorizontal);
end;

end.
