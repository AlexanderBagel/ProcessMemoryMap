////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Unit Name : FWProgressBar.pas
//  * Purpose   : A simple progress bar instead of the standard one
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.1
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
  GraphUtil,
  Math,
  Themes,
  Types;

type
  TFWHintLabel = class(TPersistent)
  private
    FOwner: TCustomControl;
    FText: string;
    FVisible: Boolean;
    FWidth: Integer;
    procedure DoChange;
    procedure SetText(const Value: string);
    procedure SetVisible(const Value: Boolean);
    procedure SetWidth(const Value: Integer);
  public
    constructor Create(AOwner: TCustomControl);
    function ClientRect: TRect;
  published
    property Text: string read FText write SetText;
    property Visible: Boolean read FVisible write SetVisible default False;
    property Width: Integer read FWidth write SetWidth default 100;
  end;

  TFWProgressBar = class(TCustomControl)
  private const
    TimerID = 5;
  private
    FAnimationBitmap: TBitmap;
    FAnimationOffset: Integer;
    FBackGroundColor: TColor;
    FCancelHint: string;
    FLabel: TFWHintLabel;
    FMin, FMax, FPosition: Int64;
    FProgressColor: TColor;
    FProgressHeight: Integer;
    FTimeHandle: THandle;
    FTimerStarted: Boolean;
    FShowCancelButton: Boolean;
    FCancelRect: TRect;
    FButtonHot: Boolean;
    FButtonPressed: Boolean;
    FOnCancelClick: TNotifyEvent;
    procedure DrawCancelButton(ARect: TRect);
    procedure DrawCancelCross(ARect: TRect);
    procedure SetBackGroundColor(const Value: TColor);
    procedure SetButtonHot(Value: Boolean);
    procedure SetButtonPressed(Value: Boolean);
    procedure SetMax(Value: Int64);
    procedure SetMin(Value: Int64);
    procedure SetParams(APosition, AMin, AMax: Int64);
    procedure SetPosition(Value: Int64);
    procedure SetProgressColor(const Value: TColor);
    procedure SetProgressHeight(const Value: Integer);
    procedure SetShowCancelButton(const Value: Boolean);
    procedure TimerStart; virtual;
    procedure TimerStop(ResetAnimation: Boolean = True); virtual;
    procedure TimerWndProc(var Message: TMessage);
    procedure UpdateAnimationBitmap;
  protected
    procedure CMHintShow(var Message: TCMHintShow); message CM_HINTSHOW;
    procedure CMMouseLeave(var Message: TMessage); message CM_MOUSELEAVE;
    procedure Paint; override;
    procedure Resize; override;
    function ToDpi(Value: Integer): Integer;
    procedure MouseDown(Button: TMouseButton; Shift: TShiftState; X, Y: Integer); override;
    procedure MouseMove(Shift: TShiftState; X, Y: Integer); override;
    procedure MouseUp(Button: TMouseButton; Shift: TShiftState; X, Y: Integer); override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  published
    property BackGroundColor: TColor read FBackGroundColor write SetBackGroundColor;
    property CancelHint: string read FCancelHint write FCancelHint;
    property ProgressColor: TColor read FProgressColor write SetProgressColor default $D47800;
    property ProgressHeight: Integer read FProgressHeight write SetProgressHeight default 6;
    property HintLabel: TFWHintLabel read FLabel;
    property Max: Int64 read FMax write SetMax default 100;
    property Min: Int64 read FMin write SetMin default 0;
    property Position: Int64 read FPosition write SetPosition default 0;
    property ShowCancelButton: Boolean read FShowCancelButton write SetShowCancelButton;
    property Visible;
    property OnCancelClick: TNotifyEvent read FOnCancelClick write FOnCancelClick;
  end;

implementation

{ TFWHintLabel }

function TFWHintLabel.ClientRect: TRect;
begin
  Result := FOwner.ClientRect;
  Result.Right := TFWProgressBar(FOwner).ToDpi(Width);
end;

constructor TFWHintLabel.Create(AOwner: TCustomControl);
begin
  FOwner := AOwner;
  FWidth := 100;
end;

procedure TFWHintLabel.DoChange;
begin
  if not FOwner.HandleAllocated then Exit;
  InvalidateRect(FOwner.Handle, ClientRect, False);
end;

procedure TFWHintLabel.SetText(const Value: string);
begin
  if Text <> Value then
  begin
    FText := Value;
    DoChange;
  end;
end;

procedure TFWHintLabel.SetVisible(const Value: Boolean);
begin
  if Visible <> Value then
  begin
    FVisible := Value;
    DoChange;
  end;
end;

procedure TFWHintLabel.SetWidth(const Value: Integer);
begin
  if Width <> Value then
  begin
    FWidth := Value;
    DoChange;
  end;
end;

{ TFWProgressBar }

procedure TFWProgressBar.CMHintShow(var Message: TCMHintShow);
var
  P: TPoint;
begin
  inherited;
  with Message do
  begin
    Result := 1;
    P := HintInfo^.CursorPos;
    if not PtInRect(FCancelRect, P) then
      Exit;
    HintInfo.HintPos.X := P.X + ToDpi(16);
    HintInfo.HintPos.Y := P.Y + ToDpi(16);
    HintInfo.HintPos := ClientToScreen(HintInfo.HintPos);
    HintInfo^.CursorRect := FCancelRect;
    HintInfo^.HintStr := FCancelHint;
    Result := 0;
  end;
end;

procedure TFWProgressBar.CMMouseLeave(var Message: TMessage);
begin
  inherited;
  SetButtonHot(False);
  SetButtonPressed(False);
end;

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
  FLabel := TFWHintLabel.Create(Self);
end;

destructor TFWProgressBar.Destroy;
begin
  TimerStop;
  DeallocateHWnd(FTimeHandle);
  FAnimationBitmap.Free;
  FLabel.Free;
  inherited;
end;

procedure TFWProgressBar.DrawCancelCross(ARect: TRect);
var
  CX, CY, D: Integer;
begin
  CX := ARect.CenterPoint.X;
  CY := ARect.CenterPoint.Y;
  D := Math.Min(ARect.Width, ARect.Height) div 4;
  if D < 2 then Exit;
  Canvas.Pen.Color := ProgressColor;
  Canvas.Pen.Width := ToDpi(2);
  Canvas.Pen.Style := psSolid;
  Canvas.MoveTo(CX - D, CY - D);
  Canvas.LineTo(CX + D, CY + D);
  Canvas.MoveTo(CX + D, CY - D);
  Canvas.LineTo(CX - D, CY + D);
end;

procedure TFWProgressBar.DrawCancelButton(ARect: TRect);
var
  Details: TThemedElementDetails;
  Flags: DWORD;
begin
  if StyleServices.Enabled then
  begin
    if FButtonHot then
      Details := StyleServices.GetElementDetails(tbPushButtonHot);
    if FButtonPressed then
      Details := StyleServices.GetElementDetails(tbPushButtonPressed);
    if FButtonPressed or FButtonHot then
      StyleServices.DrawElement(Canvas.Handle, Details, ARect);
  end
  else
  begin
    if FButtonPressed or FButtonHot then
    begin
      Flags := DFCS_BUTTONPUSH;
      if FButtonPressed then
        Flags := Flags or DFCS_PUSHED;
      DrawFrameControl(Canvas.Handle, ARect, DFC_BUTTON, Flags);
    end;
  end;
  DrawCancelCross(ARect);
end;

procedure TFWProgressBar.MouseDown(Button: TMouseButton; Shift: TShiftState;
  X, Y: Integer);
begin
  inherited;
  if (Button = mbLeft) and ShowCancelButton and PtInRect(FCancelRect, Point(X, Y)) then
    SetButtonPressed(True);
end;

procedure TFWProgressBar.MouseMove(Shift: TShiftState; X, Y: Integer);
begin
  inherited;
  if ShowCancelButton then
    SetButtonHot(PtInRect(FCancelRect, Point(X, Y)))
  else
    SetButtonHot(False);
end;

procedure TFWProgressBar.MouseUp(Button: TMouseButton; Shift: TShiftState;
  X, Y: Integer);
var
  WasPressed: Boolean;
begin
  inherited;
  if Button = mbLeft then
  begin
    WasPressed := FButtonPressed;
    SetButtonPressed(False);
    if WasPressed and ShowCancelButton and
      PtInRect(FCancelRect, Point(X, Y)) and Assigned(FOnCancelClick) then
    begin
      if FTimerStarted then
      begin
        TimerStop(False);
        try
          FOnCancelClick(Self);
        finally
          TimerStart;
        end;
      end
      else
        FOnCancelClick(Self);
    end;
  end;
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
  CR, LR, NR: TRect;
  AWidth: Integer;
begin
  inherited;
  // фон
  Canvas.Brush.Color := Color;
  Canvas.Brush.Style := bsSolid;
  CR := ClientRect;

  // режим метки
  if FLabel.Visible then
  begin
    LR := FLabel.ClientRect;
    Canvas.FillRect(LR);
    Canvas.Font := Font;
    Canvas.Brush.Style := bsClear;
    Canvas.TextOut(0, 0, FLabel.Text);
    CR.Left := LR.Right;
  end;

  // кнопка отмены
  if ShowCancelButton then
  begin
    FCancelRect := CR;
    FCancelRect.Left := FCancelRect.Right - FCancelRect.Bottom - ToDpi(6);
    CR.Right := FCancelRect.Left - ToDpi(6);
    DrawCancelButton(FCancelRect);
  end
  else
    FCancelRect := TRect.Empty;

  Canvas.FillRect(CR);

  InflateRect(CR, 0, -((CR.Height - ToDpi(ProgressHeight)) div 2));
  CR.Height := ToDpi(ProgressHeight);

  DrawRounded(CR, BackGroundColor, False);

  if Max = 0 then
  begin
    NR := CR;
    AWidth := ToDpi(100);
    NR.Right := Math.Min(CR.Right + AWidth, CR.Left + FAnimationOffset);
    NR.Left := Math.Max(NR.Left, NR.Right - AWidth);
    NR.Right := Math.Min(NR.Right, CR.Right);
    if FAnimationOffset > CR.Width + AWidth * 3 then
      FAnimationOffset := 0;
    DrawRounded(NR, ProgressColor, True);
    Exit;
  end;

  if Position > 0 then
  begin
    CR.Right := CR.Left + Trunc(CR.Width * (Position / (Max - Min))) + 1;
    if CR.Right > 0 then
      DrawRounded(CR, ProgressColor, True);
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

procedure TFWProgressBar.SetButtonHot(Value: Boolean);
begin
  if FButtonHot <> Value then
  begin
    FButtonHot := Value;
    if HandleAllocated then
      InvalidateRect(Handle, FCancelRect, False);
  end;
end;

procedure TFWProgressBar.SetButtonPressed(Value: Boolean);
begin
  if FButtonPressed <> Value then
  begin
    FButtonPressed := Value;
    if HandleAllocated then
      InvalidateRect(Handle, FCancelRect, False);
  end;
end;

procedure TFWProgressBar.SetMax(Value: Int64);
begin
  if Value >= Min then
    SetParams(Position, Min, Value);
end;

procedure TFWProgressBar.SetMin(Value: Int64);
begin
  if Value <= Max then
    SetParams(Position, Value, Max);
end;

procedure TFWProgressBar.SetParams(APosition, AMin, AMax: Int64);
var
  Changed: Boolean;
begin
  Changed := False;
  if (AMax <> 0) and (AMax < AMin) then
    raise EInvalidOperation.CreateFmt(SPropertyOutOfRange, [Self.Classname]);
  if APosition < AMin then APosition := AMin;
  if (AMax <> 0) and (APosition > AMax) then APosition := AMax;
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

procedure TFWProgressBar.SetPosition(Value: Int64);
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

procedure TFWProgressBar.SetShowCancelButton(const Value: Boolean);
begin
  if ShowCancelButton <> Value then
  begin
    FShowCancelButton := Value;
    if not Value then
    begin
      FButtonHot := False;
      FButtonPressed := False;
      FCancelRect := TRect.Empty;
    end;
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

procedure TFWProgressBar.TimerStop(ResetAnimation: Boolean);
begin
  if csDesigning in ComponentState then Exit;
  if FTimerStarted then
  begin
    KillTimer(FTimeHandle, TimerID);
    if ResetAnimation then
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

function TFWProgressBar.ToDpi(Value: Integer): Integer;
begin
  Result := MulDiv(Value, FCurrentPPI, USER_DEFAULT_SCREEN_DPI);
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
