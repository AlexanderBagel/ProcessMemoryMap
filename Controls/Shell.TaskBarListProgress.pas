////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Unit Name : Shell.TaskBarListProgress
//  * Purpose   : Реализация отображения прогрессбара на
//  *           : кнопке приложения в таскбаре
//  * Author    : Александр (Rouse_) Багель
//  * Version   : 1.0
//  ****************************************************************************
//

unit Shell.TaskBarListProgress;

interface

uses
  Windows,
  Messages,
  Classes,
  Graphics,
  SysUtils,
  Dwmapi,
  ActiveX,
  ShlObj,
  ComObj,
  Forms;

type
  TProgressState = (psNoProgress, psDefault, psPaused, psError, psIndeterminate);

  TTaskBarListProgress = class
  strict private const
    States: array [TProgressState] of Cardinal =
      (TBPF_NOPROGRESS, TBPF_NORMAL, TBPF_PAUSED, TBPF_ERROR, TBPF_INDETERMINATE);
  strict private
    FMax: Integer;
    FMin: Integer;
    FNewTabButton: THandle;
    FPosition: Integer;
    FProgressState: TProgressState;
    FTaskbarList3: ITaskbarList3;
    FOwnerWnd: THandle;
    FIcon: TIcon;
  private
    procedure SetValue(const Index, Value: Integer);
    procedure SetPS(const Value: TProgressState);
    procedure WndProc(var Message: TMessage);
  protected
    function GetTaskbarFormHandle: THandle;
    function GetPreviewBitmap: TBitmap;
    procedure PaintThumbnail(Width, Height: Integer);
    procedure PaintLivePreviewBitmap;
  public
    constructor Create(WndHandle: THandle = INVALID_HANDLE_VALUE);
    destructor Destroy; override;
    procedure ShowOwnerWindow;
    procedure ShowExternalButton(AOwnerWnd: HWND; const Caption, Hint: string);
    procedure ReleaseExternalButton;
    procedure InvalidateThumbnail;
    property Icon: TIcon read FIcon;
    property Max: Integer index 0 read FMax write SetValue;
    property Min: Integer index 1 read FMin write SetValue;
    property Position: Integer index 2 read FPosition write SetValue;
    property ProgressState: TProgressState read FProgressState write SetPS;
    property TabButtonHandle: THandle read FNewTabButton;
  end;

implementation

var
  UtilWindowClassEx: TWndClass = (
    style: 0;
    lpfnWndProc: @DefWindowProc;
    cbClsExtra: 0;
    cbWndExtra: 0;
    hInstance: 0;
    hIcon: 0;
    hCursor: 0;
    hbrBackground: 0;
    lpszMenuName: nil;
    lpszClassName: 'TPUtilWindowEx');

function AllocateHWndEx(AMethod: TWndMethod): HWND;
var
  TempClass: TWndClass;
  ClassRegistered: Boolean;
begin
  UtilWindowClassEx.hInstance := HInstance;
{$IFDEF PIC}
  UtilWindowClassEx.lpfnWndProc := @DefWindowProc;
{$ENDIF}
  ClassRegistered := GetClassInfo(HInstance, UtilWindowClassEx.lpszClassName,
    TempClass);
  if not ClassRegistered or (TempClass.lpfnWndProc <> @DefWindowProc) then
  begin
    if ClassRegistered then
      Windows.UnregisterClass(UtilWindowClassEx.lpszClassName, HInstance);
    Windows.RegisterClass(UtilWindowClassEx);
  end;
  Result := CreateWindowEx(WS_EX_APPWINDOW, UtilWindowClassEx.lpszClassName,
    '', WS_CAPTION or WS_SYSMENU or WS_VISIBLE, -300, -300, 50, 50, 0, 0, HInstance, nil);
  if Assigned(AMethod) then
    SetWindowLong(Result, GWL_WNDPROC, NativeUInt(MakeObjectInstance(AMethod)));
end;

{ TTaskBarListProgress }

constructor TTaskBarListProgress.Create(WndHandle: THandle);
var
  TaskbarList: ITaskbarList;
begin
  FMin := 0;
  FMax := 100;
  FPosition := 0;
  FOwnerWnd := INVALID_HANDLE_VALUE;
  FNewTabButton := WndHandle;
  CoInitialize(nil);
  TaskbarList := ITaskbarList(CreateComObject(CLSID_TaskbarList));
  if TaskbarList <> nil then
  begin
    TaskbarList.HrInit;
    TaskbarList.QueryInterface(IID_ITaskbarList3, FTaskbarList3);
  end;
  FIcon := TIcon.Create;
end;

destructor TTaskBarListProgress.Destroy;
begin
  FIcon.Free;
  ReleaseExternalButton;
  inherited;
end;

function TTaskBarListProgress.GetPreviewBitmap: TBitmap;
var
  R: TRect;
  WindowHandle: THandle;
  DC: HDC;
  NeedReleaseDC: Boolean;
begin
  DC := 0;
  NeedReleaseDC := False;
  if FOwnerWnd = INVALID_HANDLE_VALUE then
    WindowHandle := GetTaskbarFormHandle
  else
  begin
    WindowHandle := FOwnerWnd;
    DC := SendMessage(WindowHandle, WM_USER + 500, 0, 0);
  end;
  if DC = 0 then
  begin
    DC := GetWindowDC(WindowHandle);
    NeedReleaseDC := True;
  end;
  try
    Result := TBitmap.Create;
    GetWindowRect(WindowHandle, R);
    OffsetRect(R, -R.Left, -R.Top);
    Result.PixelFormat := pf32bit;
    Result.SetSize(R.Right, R.Bottom);
    BitBlt(Result.Canvas.Handle, 0, 0, R.Right, R.Bottom, DC, 0, 0, SRCCOPY);
  finally
    if NeedReleaseDC then
      ReleaseDC(WindowHandle, DC);
  end;
end;

function TTaskBarListProgress.GetTaskbarFormHandle: THandle;
begin
  if FNewTabButton <> INVALID_HANDLE_VALUE then
  begin
    Result := FNewTabButton;
    Exit;
  end;
  if Application.MainFormOnTaskBar and (Application.MainForm <> nil) then
    Result := Application.MainForm.Handle
  else
    Result := Application.Handle;
end;

procedure TTaskBarListProgress.InvalidateThumbnail;
begin
  if CheckWin32Version(6,1) then
    DwmInvalidateIconicBitmaps(GetTaskbarFormHandle);
end;

procedure TTaskBarListProgress.PaintLivePreviewBitmap;
var
  Bitmap: TBitmap;
  P: TPoint;
begin
  Bitmap := GetPreviewBitmap;
  try
    P.X := 10;
    P.Y := 10;
    DwmSetIconicLivePreviewBitmap(GetTaskbarFormHandle, Bitmap.Handle, P, 0);
  finally
    Bitmap.Free;
  end;
end;

procedure TTaskBarListProgress.PaintThumbnail(Width, Height: Integer);
var
  Bitmap, Thumbnail: TBitmap;
  WindowMultiplier, ThumbsMultiplier: Currency;
begin
  Bitmap := GetPreviewBitmap;
  try
    ThumbsMultiplier := Width / Height;
    WindowMultiplier := Bitmap.Width / Bitmap.Height;
    if WindowMultiplier > ThumbsMultiplier then
      Height := Trunc(Height * ThumbsMultiplier / WindowMultiplier)
    else
      Width := Trunc(Width * WindowMultiplier / ThumbsMultiplier);
    Thumbnail := TBitmap.Create;
    try
      Thumbnail.PixelFormat := pf32bit;
      Thumbnail.SetSize(Width, Height);
      // Цвета уплывают при сжатии картинки, восстанавливаем при помощи HALFTONE
      SetStretchBltMode(Thumbnail.Canvas.Handle, HALFTONE);
      StretchBlt(Thumbnail.Canvas.Handle, 0, 0, Width, Height,
        Bitmap.Canvas.Handle, 0, 0, Bitmap.Width, Bitmap.Height, SRCCOPY);
      DwmSetIconicThumbnail(GetTaskbarFormHandle, Thumbnail.Handle, 0);
    finally
      Thumbnail.Free;
    end;
  finally
    Bitmap.Free;
  end;
end;

procedure TTaskBarListProgress.ReleaseExternalButton;
begin
  if FOwnerWnd <> INVALID_HANDLE_VALUE then
  begin
    FOwnerWnd := INVALID_HANDLE_VALUE;
    DeallocateHWnd(FNewTabButton);
  end;
end;

procedure TTaskBarListProgress.SetPS(const Value: TProgressState);
begin
  FProgressState := Value;
  if FTaskbarList3 <> nil then
    FTaskbarList3.SetProgressState(GetTaskbarFormHandle, States[Value]);
end;

procedure TTaskBarListProgress.SetValue(const Index, Value: Integer);
var
  CurrentState: Cardinal;
begin
  case Index of
    0: FMax := Value;
    1: FMin := Value;
    2: FPosition := Value;
  end;
  if FTaskbarList3 <> nil then
  begin
    FTaskbarList3.SetProgressValue(GetTaskbarFormHandle, FPosition - FMin, FMax - FMin);
    CurrentState := TBPF_NOPROGRESS;
    if FMax <> FPosition then
      CurrentState := States[ProgressState];
    FTaskbarList3.SetProgressState(GetTaskbarFormHandle, CurrentState);
  end;
end;

procedure TTaskBarListProgress.ShowExternalButton(
  AOwnerWnd: HWND; const Caption, Hint: string);
var
  Attribute: BOOL;
begin
  if FOwnerWnd <> INVALID_HANDLE_VALUE then Exit;
  FOwnerWnd := AOwnerWnd;
  FNewTabButton := AllocateHWndEx(WndProc);
  SetClassLong(FNewTabButton, GCL_HICON, NativeInt(Icon.Handle));
  if Hint <> '' then
    if FTaskbarList3 <> nil then
      FTaskbarList3.SetThumbnailTooltip(FNewTabButton, PWideChar(Hint));
  if Caption <> '' then
    DefWindowProc(FNewTabButton, WM_SETTEXT, 0 , LPARAM(PChar(Caption)));
  if CheckWin32Version(6,1) then
  begin
    Attribute := True;
    DwmSetWindowAttribute(FNewTabButton, DWMWA_HAS_ICONIC_BITMAP, @Attribute, SizeOf(Attribute));
    DwmSetWindowAttribute(FNewTabButton, DWMWA_FORCE_ICONIC_REPRESENTATION, @Attribute, SizeOf(Attribute));
  end;
end;

procedure TTaskBarListProgress.ShowOwnerWindow;
begin
  if FOwnerWnd <> INVALID_HANDLE_VALUE then
    if GetForegroundWindow <> FOwnerWnd then
      SetForegroundWindow(FOwnerWnd);
end;

procedure TTaskBarListProgress.WndProc(var Message: TMessage);
begin
  with Message do
  begin
    case Msg of
      WM_GETICON:
        InvalidateThumbnail;
      WM_ACTIVATEAPP:
        if TWMActivate(Message).Active = WA_ACTIVE then
          ShowOwnerWindow;
      WM_DWMSENDICONICTHUMBNAIL:
        PaintThumbnail(HiWord(LParam), LoWord(LParam));
      WM_DWMSENDICONICLIVEPREVIEWBITMAP:
        PaintLivePreviewBitmap;
    end;
    Result := DefWindowProc(FNewTabButton, Msg, WParam, LParam);
  end;
end;

end.
