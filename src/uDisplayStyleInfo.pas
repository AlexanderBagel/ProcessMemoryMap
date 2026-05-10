////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uDisplayStyleInfo.pas
//  * Purpose   : Вспомогательные функции и массивы для определения стилей окна
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.2.26
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

// Основано на базе кода:
//  https://github.com/strobejb/winspy/blob/master/src/DisplayStyleInfo.c
//  Copyright (c) 2002 by J Brown
//	Freeware

unit uDisplayStyleInfo;

{$message 'проверить все стили по MSDN'}

interface

uses
  Windows, Messages, SysUtils, Classes, CommCtrl, RichEdit;

type
  PStyleLookupEx = ^TStyleLookupEx;
  TStyleLookupEx = record
    style: DWORD;        // Single window style
    name: PChar;         // Textual name of style
    cmp_mask: DWORD;     // If zero, then -style- is treated as a single bit-field
                         // Otherwise, cmp_mask is used to make sure that
                         // ALL the bits in the mask match -style-
    depends: DWORD;      // Style is only valid if includes these styles
    excludes: DWORD;     // Style is only valid if these aren't set
  end;

  PClassStyleLookup = ^TClassStyleLookup;
  TClassStyleLookup = record
    szClassName: PChar;
    stylelist: PStyleLookupEx;
  end;

const
  NO_DATA = DWORD(-1);
  DTS_SHORTDATECENTURYFORMAT = $C;
  DIALOG_TYPE = '#32770';

  WindowStyles: array[0..22] of TStyleLookupEx = (
    (style: WS_OVERLAPPEDWINDOW; name: 'WS_OVERLAPPEDWINDOW'; cmp_mask: 0; depends: NO_DATA; excludes: WS_POPUP or WS_CHILD),
    (style: WS_POPUPWINDOW; name: 'WS_POPUPWINDOW'; cmp_mask: WS_POPUPWINDOW; depends: NO_DATA; excludes: 0),
    (style: WS_OVERLAPPED; name: 'WS_OVERLAPPED'; cmp_mask: 0; depends: NO_DATA; excludes: WS_POPUP or WS_CHILD),
    (style: WS_POPUP; name: 'WS_POPUP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_CHILD; name: 'WS_CHILD'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_MINIMIZE; name: 'WS_MINIMIZE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_VISIBLE; name: 'WS_VISIBLE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_DISABLED; name: 'WS_DISABLED'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_CLIPSIBLINGS; name: 'WS_CLIPSIBLINGS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_CLIPCHILDREN; name: 'WS_CLIPCHILDREN'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_MAXIMIZE; name: 'WS_MAXIMIZE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_CAPTION; name: 'WS_CAPTION'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_DLGFRAME; name: 'WS_DLGFRAME'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_BORDER; name: 'WS_BORDER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_VSCROLL; name: 'WS_VSCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_HSCROLL; name: 'WS_HSCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_SYSMENU; name: 'WS_SYSMENU'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_THICKFRAME; name: 'WS_THICKFRAME'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_GROUP; name: 'WS_GROUP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_TABSTOP; name: 'WS_TABSTOP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_MINIMIZEBOX; name: 'WS_MINIMIZEBOX'; cmp_mask: 0; depends: WS_POPUPWINDOW or WS_OVERLAPPEDWINDOW or WS_CAPTION; excludes: 0),
    (style: WS_MAXIMIZEBOX; name: 'WS_MAXIMIZEBOX'; cmp_mask: 0; depends: WS_POPUPWINDOW or WS_OVERLAPPEDWINDOW or WS_CAPTION; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  DialogStyles: array[0..14] of TStyleLookupEx = (
    (style: DS_ABSALIGN; name: 'DS_ABSALIGN'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DS_SYSMODAL; name: 'DS_SYSMODAL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DS_LOCALEDIT; name: 'DS_LOCALEDIT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DS_SETFONT; name: 'DS_SETFONT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DS_MODALFRAME; name: 'DS_MODALFRAME'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DS_NOIDLEMSG; name: 'DS_NOIDLEMSG'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DS_SETFOREGROUND; name: 'DS_SETFOREGROUND'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DS_3DLOOK; name: 'DS_3DLOOK'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DS_FIXEDSYS; name: 'DS_FIXEDSYS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DS_NOFAILCREATE; name: 'DS_NOFAILCREATE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DS_CONTROL; name: 'DS_CONTROL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DS_CENTER; name: 'DS_CENTER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DS_CENTERMOUSE; name: 'DS_CENTERMOUSE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DS_CONTEXTHELP; name: 'DS_CONTEXTHELP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  ButtonStyles: array[0..26] of TStyleLookupEx = (
    (style: BS_PUSHBUTTON; name: 'BS_PUSHBUTTON'; cmp_mask: 0; depends: NO_DATA; excludes: BS_DEFPUSHBUTTON or BS_CHECKBOX or BS_AUTOCHECKBOX or BS_RADIOBUTTON or BS_GROUPBOX or BS_AUTORADIOBUTTON),
    (style: BS_DEFPUSHBUTTON; name: 'BS_DEFPUSHBUTTON'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: BS_CHECKBOX; name: 'BS_CHECKBOX'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: BS_AUTOCHECKBOX; name: 'BS_AUTOCHECKBOX'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: BS_RADIOBUTTON; name: 'BS_RADIOBUTTON'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: BS_3STATE; name: 'BS_3STATE'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: BS_AUTO3STATE; name: 'BS_AUTO3STATE'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: BS_GROUPBOX; name: 'BS_GROUPBOX'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: BS_USERBUTTON; name: 'BS_USERBUTTON'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: BS_AUTORADIOBUTTON; name: 'BS_AUTORADIOBUTTON'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: BS_OWNERDRAW; name: 'BS_OWNERDRAW'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: BS_LEFTTEXT; name: 'BS_LEFTTEXT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: BS_TEXT; name: 'BS_TEXT'; cmp_mask: 0; depends: NO_DATA; excludes: BS_ICON or BS_BITMAP or BS_AUTOCHECKBOX or BS_AUTORADIOBUTTON or BS_CHECKBOX or BS_RADIOBUTTON),
    (style: BS_ICON; name: 'BS_ICON'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: BS_BITMAP; name: 'BS_BITMAP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: BS_LEFT; name: 'BS_LEFT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: BS_RIGHT; name: 'BS_RIGHT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: BS_CENTER; name: 'BS_CENTER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: BS_TOP; name: 'BS_TOP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: BS_BOTTOM; name: 'BS_BOTTOM'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: BS_VCENTER; name: 'BS_VCENTER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: BS_PUSHLIKE; name: 'BS_PUSHLIKE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: BS_MULTILINE; name: 'BS_MULTILINE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: BS_NOTIFY; name: 'BS_NOTIFY'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: BS_FLAT; name: 'BS_FLAT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: BS_RIGHTBUTTON; name: 'BS_RIGHTBUTTON'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  EditStyles: array[0..14] of TStyleLookupEx = (
    (style: ES_LEFT; name: 'ES_LEFT'; cmp_mask: 0; depends: NO_DATA; excludes: ES_CENTER or ES_RIGHT),
    (style: ES_CENTER; name: 'ES_CENTER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_RIGHT; name: 'ES_RIGHT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_MULTILINE; name: 'ES_MULTILINE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_UPPERCASE; name: 'ES_UPPERCASE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_LOWERCASE; name: 'ES_LOWERCASE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_PASSWORD; name: 'ES_PASSWORD'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_AUTOVSCROLL; name: 'ES_AUTOVSCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_AUTOHSCROLL; name: 'ES_AUTOHSCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_NOHIDESEL; name: 'ES_NOHIDESEL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_OEMCONVERT; name: 'ES_OEMCONVERT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_READONLY; name: 'ES_READONLY'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_WANTRETURN; name: 'ES_WANTRETURN'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_NUMBER; name: 'ES_NUMBER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  RichedStyles: array[0..16] of TStyleLookupEx = (
    (style: ES_LEFT; name: 'ES_LEFT'; cmp_mask: 0; depends: NO_DATA; excludes: ES_CENTER or ES_RIGHT),
    (style: ES_CENTER; name: 'ES_CENTER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_RIGHT; name: 'ES_RIGHT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_MULTILINE; name: 'ES_MULTILINE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_PASSWORD; name: 'ES_PASSWORD'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_AUTOVSCROLL; name: 'ES_AUTOVSCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_AUTOHSCROLL; name: 'ES_AUTOHSCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_NOHIDESEL; name: 'ES_NOHIDESEL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_READONLY; name: 'ES_READONLY'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_WANTRETURN; name: 'ES_WANTRETURN'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_NUMBER; name: 'ES_NUMBER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_SAVESEL; name: 'ES_SAVESEL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_SUNKEN; name: 'ES_SUNKEN'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_DISABLENOSCROLL; name: 'ES_DISABLENOSCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_SELECTIONBAR; name: 'ES_SELECTIONBAR'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ES_NOOLEDRAGDROP; name: 'ES_NOOLEDRAGDROP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  ComboStyles: array[0..13] of TStyleLookupEx = (
    (style: CBS_SIMPLE; name: 'CBS_SIMPLE'; cmp_mask: $3; depends: NO_DATA; excludes: 0),
    (style: CBS_DROPDOWN; name: 'CBS_DROPDOWN'; cmp_mask: $3; depends: NO_DATA; excludes: 0),
    (style: CBS_DROPDOWNLIST; name: 'CBS_DROPDOWNLIST'; cmp_mask: $3; depends: NO_DATA; excludes: 0),
    (style: CBS_OWNERDRAWFIXED; name: 'CBS_OWNERDRAWFIXED'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CBS_OWNERDRAWVARIABLE; name: 'CBS_OWNERDRAWVARIABLE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CBS_AUTOHSCROLL; name: 'CBS_AUTOHSCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CBS_OEMCONVERT; name: 'CBS_OEMCONVERT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CBS_SORT; name: 'CBS_SORT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CBS_HASSTRINGS; name: 'CBS_HASSTRINGS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CBS_NOINTEGRALHEIGHT; name: 'CBS_NOINTEGRALHEIGHT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CBS_DISABLENOSCROLL; name: 'CBS_DISABLENOSCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CBS_UPPERCASE; name: 'CBS_UPPERCASE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CBS_LOWERCASE; name: 'CBS_LOWERCASE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  ListBoxStyles: array[0..15] of TStyleLookupEx = (
    (style: LBS_NOTIFY; name: 'LBS_NOTIFY'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LBS_SORT; name: 'LBS_SORT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LBS_NOREDRAW; name: 'LBS_NOREDRAW'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LBS_MULTIPLESEL; name: 'LBS_MULTIPLESEL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LBS_OWNERDRAWFIXED; name: 'LBS_OWNERDRAWFIXED'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LBS_OWNERDRAWVARIABLE; name: 'LBS_OWNERDRAWVARIABLE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LBS_HASSTRINGS; name: 'LBS_HASSTRINGS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LBS_USETABSTOPS; name: 'LBS_USETABSTOPS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LBS_NOINTEGRALHEIGHT; name: 'LBS_NOINTEGRALHEIGHT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LBS_MULTICOLUMN; name: 'LBS_MULTICOLUMN'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LBS_WANTKEYBOARDINPUT; name: 'LBS_WANTKEYBOARDINPUT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LBS_EXTENDEDSEL; name: 'LBS_EXTENDEDSEL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LBS_DISABLENOSCROLL; name: 'LBS_DISABLENOSCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LBS_NODATA; name: 'LBS_NODATA'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LBS_NOSEL; name: 'LBS_NOSEL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  ScrollbarStyles: array[0..10] of TStyleLookupEx = (
    (style: SBS_TOPALIGN; name: 'SBS_TOPALIGN'; cmp_mask: 0; depends: SBS_HORZ; excludes: 0),
    (style: SBS_LEFTALIGN; name: 'SBS_LEFTALIGN'; cmp_mask: 0; depends: SBS_VERT; excludes: 0),
    (style: SBS_BOTTOMALIGN; name: 'SBS_BOTTOMALIGN'; cmp_mask: 0; depends: SBS_HORZ or SBS_SIZEBOX or SBS_SIZEGRIP; excludes: 0),
    (style: SBS_RIGHTALIGN; name: 'SBS_RIGHTALIGN'; cmp_mask: 0; depends: SBS_VERT or SBS_SIZEBOX or SBS_SIZEGRIP; excludes: 0),
    (style: SBS_HORZ; name: 'SBS_HORZ'; cmp_mask: 0; depends: NO_DATA; excludes: SBS_VERT or SBS_SIZEBOX or SBS_SIZEGRIP),
    (style: SBS_VERT; name: 'SBS_VERT'; cmp_mask: 0; depends: NO_DATA; excludes: SBS_SIZEBOX or SBS_SIZEGRIP),
    (style: SBS_SIZEBOXTOPLEFTALIGN; name: 'SBS_SIZEBOXTOPLEFTALIGN'; cmp_mask: 0; depends: SBS_SIZEBOX or SBS_SIZEGRIP; excludes: 0),
    (style: SBS_SIZEBOXBOTTOMRIGHTALIGN; name: 'SBS_SIZEBOXBOTTOMRIGHTALIGN'; cmp_mask: 0; depends: SBS_SIZEBOX or SBS_SIZEGRIP; excludes: 0),
    (style: SBS_SIZEBOX; name: 'SBS_SIZEBOX'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: SBS_SIZEGRIP; name: 'SBS_SIZEGRIP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  StaticStyles: array[0..30] of TStyleLookupEx = (
    (style: SS_LEFT; name: 'SS_LEFT'; cmp_mask: $1F; depends: NO_DATA; excludes: SS_CENTER or SS_RIGHT),
    (style: SS_CENTER; name: 'SS_CENTER'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_RIGHT; name: 'SS_RIGHT'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_ICON; name: 'SS_ICON'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_BLACKRECT; name: 'SS_BLACKRECT'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_GRAYRECT; name: 'SS_GRAYRECT'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_WHITERECT; name: 'SS_WHITERECT'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_BLACKFRAME; name: 'SS_BLACKFRAME'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_GRAYFRAME; name: 'SS_GRAYFRAME'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_WHITEFRAME; name: 'SS_WHITEFRAME'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_USERITEM; name: 'SS_USERITEM'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_SIMPLE; name: 'SS_SIMPLE'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_LEFTNOWORDWRAP; name: 'SS_LEFTNOWORDWRAP'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_OWNERDRAW; name: 'SS_OWNERDRAW'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_BITMAP; name: 'SS_BITMAP'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_ENHMETAFILE; name: 'SS_ENHMETAFILE'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_ETCHEDHORZ; name: 'SS_ETCHEDHORZ'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_ETCHEDVERT; name: 'SS_ETCHEDVERT'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_ETCHEDFRAME; name: 'SS_ETCHEDFRAME'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_TYPEMASK; name: 'SS_TYPEMASK'; cmp_mask: $1F; depends: NO_DATA; excludes: 0),
    (style: SS_NOPREFIX; name: 'SS_NOPREFIX'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: SS_NOTIFY; name: 'SS_NOTIFY'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: SS_CENTERIMAGE; name: 'SS_CENTERIMAGE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: SS_RIGHTJUST; name: 'SS_RIGHTJUST'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: SS_REALSIZEIMAGE; name: 'SS_REALSIZEIMAGE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: SS_SUNKEN; name: 'SS_SUNKEN'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: SS_ENDELLIPSIS; name: 'SS_ENDELLIPSIS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: SS_PATHELLIPSIS; name: 'SS_PATHELLIPSIS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: SS_WORDELLIPSIS; name: 'SS_WORDELLIPSIS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: SS_ELLIPSISMASK; name: 'SS_ELLIPSISMASK'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  CommCtrlList: array[0..8] of TStyleLookupEx = (
    (style: CCS_TOP; name: 'CCS_TOP'; cmp_mask: $3; depends: NO_DATA; excludes: 0),
    (style: CCS_NOMOVEY; name: 'CCS_NOMOVEY'; cmp_mask: $3; depends: NO_DATA; excludes: 0),
    (style: CCS_BOTTOM; name: 'CCS_BOTTOM'; cmp_mask: $3; depends: NO_DATA; excludes: 0),
    (style: CCS_NORESIZE; name: 'CCS_NORESIZE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CCS_NOPARENTALIGN; name: 'CCS_NOPARENTALIGN'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CCS_ADJUSTABLE; name: 'CCS_ADJUSTABLE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CCS_NODIVIDER; name: 'CCS_NODIVIDER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CCS_VERT; name: 'CCS_VERT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  HeaderStyles: array[0..7] of TStyleLookupEx = (
    (style: HDS_HORZ; name: 'HDS_HORZ'; cmp_mask: 0; depends: NO_DATA; excludes: 16),
    (style: HDS_BUTTONS; name: 'HDS_BUTTONS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: HDS_HOTTRACK; name: 'HDS_HOTTRACK'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: HDS_DRAGDROP; name: 'HDS_DRAGDROP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: HDS_FULLDRAG; name: 'HDS_FULLDRAG'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: HDS_HIDDEN; name: 'HDS_HIDDEN'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: HDS_FILTERBAR; name: 'HDS_FILTERBAR'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  ListViewStyles: array[0..19] of TStyleLookupEx = (
    (style: LVS_ICON; name: 'LVS_ICON'; cmp_mask: LVS_TYPEMASK; depends: NO_DATA; excludes: LVS_REPORT or LVS_SMALLICON or LVS_LIST),
    (style: LVS_REPORT; name: 'LVS_REPORT'; cmp_mask: LVS_TYPEMASK; depends: NO_DATA; excludes: 0),
    (style: LVS_SMALLICON; name: 'LVS_SMALLICON'; cmp_mask: LVS_TYPEMASK; depends: NO_DATA; excludes: 0),
    (style: LVS_LIST; name: 'LVS_LIST'; cmp_mask: LVS_TYPEMASK; depends: NO_DATA; excludes: 0),
    (style: LVS_SINGLESEL; name: 'LVS_SINGLESEL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_SHOWSELALWAYS; name: 'LVS_SHOWSELALWAYS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_SORTASCENDING; name: 'LVS_SORTASCENDING'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_SORTDESCENDING; name: 'LVS_SORTDESCENDING'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_SHAREIMAGELISTS; name: 'LVS_SHAREIMAGELISTS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_NOLABELWRAP; name: 'LVS_NOLABELWRAP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_AUTOARRANGE; name: 'LVS_AUTOARRANGE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EDITLABELS; name: 'LVS_EDITLABELS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_OWNERDATA; name: 'LVS_OWNERDATA'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_NOSCROLL; name: 'LVS_NOSCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_ALIGNTOP; name: 'LVS_ALIGNTOP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_ALIGNLEFT; name: 'LVS_ALIGNLEFT'; cmp_mask: LVS_ALIGNMASK; depends: NO_DATA; excludes: 0),
    (style: LVS_OWNERDRAWFIXED; name: 'LVS_OWNERDRAWFIXED'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_NOCOLUMNHEADER; name: 'LVS_NOCOLUMNHEADER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_NOSORTHEADER; name: 'LVS_NOSORTHEADER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  ToolbarStyles: array[0..8] of TStyleLookupEx = (
    (style: TBSTYLE_TOOLTIPS; name: 'TBSTYLE_TOOLTIPS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TBSTYLE_WRAPABLE; name: 'TBSTYLE_WRAPABLE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TBSTYLE_ALTDRAG; name: 'TBSTYLE_ALTDRAG'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TBSTYLE_FLAT; name: 'TBSTYLE_FLAT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TBSTYLE_LIST; name: 'TBSTYLE_LIST'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TBSTYLE_CUSTOMERASE; name: 'TBSTYLE_CUSTOMERASE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TBSTYLE_REGISTERDROP; name: 'TBSTYLE_REGISTERDROP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TBSTYLE_TRANSPARENT; name: 'TBSTYLE_TRANSPARENT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  RebarStyles: array[0..8] of TStyleLookupEx = (
    (style: RBS_TOOLTIPS; name: 'RBS_TOOLTIPS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: RBS_VARHEIGHT; name: 'RBS_VARHEIGHT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: RBS_BANDBORDERS; name: 'RBS_BANDBORDERS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: RBS_FIXEDORDER; name: 'RBS_FIXEDORDER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: RBS_REGISTERDROP; name: 'RBS_REGISTERDROP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: RBS_AUTOSIZE; name: 'RBS_AUTOSIZE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: RBS_VERTICALGRIPPER; name: 'RBS_VERTICALGRIPPER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: RBS_DBLCLKTOGGLE; name: 'RBS_DBLCLKTOGGLE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  TrackbarStyles: array[0..14] of TStyleLookupEx = (
    (style: TBS_AUTOTICKS; name: 'TBS_AUTOTICKS'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: TBS_VERT; name: 'TBS_VERT'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: TBS_HORZ; name: 'TBS_HORZ'; cmp_mask: $F; depends: NO_DATA; excludes: TBS_VERT),
    (style: TBS_TOP; name: 'TBS_TOP'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: TBS_BOTTOM; name: 'TBS_BOTTOM'; cmp_mask: $F; depends: NO_DATA; excludes: TBS_TOP),
    (style: TBS_LEFT; name: 'TBS_LEFT'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: TBS_RIGHT; name: 'TBS_RIGHT'; cmp_mask: $F; depends: NO_DATA; excludes: TBS_LEFT),
    (style: TBS_BOTH; name: 'TBS_BOTH'; cmp_mask: $F; depends: NO_DATA; excludes: 0),
    (style: TBS_NOTICKS; name: 'TBS_NOTICKS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TBS_ENABLESELRANGE; name: 'TBS_ENABLESELRANGE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TBS_FIXEDLENGTH; name: 'TBS_FIXEDLENGTH'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TBS_NOTHUMB; name: 'TBS_NOTHUMB'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TBS_TOOLTIPS; name: 'TBS_TOOLTIPS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TBS_REVERSED; name: 'TBS_REVERSED'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  TreeViewStyles: array[0..16] of TStyleLookupEx = (
    (style: TVS_HASBUTTONS; name: 'TVS_HASBUTTONS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_HASLINES; name: 'TVS_HASLINES'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_LINESATROOT; name: 'TVS_LINESATROOT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_EDITLABELS; name: 'TVS_EDITLABELS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_DISABLEDRAGDROP; name: 'TVS_DISABLEDRAGDROP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_SHOWSELALWAYS; name: 'TVS_SHOWSELALWAYS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_RTLREADING; name: 'TVS_RTLREADING'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_NOTOOLTIPS; name: 'TVS_NOTOOLTIPS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_CHECKBOXES; name: 'TVS_CHECKBOXES'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_TRACKSELECT; name: 'TVS_TRACKSELECT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_SINGLEEXPAND; name: 'TVS_SINGLEEXPAND'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_INFOTIP; name: 'TVS_INFOTIP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_FULLROWSELECT; name: 'TVS_FULLROWSELECT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_NOSCROLL; name: 'TVS_NOSCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_NONEVENHEIGHT; name: 'TVS_NONEVENHEIGHT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TVS_NOHSCROLL; name: 'TVS_NOHSCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  ToolTipStyles: array[0..5] of TStyleLookupEx = (
    (style: TTS_ALWAYSTIP; name: 'TTS_ALWAYSTIP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TTS_NOPREFIX; name: 'TTS_NOPREFIX'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TTS_NOANIMATE; name: 'TTS_NOANIMATE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TTS_NOFADE; name: 'TTS_NOFADE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TTS_BALLOON; name: 'TTS_BALLOON'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  StatusBarStyles: array[0..2] of TStyleLookupEx = (
    (style: SBARS_SIZEGRIP; name: 'SBARS_SIZEGRIP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: SBT_TOOLTIPS; name: 'SBT_TOOLTIPS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  UpDownStyles: array[0..9] of TStyleLookupEx = (
    (style: UDS_WRAP; name: 'UDS_WRAP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: UDS_SETBUDDYINT; name: 'UDS_SETBUDDYINT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: UDS_ALIGNRIGHT; name: 'UDS_ALIGNRIGHT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: UDS_ALIGNLEFT; name: 'UDS_ALIGNLEFT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: UDS_AUTOBUDDY; name: 'UDS_AUTOBUDDY'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: UDS_ARROWKEYS; name: 'UDS_ARROWKEYS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: UDS_HORZ; name: 'UDS_HORZ'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: UDS_NOTHOUSANDS; name: 'UDS_NOTHOUSANDS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: UDS_HOTTRACK; name: 'UDS_HOTTRACK'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  ProgressStyles: array[0..2] of TStyleLookupEx = (
    (style: PBS_SMOOTH; name: 'PBS_SMOOTH'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: PBS_VERTICAL; name: 'PBS_VERTICAL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  TabStyles: array[0..20] of TStyleLookupEx = (
    (style: TCS_SCROLLOPPOSITE; name: 'TCS_SCROLLOPPOSITE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_BOTTOM; name: 'TCS_BOTTOM'; cmp_mask: 0; depends: TCS_VERTICAL; excludes: 0),
    (style: TCS_RIGHT; name: 'TCS_RIGHT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_MULTISELECT; name: 'TCS_MULTISELECT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_FLATBUTTONS; name: 'TCS_FLATBUTTONS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_FORCEICONLEFT; name: 'TCS_FORCEICONLEFT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_FORCELABELLEFT; name: 'TCS_FORCELABELLEFT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_HOTTRACK; name: 'TCS_HOTTRACK'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_VERTICAL; name: 'TCS_VERTICAL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_TABS; name: 'TCS_TABS'; cmp_mask: 0; depends: NO_DATA; excludes: TCS_BUTTONS),
    (style: TCS_BUTTONS; name: 'TCS_BUTTONS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_SINGLELINE; name: 'TCS_SINGLELINE'; cmp_mask: 0; depends: NO_DATA; excludes: TCS_MULTILINE),
    (style: TCS_MULTILINE; name: 'TCS_MULTILINE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_RIGHTJUSTIFY; name: 'TCS_RIGHTJUSTIFY'; cmp_mask: 0; depends: NO_DATA; excludes: NO_DATA),
    (style: TCS_FIXEDWIDTH; name: 'TCS_FIXEDWIDTH'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_RAGGEDRIGHT; name: 'TCS_RAGGEDRIGHT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_FOCUSONBUTTONDOWN; name: 'TCS_FOCUSONBUTTONDOWN'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_OWNERDRAWFIXED; name: 'TCS_OWNERDRAWFIXED'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_TOOLTIPS; name: 'TCS_TOOLTIPS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_FOCUSNEVER; name: 'TCS_FOCUSNEVER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  AnimateStyles: array[0..4] of TStyleLookupEx = (
    (style: ACS_CENTER; name: 'ACS_CENTER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ACS_TRANSPARENT; name: 'ACS_TRANSPARENT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ACS_AUTOPLAY; name: 'ACS_AUTOPLAY'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ACS_TIMER; name: 'ACS_TIMER'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  MonthCalStyles: array[0..5] of TStyleLookupEx = (
    (style: MCS_DAYSTATE; name: 'MCS_DAYSTATE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: MCS_MULTISELECT; name: 'MCS_MULTISELECT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: MCS_WEEKNUMBERS; name: 'MCS_WEEKNUMBERS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: MCS_NOTODAYCIRCLE; name: 'MCS_NOTODAYCIRCLE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: MCS_NOTODAY; name: 'MCS_NOTODAY'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  DateTimeStyles: array[0..8] of TStyleLookupEx = (
    (style: DTS_UPDOWN; name: 'DTS_UPDOWN'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DTS_SHOWNONE; name: 'DTS_SHOWNONE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DTS_SHORTDATEFORMAT; name: 'DTS_SHORTDATEFORMAT'; cmp_mask: 0; depends: NO_DATA; excludes: DTS_LONGDATEFORMAT),
    (style: DTS_LONGDATEFORMAT; name: 'DTS_LONGDATEFORMAT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DTS_SHORTDATECENTURYFORMAT; name: 'DTS_SHORTDATECENTURYFORMAT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DTS_TIMEFORMAT; name: 'DTS_TIMEFORMAT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DTS_APPCANPARSE; name: 'DTS_APPCANPARSE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: DTS_RIGHTALIGN; name: 'DTS_RIGHTALIGN'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  PagerStyles: array[0..4] of TStyleLookupEx = (
    (style: PGS_VERT; name: 'PGS_VERT'; cmp_mask: 0; depends: NO_DATA; excludes: PGS_HORZ),
    (style: PGS_HORZ; name: 'PGS_HORZ'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: PGS_AUTOSCROLL; name: 'PGS_AUTOSCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: PGS_DRAGNDROP; name: 'PGS_DRAGNDROP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  // тут дефолтные
  StyleExList: array[0..23] of TStyleLookupEx = (
    (style: WS_EX_PALETTEWINDOW; name: 'WS_EX_PALETTEWINDOW'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_OVERLAPPEDWINDOW; name: 'WS_EX_OVERLAPPEDWINDOW'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_DLGMODALFRAME; name: 'WS_EX_DLGMODALFRAME'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_NOPARENTNOTIFY; name: 'WS_EX_NOPARENTNOTIFY'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_TOPMOST; name: 'WS_EX_TOPMOST'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_ACCEPTFILES; name: 'WS_EX_ACCEPTFILES'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_TRANSPARENT; name: 'WS_EX_TRANSPARENT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_MDICHILD; name: 'WS_EX_MDICHILD'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_TOOLWINDOW; name: 'WS_EX_TOOLWINDOW'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_WINDOWEDGE; name: 'WS_EX_WINDOWEDGE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_CLIENTEDGE; name: 'WS_EX_CLIENTEDGE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_CONTEXTHELP; name: 'WS_EX_CONTEXTHELP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
//    (style: WS_EX_LEFT; name: 'WS_EX_LEFT'; cmp_mask: 0; depends: NO_DATA; excludes: WS_EX_RIGHT),
    (style: WS_EX_RIGHT; name: 'WS_EX_RIGHT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
//    (style: WS_EX_LTRREADING; name: 'WS_EX_LTRREADING'; cmp_mask: 0; depends: NO_DATA; excludes: WS_EX_RTLREADING),
    (style: WS_EX_RTLREADING; name: 'WS_EX_RTLREADING'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_LEFTSCROLLBAR; name: 'WS_EX_LEFTSCROLLBAR'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
//    (style: WS_EX_RIGHTSCROLLBAR; name: 'WS_EX_RIGHTSCROLLBAR'; cmp_mask: 0; depends: NO_DATA; excludes: WS_EX_LEFTSCROLLBAR),
    (style: WS_EX_CONTROLPARENT; name: 'WS_EX_CONTROLPARENT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_STATICEDGE; name: 'WS_EX_STATICEDGE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_APPWINDOW; name: 'WS_EX_APPWINDOW'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_LAYERED; name: 'WS_EX_LAYERED'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_NOINHERITLAYOUT; name: 'WS_EX_NOINHERITLAYOUT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_LAYOUTRTL; name: 'WS_EX_LAYOUTRTL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_COMPOSITED; name: 'WS_EX_COMPOSITED'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: WS_EX_NOACTIVATE; name: 'WS_EX_NOACTIVATE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );


  ListViewExStyles: array[0..15] of TStyleLookupEx = (
    (style: LVS_EX_GRIDLINES; name: 'LVS_EX_GRIDLINES'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EX_SUBITEMIMAGES; name: 'LVS_EX_SUBITEMIMAGES'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EX_CHECKBOXES; name: 'LVS_EX_CHECKBOXES'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EX_TRACKSELECT; name: 'LVS_EX_TRACKSELECT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EX_HEADERDRAGDROP; name: 'LVS_EX_HEADERDRAGDROP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EX_FULLROWSELECT; name: 'LVS_EX_FULLROWSELECT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EX_ONECLICKACTIVATE; name: 'LVS_EX_ONECLICKACTIVATE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EX_TWOCLICKACTIVATE; name: 'LVS_EX_TWOCLICKACTIVATE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EX_FLATSB; name: 'LVS_EX_FLATSB'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EX_REGIONAL; name: 'LVS_EX_REGIONAL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EX_INFOTIP; name: 'LVS_EX_INFOTIP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EX_UNDERLINEHOT; name: 'LVS_EX_UNDERLINEHOT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EX_UNDERLINECOLD; name: 'LVS_EX_UNDERLINECOLD'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EX_MULTIWORKAREAS; name: 'LVS_EX_MULTIWORKAREAS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: LVS_EX_LABELTIP; name: 'LVS_EX_LABELTIP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  ComboBoxExStyles: array[0..5] of TStyleLookupEx = (
    (style: CBES_EX_NOEDITIMAGE; name: 'CBES_EX_NOEDITIMAGE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CBES_EX_NOEDITIMAGEINDENT; name: 'CBES_EX_NOEDITIMAGEINDENT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CBES_EX_PATHWORDBREAKPROC; name: 'CBES_EX_PATHWORDBREAKPROC'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CBES_EX_NOSIZELIMIT; name: 'CBES_EX_NOSIZELIMIT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: CBES_EX_CASESENSITIVE; name: 'CBES_EX_CASESENSITIVE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  TabCtrlExStyles: array[0..2] of TStyleLookupEx = (
    (style: TCS_EX_FLATSEPARATORS; name: 'TCS_EX_FLATSEPARATORS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TCS_EX_REGISTERDROP; name: 'TCS_EX_REGISTERDROP'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  ToolBarExStyles: array[0..3] of TStyleLookupEx = (
    (style: TBSTYLE_EX_DRAWDDARROWS; name: 'TBSTYLE_EX_DRAWDDARROWS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TBSTYLE_EX_MIXEDBUTTONS; name: 'TBSTYLE_EX_MIXEDBUTTONS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: TBSTYLE_EX_HIDECLIPPEDBUTTONS; name: 'TBSTYLE_EX_HIDECLIPPEDBUTTONS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  RichedEventMask: array[0..17] of TStyleLookupEx = (
    (style: ENM_NONE; name: 'ENM_NONE'; cmp_mask: 0; depends: NO_DATA; excludes: NO_DATA),
    (style: ENM_CHANGE; name: 'ENM_CHANGE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_UPDATE; name: 'ENM_UPDATE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_SCROLL; name: 'ENM_SCROLL'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_KEYEVENTS; name: 'ENM_KEYEVENTS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_MOUSEEVENTS; name: 'ENM_MOUSEEVENTS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_REQUESTRESIZE; name: 'ENM_REQUESTRESIZE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_SELCHANGE; name: 'ENM_SELCHANGE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_DROPFILES; name: 'ENM_DROPFILES'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_PROTECTED; name: 'ENM_PROTECTED'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_CORRECTTEXT; name: 'ENM_CORRECTTEXT'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_SCROLLEVENTS; name: 'ENM_SCROLLEVENTS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_DRAGDROPDONE; name: 'ENM_DRAGDROPDONE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_IMECHANGE; name: 'ENM_IMECHANGE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_LANGCHANGE; name: 'ENM_LANGCHANGE'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_OBJECTPOSITIONS; name: 'ENM_OBJECTPOSITIONS'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: ENM_LINK; name: 'ENM_LINK'; cmp_mask: 0; depends: NO_DATA; excludes: 0),
    (style: NO_DATA; name: ''; cmp_mask: NO_DATA; depends: NO_DATA; excludes: NO_DATA)
  );

  // Таблицы поиска классов
  StandardControls: array[0..27] of TClassStyleLookup = (
    (szClassName: DIALOG_TYPE; stylelist: @DialogStyles),
    (szClassName: 'BUTTON'; stylelist: @ButtonStyles),
    (szClassName: 'COMBOBOX'; stylelist: @ComboStyles),
    (szClassName: 'EDIT'; stylelist: @EditStyles),
    (szClassName: 'LISTBOX'; stylelist: @ListBoxStyles),
    (szClassName: 'RICHEDIT'; stylelist: @RichedStyles),
    (szClassName: 'RichEdit20A'; stylelist: @RichedStyles),
    (szClassName: 'RichEdit20W'; stylelist: @RichedStyles),
    (szClassName: 'SCROLLBAR'; stylelist: @ScrollbarStyles),
    (szClassName: 'STATIC'; stylelist: @StaticStyles),
    (szClassName: 'SysAnimate32'; stylelist: @AnimateStyles),
    (szClassName: 'ComboBoxEx32'; stylelist: @ComboStyles),
    (szClassName: 'SysDateTimePick32'; stylelist: @DateTimeStyles),
    (szClassName: 'DragList'; stylelist: @ListBoxStyles),
    (szClassName: 'SysHeader32'; stylelist: @HeaderStyles),
    (szClassName: 'SysListView32'; stylelist: @ListViewStyles),
    (szClassName: 'SysMonthCal32'; stylelist: @MonthCalStyles),
    (szClassName: 'SysPager'; stylelist: @PagerStyles),
    (szClassName: 'msctls_progress32'; stylelist: @ProgressStyles),
    (szClassName: 'RebarWindow32'; stylelist: @RebarStyles),
    (szClassName: 'msctls_statusbar32'; stylelist: @StatusBarStyles),
    (szClassName: 'SysTabControl32'; stylelist: @TabStyles),
    (szClassName: 'ToolbarWindow32'; stylelist: @ToolbarStyles),
    (szClassName: 'tooltips_class32'; stylelist: @ToolTipStyles),
    (szClassName: 'msctls_trackbar32'; stylelist: @TrackbarStyles),
    (szClassName: 'SysTreeView32'; stylelist: @TreeViewStyles),
    (szClassName: 'msctls_updown32'; stylelist: @UpDownStyles),
    (szClassName: nil; stylelist: nil)
  );

  CustomControls: array[0..4] of TClassStyleLookup = (
    (szClassName: 'msctls_statusbar32'; stylelist: @CommCtrlList),
    (szClassName: 'RebarWindow32'; stylelist: @CommCtrlList),
    (szClassName: 'ToolbarWindow32'; stylelist: @CommCtrlList),
    (szClassName: 'SysHeader32'; stylelist: @CommCtrlList),
    (szClassName: nil; stylelist: nil)
  );

  ExtendedControls: array[0..7] of TClassStyleLookup = (
    (szClassName: 'SysTabControl32'; stylelist: @TabCtrlExStyles),
    (szClassName: 'ToolbarWindow32'; stylelist: @ToolBarExStyles),
    (szClassName: 'ComboBoxEx32'; stylelist: @ComboBoxExStyles),
    (szClassName: 'SysListView32'; stylelist: @ListViewExStyles),
    (szClassName: 'RICHEDIT'; stylelist: @RichedEventMask),
    (szClassName: 'RichEdit20A'; stylelist: @RichedEventMask),
    (szClassName: 'RichEdit20W'; stylelist: @RichedEventMask),
    (szClassName: nil; stylelist: nil)
  );

  function FillStyleLists(const szClassName: string;
    dwStyle, dwExtendedStyle: DWORD): string;

implementation

function FindStyleList(ClassStyleLookup: PClassStyleLookup;
  const szClassName: string): PStyleLookupEx;
begin
  Result := nil;
  while ClassStyleLookup^.szClassName <> nil do
  begin
    if ClassStyleLookup^.szClassName = szClassName then
      Exit(ClassStyleLookup^.stylelist);
    Inc(ClassStyleLookup);
  end;
end;

//
//	Find all the styles that match from the specified list
//
//	StyleList  - list of styles
//  dwStyle    - style for the target window
//

function EnumStyles(StyleList: PStyleLookupEx; dwStyle: DWORD; var StyleStr: string): DWORD;
var
  fAddIt: Boolean;
  dwOrig: DWORD;
begin
  // Remember what the style is before we start modifying it
  dwOrig := dwStyle;

	//
	//	Loop through all of the styles that we know about
	//	Check each style against our window's one, to see
	//  if it is set or not
	//
  while StyleList^.style <> NO_DATA do
  begin
    fAddIt := False;

		// This style needs a mask to detect if it is set -
		// i.e. the style doesn't just use one bit to decide if it is on/off.
    if StyleList^.cmp_mask <> 0 then
    begin
      // Style is valid if the excludes styles are not set
      if (StyleList^.excludes <> 0) and ((StyleList^.excludes and (dwOrig and StyleList^.cmp_mask)) = 0) then
        fAddIt := True;

      // If the style matches exactly (when masked)
      if (StyleList^.style <> 0) and ((StyleList^.cmp_mask and dwStyle) = StyleList^.style) then
        fAddIt := True;
    end
    else
    begin
      // Style is valid when
      if (StyleList^.excludes <> 0) and ((StyleList^.excludes and dwOrig) = 0) then
        fAddIt := True;

      // If style matches exactly (all bits are set
      if (StyleList^.style <> 0) and ((StyleList^.style and dwStyle) = StyleList^.style) then
        fAddIt := True

      // If no bits are set, then we have to skip it
      else if (StyleList^.style <> 0) and ((StyleList^.style and dwStyle) = 0) then
        fAddIt := False;

      // If this style depends on others being set..
      if (dwStyle <> 0) and ((StyleList^.depends and dwStyle) = 0) then
        fAddIt := False;
    end;

    // Now add the style..
    if fAddIt then
    begin
      // We've added this style, so remove it to stop it appearing again
      dwStyle := dwStyle and not StyleList^.style;
      StyleStr := StyleStr + StyleList^.name + ' ';
    end;

    Inc(StyleList);
  end;

	// return the style. This will be zero if we decoded all the bits
	// that were set, or non-zero if there are still bits left
  Result := dwStyle;
end;

function FillStyleLists(const szClassName: string;
  dwStyle, dwExtendedStyle: DWORD): string;
var
  OrigStyle: DWORD;
  StyleList: PStyleLookupEx;
  DefStyleString, ExStyleString: string;
begin
  Result := '';
  OrigStyle := dwStyle;

  // enumerate the standard window styles, for any window no
  // matter what class it might be
  DefStyleString := '';
  dwStyle := EnumStyles(@WindowStyles[0], dwStyle, DefStyleString);

  // if the window class is one we know about, then see if we
  // can decode any more style bits
  // enumerate the custom control styles
  StyleList := FindStyleList(@StandardControls[0], szClassName);
  if Assigned(StyleList) then
    dwStyle := EnumStyles(StyleList, dwStyle, Result);

  // does the window support the CCS_xxx styles (custom control styles)
  StyleList := FindStyleList(@CustomControls[0], szClassName);
  if Assigned(StyleList) then
    dwStyle := EnumStyles(StyleList, dwStyle, Result);

  // if there are still style bits set in the window style,
  // then there is something that we can't decode. Just display
  // a single HEX entry at the end of the list.
  if dwStyle <> 0 then
    Result := Format('%s0x%.8X ', [Result, dwStyle]);

  if DefStyleString <> '' then
    Result := Format('%s%s', [Result, DefStyleString]);

  if dwExtendedStyle <> 0 then
  begin
    // Extended window styles
    ExStyleString := '';
    dwExtendedStyle := EnumStyles(@StyleExList[0], dwExtendedStyle, ExStyleString);

    // Does this window use any custom control extended styles???
    StyleList := FindStyleList(@ExtendedControls[0], szClassName);
    if Assigned(StyleList) then
      EnumStyles(StyleList, dwExtendedStyle, ExStyleString);

    if ExStyleString <> '' then
    begin
      if OrigStyle = 0 then
        Result := ExStyleString
      else
        Result := Format('%s%s', [Result, ExStyleString]);
    end;
  end;

  if Result <> '' then
    Result := StringReplace(Trim(Result), ' ', ' | ', [rfReplaceAll]);
end;

end.