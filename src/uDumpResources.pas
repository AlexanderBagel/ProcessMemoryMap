////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uDumpResources.pas
//  * Purpose   : Вспомогательные функции для работы с ресурсами
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.7.53
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uDumpResources;

interface

uses
  Windows,
  Classes,
  SysUtils,
  StrUtils,
  RawScanner.Resources,
  RawScanner.Resources.Helpers,
  uDisplayStyleInfo;

type
  PIdList = ^TIdList;
  TIdList = array of Word;

  function GetBitmapStreamFromDib(ARes: TResource): TMemoryStream;
  function GetCursorIconStreamFromDib(ARes: TResource; AResType: Word): TMemoryStream;
  function GetCursorGroupStream(ARes: TResource; out IdList: TIdList): TMemoryStream;
  function GetIconGroupStream(ARes: TResource; out IdList: TIdList): TMemoryStream;
  function VersionToRC(ARes: TResource): TStringList;
  function LookupLangID(ALangID: LANGID; out ALangName, ASubName: string): Boolean;
  function StringsToRC(ARes: TResource): TStringList;
  function MessageTableToString(ARes: TResource): TStringList;
  function AcceleratorsToRC(ARes: TResource): TStringList;
  function MenuToRC(ARes: TResource): TStringList;
  function DialogToRC(ARes: TResource): TStringList;
  function DVCLALToString(ARes: TResource): TStringList;
  function PackageInfoToString(ARes: TResource): TStringList;
  function DFMToString(ARes: TResource): TStringList;

implementation

const
  PNG_CT_GRAYSCALE = 0;
  PNG_CT_RGB = 2;
  PNG_CT_INDEXED = 3;
  PNG_CT_GRAYSCALE_ALPHA = 4;
  PNG_CT_RGBA = 6;

  BI_RGB = 0;
  BI_BITFIELDS = 3;

  FVIRTKEY = $01;
  FNOINVERT = $02;
  FSHIFT = $04;
  FCONTROL = $08;
  FALT = $10;
  FEND = $80;

  MESSAGE_RESOURCE_UNICODE = $0001;

type
  PMessageResourceData = ^TMessageResourceData;
  TMessageResourceData = packed record
    NumberOfBlocks: DWORD;
    // Blocks: array [NumberOfBlocks] of TMessageResourceBlock
  end;

  PMessageResourceBlock = ^TMessageResourceBlock;
  TMessageResourceBlock = packed record
    LowId: DWORD;
    HighId: DWORD;
    OffsetToEntries: DWORD;
  end;

  PMessageResourceEntry = ^TMessageResourceEntry;
  TMessageResourceEntry = packed record
    Length: Word; // полный размер TMessageResourceEntry вместе с данными
    Flags: Word;  // 0 или MESSAGE_RESOURCE_UNICODE
    Text: {array [Length - 4] of} Byte
  end;

  TAccelEntry = packed record
    fFlags: Word;
    wAnsi: Word;
    wId: Word;
    padding: Word;
  end;

  TMenuHeader = packed record
    wVersion: Word;
    cbHeaderSize: Word;
  end;

  TMenuExTemplateHeader = packed record
    wVersion: Word;
    cbHeaderSize: Word;
    dwHelpID: DWORD;
  end;

  TMenuExTemplateItem = packed record
    dwType: DWORD;
    dwState: DWORD;
    uId: UINT;
    wFlags: Word;
    // szText: array of Char;
  end;

  TDlgTemplateEx = packed record
    wVersion: WORD;
    wSignature: WORD;
    helpID: DWORD;
    exStyle: DWORD;
    style: DWORD;
    cDlgItems: WORD;
    x: SmallInt;
    y: SmallInt;
    cx: SmallInt;
    cy: SmallInt;
  end;

  TDlgItemTemplateEx = record
    helpID: DWORD;
    exStyle: DWORD;
    style: DWORD;
    x: SHORT;
    y: SHORT;
    cx: SHORT;
    cy: SHORT;
    id: DWORD;
  end;

  TDialogFontInfo = packed record
    wPointSize: Word;
    wWeight: Word;
    bItalic: Byte;
    bCharset: Byte;
    // FaceName: array of WideChar;
  end;

const
  DefDialogFontInfo: TDialogFontInfo = (
    wPointSize: 8;
    wWeight: FW_NORMAL;
    bItalic: 0;
    bCharset: DEFAULT_CHARSET;
  );

type

  TLangEntry = record
    LangID: LANGID;
    LangName: string;
    SubName: string;
  end;

const
  LN_SPANISH = 'LANG_SPANISH';
  LN_ARABIC = 'LANG_ARABIC';
  LN_ENGLISH = 'LANG_ENGLISH';
  LN_SAMI = 'LANG_SAMI';
  LN_SERBIAN = 'LANG_SERBIAN';
  LN_FRENCH = 'LANG_FRENCH';
  LN_NEUTRAL = 'LANG_NEUTRAL';
  LN_CHINESE = 'LANG_CHINESE';
  LN_GERMAN = 'LANG_GERMAN';
  LN_QUECHUA = 'LANG_QUECHUA';
  LN_AZERBAIJANI = 'LANG_AZERBAIJANI';
  LN_BANGLA = 'LANG_BANGLA';
  LN_BOSNIAN = 'LANG_BOSNIAN';
  LN_CATALAN = 'LANG_CATALAN';
  LN_CROATIAN = 'LANG_CROATIAN';
  LN_DUTCH = 'LANG_DUTCH';
  LN_INUKTITUT = 'LANG_INUKTITUT';
  LN_ITALIAN = 'LANG_ITALIAN';
  LN_MALAY = 'LANG_MALAY';
  LN_MONGOLIAN = 'LANG_MONGOLIAN';
  LN_NEPALI = 'LANG_NEPALI';
  LN_NORWEGIAN = 'LANG_NORWEGIAN';
  LN_PORTUGUESE = 'LANG_PORTUGUESE';
  LN_PUNJABI = 'LANG_PUNJABI';
  LN_SINDHI = 'LANG_SINDHI';
  LN_SWEDISH = 'LANG_SWEDISH';
  LN_TAMAZIGHT = 'LANG_TAMAZIGHT';
  LN_TAMIL = 'LANG_TAMIL';
  LN_TIGRINYA = 'LANG_TIGRINYA';
  LN_TSWANA = 'LANG_TSWANA';
  LN_URDU = 'LANG_URDU';
  LN_UZBEK = 'LANG_UZBEK';

  LangIDTable: array[0..232] of TLangEntry = (
    (LangID: $0000; LangName: LN_NEUTRAL; SubName: 'SUBLANG_NEUTRAL'),
    (LangID: $0400; LangName: LN_NEUTRAL; SubName: 'SUBLANG_DEFAULT'),
    (LangID: $0401; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_SAUDI_ARABIA'),
    (LangID: $0402; LangName: 'LANG_BULGARIAN'; SubName: 'SUBLANG_BULGARIAN_BULGARIA'),
    (LangID: $0403; LangName: LN_CATALAN; SubName: 'SUBLANG_CATALAN_CATALAN'),
    (LangID: $0404; LangName: LN_CHINESE; SubName: 'SUBLANG_CHINESE_TRADITIONAL'),
    (LangID: $0405; LangName: 'LANG_CZECH'; SubName: 'SUBLANG_CZECH_CZECH_REPUBLIC'),
    (LangID: $0406; LangName: 'LANG_DANISH'; SubName: 'SUBLANG_DANISH_DENMARK'),
    (LangID: $0407; LangName: LN_GERMAN; SubName: 'SUBLANG_GERMAN'),
    (LangID: $0408; LangName: 'LANG_GREEK'; SubName: 'SUBLANG_GREEK_GREECE'),
    (LangID: $0409; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_US'),
    (LangID: $040A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH'),
    (LangID: $040B; LangName: 'LANG_FINNISH'; SubName: 'SUBLANG_FINNISH_FINLAND'),
    (LangID: $040C; LangName: LN_FRENCH; SubName: 'SUBLANG_FRENCH'),
    (LangID: $040D; LangName: 'LANG_HEBREW'; SubName: 'SUBLANG_HEBREW_ISRAEL'),
    (LangID: $040E; LangName: 'LANG_HUNGARIAN'; SubName: 'SUBLANG_HUNGARIAN_HUNGARY'),
    (LangID: $040F; LangName: 'LANG_ICELANDIC'; SubName: 'SUBLANG_ICELANDIC_ICELAND'),
    (LangID: $0410; LangName: LN_ITALIAN; SubName: 'SUBLANG_ITALIAN'),
    (LangID: $0411; LangName: 'LANG_JAPANESE'; SubName: 'SUBLANG_JAPANESE_JAPAN'),
    (LangID: $0412; LangName: 'LANG_KOREAN'; SubName: 'SUBLANG_KOREAN'),
    (LangID: $0413; LangName: LN_DUTCH; SubName: 'SUBLANG_DUTCH'),
    (LangID: $0414; LangName: LN_NORWEGIAN; SubName: 'SUBLANG_NORWEGIAN_BOKMAL'),
    (LangID: $0415; LangName: 'LANG_POLISH'; SubName: 'SUBLANG_POLISH_POLAND'),
    (LangID: $0416; LangName: LN_PORTUGUESE; SubName: 'SUBLANG_PORTUGUESE_BRAZILIAN'),
    (LangID: $0417; LangName: 'LANG_ROMANSH'; SubName: 'SUBLANG_ROMANSH_SWITZERLAND'),
    (LangID: $0418; LangName: 'LANG_ROMANIAN'; SubName: 'SUBLANG_ROMANIAN_ROMANIA'),
    (LangID: $0419; LangName: 'LANG_RUSSIAN'; SubName: 'SUBLANG_RUSSIAN_RUSSIA'),
    (LangID: $041A; LangName: LN_CROATIAN; SubName: 'SUBLANG_CROATIAN_CROATIA'),
    (LangID: $041B; LangName: 'LANG_SLOVAK'; SubName: 'SUBLANG_SLOVAK_SLOVAKIA'),
    (LangID: $041C; LangName: 'LANG_ALBANIAN'; SubName: 'SUBLANG_ALBANIAN_ALBANIA'),
    (LangID: $041D; LangName: LN_SWEDISH; SubName: 'SUBLANG_SWEDISH'),
    (LangID: $041E; LangName: 'LANG_THAI'; SubName: 'SUBLANG_THAI_THAILAND'),
    (LangID: $041F; LangName: 'LANG_TURKISH'; SubName: 'SUBLANG_TURKISH_TURKEY'),
    (LangID: $0420; LangName: LN_URDU; SubName: 'SUBLANG_URDU_PAKISTAN'),
    (LangID: $0421; LangName: 'LANG_INDONESIAN'; SubName: 'SUBLANG_INDONESIAN_INDONESIA'),
    (LangID: $0422; LangName: 'LANG_UKRAINIAN'; SubName: 'SUBLANG_UKRAINIAN_UKRAINE'),
    (LangID: $0423; LangName: 'LANG_BELARUSIAN'; SubName: 'SUBLANG_BELARUSIAN_BELARUS'),
    (LangID: $0424; LangName: 'LANG_SLOVENIAN'; SubName: 'SUBLANG_SLOVENIAN_SLOVENIA'),
    (LangID: $0425; LangName: 'LANG_ESTONIAN'; SubName: 'SUBLANG_ESTONIAN_ESTONIA'),
    (LangID: $0426; LangName: 'LANG_LATVIAN'; SubName: 'SUBLANG_LATVIAN_LATVIA'),
    (LangID: $0427; LangName: 'LANG_LITHUANIAN'; SubName: 'SUBLANG_LITHUANIAN'),
    (LangID: $0428; LangName: 'LANG_TAJIK'; SubName: 'SUBLANG_TAJIK_TAJIKISTAN'),
    (LangID: $0429; LangName: 'LANG_PERSIAN'; SubName: 'SUBLANG_PERSIAN_IRAN'),
    (LangID: $042A; LangName: 'LANG_VIETNAMESE'; SubName: 'SUBLANG_VIETNAMESE_VIETNAM'),
    (LangID: $042B; LangName: 'LANG_ARMENIAN'; SubName: 'SUBLANG_ARMENIAN_ARMENIA'),
    (LangID: $042C; LangName: LN_AZERBAIJANI; SubName: 'SUBLANG_AZERBAIJANI_AZERBAIJAN_LATIN'),
    (LangID: $042D; LangName: 'LANG_BASQUE'; SubName: 'SUBLANG_BASQUE_BASQUE'),
    (LangID: $042E; LangName: 'LANG_UPPER_SORBIAN'; SubName: 'SUBLANG_UPPER_SORBIAN_GERMANY'),
    (LangID: $042F; LangName: 'LANG_MACEDONIAN'; SubName: 'SUBLANG_MACEDONIAN_MACEDONIA'),
    (LangID: $0432; LangName: LN_TSWANA; SubName: 'SUBLANG_TSWANA_SOUTH_AFRICA'),
    (LangID: $0434; LangName: 'LANG_XHOSA'; SubName: 'SUBLANG_XHOSA_SOUTH_AFRICA'),
    (LangID: $0435; LangName: 'LANG_ZULU'; SubName: 'SUBLANG_ZULU_SOUTH_AFRICA'),
    (LangID: $0436; LangName: 'LANG_AFRIKAANS'; SubName: 'SUBLANG_AFRIKAANS_SOUTH_AFRICA'),
    (LangID: $0437; LangName: 'LANG_GEORGIAN'; SubName: 'SUBLANG_GEORGIAN_GEORGIA'),
    (LangID: $0438; LangName: 'LANG_FAEROESE'; SubName: 'SUBLANG_FAEROESE_FAROE_ISLANDS'),
    (LangID: $0439; LangName: 'LANG_HINDI'; SubName: 'SUBLANG_HINDI_INDIA'),
    (LangID: $043A; LangName: 'LANG_MALTESE'; SubName: 'SUBLANG_MALTESE_MALTA'),
    (LangID: $043B; LangName: LN_SAMI; SubName: 'SUBLANG_SAMI_NORTHERN_NORWAY'),
    (LangID: $043E; LangName: LN_MALAY; SubName: 'SUBLANG_MALAY_MALAYSIA'),
    (LangID: $043F; LangName: 'LANG_KAZAK'; SubName: 'SUBLANG_KAZAK_KAZAKHSTAN'),
    (LangID: $0440; LangName: 'LANG_KYRGYZ'; SubName: 'SUBLANG_KYRGYZ_KYRGYZSTAN'),
    (LangID: $0441; LangName: 'LANG_SWAHILI'; SubName: 'SUBLANG_SWAHILI_KENYA'),
    (LangID: $0442; LangName: 'LANG_TURKMEN'; SubName: 'SUBLANG_TURKMEN_TURKMENISTAN'),
    (LangID: $0443; LangName: LN_UZBEK; SubName: 'SUBLANG_UZBEK_LATIN'),
    (LangID: $0444; LangName: 'LANG_TATAR'; SubName: 'SUBLANG_TATAR_RUSSIA'),
    (LangID: $0445; LangName: LN_BANGLA; SubName: 'SUBLANG_BANGLA_INDIA'),
    (LangID: $0446; LangName: LN_PUNJABI; SubName: 'SUBLANG_PUNJABI_INDIA'),
    (LangID: $0447; LangName: 'LANG_GUJARATI'; SubName: 'SUBLANG_GUJARATI_INDIA'),
    (LangID: $0448; LangName: 'LANG_ODIA'; SubName: 'SUBLANG_ODIA_INDIA'),
    (LangID: $0449; LangName: LN_TAMIL; SubName: 'SUBLANG_TAMIL_INDIA'),
    (LangID: $044A; LangName: 'LANG_TELUGU'; SubName: 'SUBLANG_TELUGU_INDIA'),
    (LangID: $044B; LangName: 'LANG_KANNADA'; SubName: 'SUBLANG_KANNADA_INDIA'),
    (LangID: $044C; LangName: 'LANG_MALAYALAM'; SubName: 'SUBLANG_MALAYALAM_INDIA'),
    (LangID: $044D; LangName: 'LANG_ASSAMESE'; SubName: 'SUBLANG_ASSAMESE_INDIA'),
    (LangID: $044E; LangName: 'LANG_MARATHI'; SubName: 'SUBLANG_MARATHI_INDIA'),
    (LangID: $044F; LangName: 'LANG_SANSKRIT'; SubName: 'SUBLANG_SANSKRIT_INDIA'),
    (LangID: $0450; LangName: LN_MONGOLIAN; SubName: 'SUBLANG_MONGOLIAN_CYRILLIC_MONGOLIA'),
    (LangID: $0451; LangName: 'LANG_TIBETAN'; SubName: 'SUBLANG_TIBETAN_PRC'),
    (LangID: $0452; LangName: 'LANG_WELSH'; SubName: 'SUBLANG_WELSH_UNITED_KINGDOM'),
    (LangID: $0453; LangName: 'LANG_KHMER'; SubName: 'SUBLANG_KHMER_CAMBODIA'),
    (LangID: $0454; LangName: 'LANG_LAO'; SubName: 'SUBLANG_LAO_LAO'),
    (LangID: $0456; LangName: 'LANG_GALICIAN'; SubName: 'SUBLANG_GALICIAN_GALICIAN'),
    (LangID: $0457; LangName: 'LANG_KONKANI'; SubName: 'SUBLANG_KONKANI_INDIA'),
    (LangID: $0459; LangName: LN_SINDHI; SubName: 'SUBLANG_SINDHI_INDIA'),
    (LangID: $045A; LangName: 'LANG_SYRIAC'; SubName: 'SUBLANG_SYRIAC_SYRIA'),
    (LangID: $045B; LangName: 'LANG_SINHALESE'; SubName: 'SUBLANG_SINHALESE_SRI_LANKA'),
    (LangID: $045C; LangName: 'LANG_CHEROKEE'; SubName: 'SUBLANG_CHEROKEE_CHEROKEE'),
    (LangID: $045D; LangName: LN_INUKTITUT; SubName: 'SUBLANG_INUKTITUT_CANADA'),
    (LangID: $045E; LangName: 'LANG_AMHARIC'; SubName: 'SUBLANG_AMHARIC_ETHIOPIA'),
    (LangID: $0461; LangName: LN_NEPALI; SubName: 'SUBLANG_NEPALI_NEPAL'),
    (LangID: $0462; LangName: 'LANG_FRISIAN'; SubName: 'SUBLANG_FRISIAN_NETHERLANDS'),
    (LangID: $0463; LangName: 'LANG_PASHTO'; SubName: 'SUBLANG_PASHTO_AFGHANISTAN'),
    (LangID: $0464; LangName: 'LANG_FILIPINO'; SubName: 'SUBLANG_FILIPINO_PHILIPPINES'),
    (LangID: $0465; LangName: 'LANG_DIVEHI'; SubName: 'SUBLANG_DIVEHI_MALDIVES'),
    (LangID: $0468; LangName: 'LANG_HAUSA'; SubName: 'SUBLANG_HAUSA_NIGERIA_LATIN'),
    (LangID: $046A; LangName: 'LANG_YORUBA'; SubName: 'SUBLANG_YORUBA_NIGERIA'),
    (LangID: $046B; LangName: LN_QUECHUA; SubName: 'SUBLANG_QUECHUA_BOLIVIA'),
    (LangID: $046C; LangName: 'LANG_SOTHO'; SubName: 'SUBLANG_SOTHO_NORTHERN_SOUTH_AFRICA'),
    (LangID: $046D; LangName: 'LANG_BASHKIR'; SubName: 'SUBLANG_BASHKIR_RUSSIA'),
    (LangID: $046E; LangName: 'LANG_LUXEMBOURGISH'; SubName: 'SUBLANG_LUXEMBOURGISH_LUXEMBOURG'),
    (LangID: $046F; LangName: 'LANG_GREENLANDIC'; SubName: 'SUBLANG_GREENLANDIC_GREENLAND'),
    (LangID: $0470; LangName: 'LANG_IGBO'; SubName: 'SUBLANG_IGBO_NIGERIA'),
    (LangID: $0473; LangName: LN_TIGRINYA; SubName: 'SUBLANG_TIGRINYA_ETHIOPIA'),
    (LangID: $0475; LangName: 'LANG_HAWAIIAN'; SubName: 'SUBLANG_HAWAIIAN_US'),
    (LangID: $0478; LangName: 'LANG_YI'; SubName: 'SUBLANG_YI_PRC'),
    (LangID: $047A; LangName: 'LANG_MAPUDUNGUN'; SubName: 'SUBLANG_MAPUDUNGUN_CHILE'),
    (LangID: $047C; LangName: 'LANG_MOHAWK'; SubName: 'SUBLANG_MOHAWK_MOHAWK'),
    (LangID: $047E; LangName: 'LANG_BRETON'; SubName: 'SUBLANG_BRETON_FRANCE'),
    (LangID: $0480; LangName: 'LANG_UIGHUR'; SubName: 'SUBLANG_UIGHUR_PRC'),
    (LangID: $0481; LangName: 'LANG_MAORI'; SubName: 'SUBLANG_MAORI_NEW_ZEALAND'),
    (LangID: $0482; LangName: 'LANG_OCCITAN'; SubName: 'SUBLANG_OCCITAN_FRANCE'),
    (LangID: $0483; LangName: 'LANG_CORSICAN'; SubName: 'SUBLANG_CORSICAN_FRANCE'),
    (LangID: $0484; LangName: 'LANG_ALSATIAN'; SubName: 'SUBLANG_ALSATIAN_FRANCE'),
    (LangID: $0485; LangName: 'LANG_SAKHA'; SubName: 'SUBLANG_SAKHA_RUSSIA'),
    (LangID: $0486; LangName: 'LANG_KICHE'; SubName: 'SUBLANG_KICHE_GUATEMALA'),
    (LangID: $0487; LangName: 'LANG_KINYARWANDA'; SubName: 'SUBLANG_KINYARWANDA_RWANDA'),
    (LangID: $0488; LangName: 'LANG_WOLOF'; SubName: 'SUBLANG_WOLOF_SENEGAL'),
    (LangID: $048C; LangName: 'LANG_DARI'; SubName: 'SUBLANG_DARI_AFGHANISTAN'),
    (LangID: $0491; LangName: 'LANG_SCOTTISH_GAELIC'; SubName: 'SUBLANG_SCOTTISH_GAELIC'),
    (LangID: $0492; LangName: 'LANG_CENTRAL_KURDISH'; SubName: 'SUBLANG_CENTRAL_KURDISH_IRAQ'),
    (LangID: $0800; LangName: LN_NEUTRAL; SubName: 'SUBLANG_SYS_DEFAULT'),
    (LangID: $0801; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_IRAQ'),
    (LangID: $0803; LangName: LN_CATALAN; SubName: 'SUBLANG_VALENCIAN_VALENCIA'),
    (LangID: $0804; LangName: LN_CHINESE; SubName: 'SUBLANG_CHINESE_SIMPLIFIED'),
    (LangID: $0807; LangName: LN_GERMAN; SubName: 'SUBLANG_GERMAN_SWISS'),
    (LangID: $0809; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_UK'),
    (LangID: $080A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_MEXICAN'),
    (LangID: $080C; LangName: LN_FRENCH; SubName: 'SUBLANG_FRENCH_BELGIAN'),
    (LangID: $0810; LangName: LN_ITALIAN; SubName: 'SUBLANG_ITALIAN_SWISS'),
    (LangID: $0813; LangName: LN_DUTCH; SubName: 'SUBLANG_DUTCH_BELGIAN'),
    (LangID: $0814; LangName: LN_NORWEGIAN; SubName: 'SUBLANG_NORWEGIAN_NYNORSK'),
    (LangID: $0816; LangName: LN_PORTUGUESE; SubName: 'SUBLANG_PORTUGUESE'),
    (LangID: $081A; LangName: LN_SERBIAN; SubName: 'SUBLANG_SERBIAN_LATIN'),
    (LangID: $081D; LangName: LN_SWEDISH; SubName: 'SUBLANG_SWEDISH_FINLAND'),
    (LangID: $0820; LangName: LN_URDU; SubName: 'SUBLANG_URDU_INDIA'),
    (LangID: $082C; LangName: LN_AZERBAIJANI; SubName: 'SUBLANG_AZERBAIJANI_AZERBAIJAN_CYRILLIC'),
    (LangID: $082E; LangName: 'LANG_LOWER_SORBIAN'; SubName: 'SUBLANG_LOWER_SORBIAN_GERMANY'),
    (LangID: $0832; LangName: LN_TSWANA; SubName: 'SUBLANG_TSWANA_BOTSWANA'),
    (LangID: $083B; LangName: LN_SAMI; SubName: 'SUBLANG_SAMI_NORTHERN_SWEDEN'),
    (LangID: $083C; LangName: 'LANG_IRISH'; SubName: 'SUBLANG_IRISH_IRELAND'),
    (LangID: $083E; LangName: LN_MALAY; SubName: 'SUBLANG_MALAY_BRUNEI_DARUSSALAM'),
    (LangID: $0843; LangName: LN_UZBEK; SubName: 'SUBLANG_UZBEK_CYRILLIC'),
    (LangID: $0845; LangName: LN_BANGLA; SubName: 'SUBLANG_BANGLA_BANGLADESH'),
    (LangID: $0846; LangName: LN_PUNJABI; SubName: 'SUBLANG_PUNJABI_PAKISTAN'),
    (LangID: $0849; LangName: LN_TAMIL; SubName: 'SUBLANG_TAMIL_SRI_LANKA'),
    (LangID: $0850; LangName: LN_MONGOLIAN; SubName: 'SUBLANG_MONGOLIAN_PRC'),
    (LangID: $0859; LangName: LN_SINDHI; SubName: 'SUBLANG_SINDHI_PAKISTAN'),
    (LangID: $085D; LangName: LN_INUKTITUT; SubName: 'SUBLANG_INUKTITUT_CANADA_LATIN'),
    (LangID: $085F; LangName: LN_TAMAZIGHT; SubName: 'SUBLANG_TAMAZIGHT_ALGERIA_LATIN'),
    (LangID: $0860; LangName: 'LANG_KASHMIRI'; SubName: 'SUBLANG_KASHMIRI_SASIA'),
    (LangID: $0861; LangName: LN_NEPALI; SubName: 'SUBLANG_NEPALI_INDIA'),
    (LangID: $0867; LangName: 'LANG_FULAH'; SubName: 'SUBLANG_FULAH_SENEGAL'),
    (LangID: $086B; LangName: LN_QUECHUA; SubName: 'SUBLANG_QUECHUA_ECUADOR'),
    (LangID: $0873; LangName: LN_TIGRINYA; SubName: 'SUBLANG_TIGRINYA_ERITREA'),
    (LangID: $0C00; LangName: LN_NEUTRAL; SubName: 'SUBLANG_CUSTOM_DEFAULT'),
    (LangID: $0C01; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_EGYPT'),
    (LangID: $0C04; LangName: LN_CHINESE; SubName: 'SUBLANG_CHINESE_HONGKONG'),
    (LangID: $0C07; LangName: LN_GERMAN; SubName: 'SUBLANG_GERMAN_AUSTRIAN'),
    (LangID: $0C09; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_AUS'),
    (LangID: $0C0A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_MODERN'),
    (LangID: $0C0C; LangName: LN_FRENCH; SubName: 'SUBLANG_FRENCH_CANADIAN'),
    (LangID: $0C1A; LangName: LN_SERBIAN; SubName: 'SUBLANG_SERBIAN_CYRILLIC'),
    (LangID: $0C3B; LangName: LN_SAMI; SubName: 'SUBLANG_SAMI_NORTHERN_FINLAND'),
    (LangID: $0C6B; LangName: LN_QUECHUA; SubName: 'SUBLANG_QUECHUA_PERU'),
    (LangID: $1000; LangName: LN_NEUTRAL; SubName: 'SUBLANG_CUSTOM_UNSPECIFIED'),
    (LangID: $1001; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_LIBYA'),
    (LangID: $1004; LangName: LN_CHINESE; SubName: 'SUBLANG_CHINESE_SINGAPORE'),
    (LangID: $1007; LangName: LN_GERMAN; SubName: 'SUBLANG_GERMAN_LUXEMBOURG'),
    (LangID: $1009; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_CAN'),
    (LangID: $100A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_GUATEMALA'),
    (LangID: $100C; LangName: LN_FRENCH; SubName: 'SUBLANG_FRENCH_SWISS'),
    (LangID: $101A; LangName: LN_CROATIAN; SubName: 'SUBLANG_CROATIAN_BOSNIA_HERZEGOVINA_LATIN'),
    (LangID: $103B; LangName: LN_SAMI; SubName: 'SUBLANG_SAMI_LULE_NORWAY'),
    (LangID: $105F; LangName: LN_TAMAZIGHT; SubName: 'SUBLANG_TAMAZIGHT_MOROCCO_TIFINAGH'),
    (LangID: $1400; LangName: LN_NEUTRAL; SubName: 'SUBLANG_UI_CUSTOM_DEFAULT'),
    (LangID: $1401; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_ALGERIA'),
    (LangID: $1404; LangName: LN_CHINESE; SubName: 'SUBLANG_CHINESE_MACAU'),
    (LangID: $1407; LangName: LN_GERMAN; SubName: 'SUBLANG_GERMAN_LIECHTENSTEIN'),
    (LangID: $1409; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_NZ'),
    (LangID: $140A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_COSTA_RICA'),
    (LangID: $140C; LangName: LN_FRENCH; SubName: 'SUBLANG_FRENCH_LUXEMBOURG'),
    (LangID: $141A; LangName: LN_BOSNIAN; SubName: 'SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_LATIN'),
    (LangID: $143B; LangName: LN_SAMI; SubName: 'SUBLANG_SAMI_LULE_SWEDEN'),
    (LangID: $1801; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_MOROCCO'),
    (LangID: $1809; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_EIRE'),
    (LangID: $180A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_PANAMA'),
    (LangID: $180C; LangName: LN_FRENCH; SubName: 'SUBLANG_FRENCH_MONACO'),
    (LangID: $181A; LangName: LN_SERBIAN; SubName: 'SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_LATIN'),
    (LangID: $183B; LangName: LN_SAMI; SubName: 'SUBLANG_SAMI_SOUTHERN_NORWAY'),
    (LangID: $1C01; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_TUNISIA'),
    (LangID: $1C09; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_SOUTH_AFRICA'),
    (LangID: $1C0A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_DOMINICAN_REPUBLIC'),
    (LangID: $1C1A; LangName: LN_SERBIAN; SubName: 'SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_CYRILLIC'),
    (LangID: $1C3B; LangName: LN_SAMI; SubName: 'SUBLANG_SAMI_SOUTHERN_SWEDEN'),
    (LangID: $2001; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_OMAN'),
    (LangID: $2009; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_JAMAICA'),
    (LangID: $200A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_VENEZUELA'),
    (LangID: $201A; LangName: LN_BOSNIAN; SubName: 'SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_CYRILLIC'),
    (LangID: $203B; LangName: LN_SAMI; SubName: 'SUBLANG_SAMI_SKOLT_FINLAND'),
    (LangID: $2401; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_YEMEN'),
    (LangID: $2409; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_CARIBBEAN'),
    (LangID: $240A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_COLOMBIA'),
    (LangID: $241A; LangName: LN_SERBIAN; SubName: 'SUBLANG_SERBIAN_SERBIA_LATIN'),
    (LangID: $243B; LangName: LN_SAMI; SubName: 'SUBLANG_SAMI_INARI_FINLAND'),
    (LangID: $2801; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_SYRIA'),
    (LangID: $2809; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_BELIZE'),
    (LangID: $280A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_PERU'),
    (LangID: $281A; LangName: LN_SERBIAN; SubName: 'SUBLANG_SERBIAN_SERBIA_CYRILLIC'),
    (LangID: $2C01; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_JORDAN'),
    (LangID: $2C09; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_TRINIDAD'),
    (LangID: $2C0A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_ARGENTINA'),
    (LangID: $2C1A; LangName: LN_SERBIAN; SubName: 'SUBLANG_SERBIAN_MONTENEGRO_LATIN'),
    (LangID: $3001; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_LEBANON'),
    (LangID: $3009; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_ZIMBABWE'),
    (LangID: $300A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_ECUADOR'),
    (LangID: $301A; LangName: LN_SERBIAN; SubName: 'SUBLANG_SERBIAN_MONTENEGRO_CYRILLIC'),
    (LangID: $3401; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_KUWAIT'),
    (LangID: $3409; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_PHILIPPINES'),
    (LangID: $340A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_CHILE'),
    (LangID: $3801; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_UAE'),
    (LangID: $380A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_URUGUAY'),
    (LangID: $3C01; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_BAHRAIN'),
    (LangID: $3C0A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_PARAGUAY'),
    (LangID: $4001; LangName: LN_ARABIC; SubName: 'SUBLANG_ARABIC_QATAR'),
    (LangID: $4009; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_INDIA'),
    (LangID: $400A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_BOLIVIA'),
    (LangID: $4409; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_MALAYSIA'),
    (LangID: $440A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_EL_SALVADOR'),
    (LangID: $4809; LangName: LN_ENGLISH; SubName: 'SUBLANG_ENGLISH_SINGAPORE'),
    (LangID: $480A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_HONDURAS'),
    (LangID: $4C0A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_NICARAGUA'),
    (LangID: $500A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_PUERTO_RICO'),
    (LangID: $540A; LangName: LN_SPANISH; SubName: 'SUBLANG_SPANISH_US')
  );

function IsValidRes(ARes: TResource; AType: MakeIntResource): Boolean;
begin
  Result := False;
  if ARes = nil then Exit;
  if ARes.Data = nil then Exit;
  if GetResType(ARes).Id <> Word(AType) then Exit;
  Result := True;
end;

function GetBitmapStreamFromDib(ARes: TResource): TMemoryStream;
const
  BI_ALPHABITFIELDS = 4;
var
  BitmapFileHeader: TBitmapFileHeader;
  BitmapInfoHeader: TBitmapInfoHeader;
  PalleteSize: DWORD;
begin
  Result := TMemoryStream.Create;
  if not IsValidRes(ARes, RT_BITMAP) then Exit;
  ARes.Data.Position := 0;
  ARes.Data.ReadBuffer(BitmapInfoHeader, SizeOf(BitmapInfoHeader));
  if BitmapInfoHeader.biClrUsed > 0 then
    PalleteSize := BitmapInfoHeader.biClrUsed shl 2
  else
  begin
    case BitmapInfoHeader.biCompression of
      BI_BITFIELDS: PalleteSize := 12;
      BI_ALPHABITFIELDS: PalleteSize := 16;
      BI_RGB, BI_RLE8, BI_RLE4:
      begin
        case BitmapInfoHeader.biBitCount of
          1: PalleteSize := 8;
          4: PalleteSize := 64;
          8: PalleteSize := 1024;
        else
          PalleteSize := 0;
        end;
      end;
    else
      PalleteSize := 0;
    end;
  end;

  BitmapFileHeader := Default(TBitmapFileHeader);
  BitmapFileHeader.bfType := $4D42;
  BitmapFileHeader.bfSize := SizeOf(TBitmapFileHeader) + ARes.Data.Size;
  BitmapFileHeader.bfOffBits := SizeOf(TBitmapFileHeader) +
    BitmapInfoHeader.biSize + PalleteSize;

  Result.WriteBuffer(BitmapFileHeader, SizeOf(BitmapFileHeader));
  Result.CopyFrom(ARes.Data, 0);
  Result.Position := 0;
end;

function MakeBitmapInfoHeaderFromPNG(AStream: TStream): TBitmapInfoHeader;

  function SwapEndian32(Value: Cardinal): Cardinal;
  begin
    Result := ((Value and $FF) shl 24) or ((Value and $FF00) shl 8) or
      ((Value and $FF0000) shr 8) or ((Value and $FF000000) shr 24);
  end;

var
  ChunkHdr: TPNGChunkHeader;
  IHDR: TPNGIHDRData;
  Channels: Byte;
begin
  Result := Default(TBitmapInfoHeader);
  AStream.Position := SizeOf(PNG_SIGNATURE);
  AStream.ReadBuffer(ChunkHdr, SizeOf(ChunkHdr));
  if string(ChunkHdr.ChunkType) <> 'IHDR' then
    raise Exception.Create('Invalid PNG Image');
  AStream.ReadBuffer(IHDR, SizeOf(IHDR));

  case IHDR.ColorType of
    PNG_CT_GRAYSCALE: Channels := 1;
    PNG_CT_RGB: Channels := 3;
    PNG_CT_INDEXED: Channels := 1;
    PNG_CT_GRAYSCALE_ALPHA: Channels := 2;
    PNG_CT_RGBA: Channels := 4;
  else
    raise Exception.CreateFmt('Invalid PNG Image. Unknown ColorType (%d)', [IHDR.ColorType]);
  end;

  Result.biSize := SizeOf(TBitmapInfoHeader);
  Result.biWidth := SwapEndian32(IHDR.Width);
  Result.biHeight := SwapEndian32(IHDR.Height) shl 1;
  Result.biPlanes := 1;
  Result.biBitCount := Channels * IHDR.BitDepth;
  if Result.biBitCount = 32 then
    Result.biCompression := BI_BITFIELDS
  else
    Result.biCompression := BI_RGB;
end;

function GetIconFileDirEntry(AResType: Word; AStream: TStream): TIconFileDirEntry;
var
  HotspotX, HotspotY: Word;
  BitmapInfoHeader: TBitmapInfoHeader;
  HotspotSize: Integer;
begin
  Result := Default(TIconFileDirEntry);
  AStream.Position := 0;
  HotspotSize := 0;
  if AResType = RC3_CURSOR then
  begin
    AStream.ReadBuffer(HotspotX, 2);
    AStream.ReadBuffer(HotspotY, 2);
    HotspotSize := 4;
  end;
  AStream.ReadBuffer(BitmapInfoHeader, SizeOf(BitmapInfoHeader));

  case BitmapInfoHeader.biSize of
    SizeOf(TBitmapInfoHeader), SizeOf(TBitmapV4Header), SizeOf(TBitmapV5Header):
      AStream.Position := HotspotSize;
  else
    if CompareMem(@BitmapInfoHeader, @PNG_SIGNATURE, SizeOf(PNG_SIGNATURE)) then
    begin
      BitmapInfoHeader := MakeBitmapInfoHeaderFromPNG(AStream);
      AStream.Position := HotspotSize;
    end
    else
      raise Exception.Create('Invalid ' +
        IfThen(AResType = RC3_CURSOR, 'Cursor', 'Icon') + ' data stream.');
  end;

  Result.Width := Byte(BitmapInfoHeader.biWidth);
  if (BitmapInfoHeader.biHeight = BitmapInfoHeader.biWidth) or
    (BitmapInfoHeader.biHeight = BitmapInfoHeader.biWidth shl 1) then
    Result.Height := Byte(BitmapInfoHeader.biWidth)
  else
    Result.Height := Byte(BitmapInfoHeader.biHeight shr 1);
  Result.BytesInRes := AStream.Size - HotspotSize;
  Result.ImageOffset := SizeOf(TCursorOrIcon) + SizeOf(Result);

  case AResType of
    RC3_ICON:
    begin
      Result.Planes := BitmapInfoHeader.biPlanes;
      Result.BitCount := BitmapInfoHeader.biBitCount;
    end;
    RC3_CURSOR:
    begin
      Result.Planes := HotspotX;
      Result.BitCount := HotspotY;
    end;
  end;
end;

function GetCursorIconStreamFromDib(ARes: TResource; AResType: Word): TMemoryStream;
var
  Hdr: TCursorOrIcon;
  NeedResID: ULONG;
  DirEntry: TIconFileDirEntry;
begin
  Result := TMemoryStream.Create;
  if ARes = nil then Exit;
  case AResType of
    RC3_ICON: NeedResID := ULONG(RT_ICON);
    RC3_CURSOR: NeedResID := ULONG(RT_CURSOR);
  else
    Exit;
  end;
  if GetResType(ARes).Id <> NeedResID then Exit;
  if ARes.Data = nil then Exit;

  Hdr := Default(TCursorOrIcon);
  Hdr.wType := AResType;
  Hdr.Count := 1;

  DirEntry := GetIconFileDirEntry(AResType, ARes.Data);

  Result.WriteBuffer(Hdr, SizeOf(Hdr));
  Result.WriteBuffer(DirEntry, SizeOf(DirEntry));
  Result.CopyFrom(ARes.Data, DirEntry.BytesInRes);
  Result.Position := 0;
end;

function GetCursorGroupStream(ARes: TResource; out IdList: TIdList): TMemoryStream;
var
  Hdr: TCursorOrIcon;
  Entry: TGrpCursorEntry;
  DirEntry: TIconFileDirEntry;
  Root, CursorRes: TResource;
  I, DataOffset: Integer;
  RawData: TMemoryStream;
begin
  Result := TMemoryStream.Create;
  if not IsValidRes(ARes, RT_GROUP_CURSOR) then Exit;
  Root := GetResRoot(ARes);
  if Root = nil then Exit;
  Root := FindRes(Root, Word(RT_CURSOR), '');
  ARes.Data.Position := 0;
  ARes.Data.ReadBuffer(Hdr, SizeOf(Hdr));
  if Hdr.Count = 0 then Exit;
  Result.WriteBuffer(Hdr, SizeOf(Hdr));
  DataOffset := SizeOf(Hdr) + Hdr.Count * SizeOf(DirEntry);
  SetLength(IdList, Hdr.Count);
  for I := 0 to Hdr.Count - 1 do
  begin
    ARes.Data.ReadBuffer(Entry, SizeOf(Entry));
    IdList[I] := Entry.Id;
    CursorRes := FindRes(Root, IdList[I], '');
    RawData := CursorRes.Childs[0].Data;
    DirEntry := GetIconFileDirEntry(RC3_CURSOR, RawData);
    DirEntry.ImageOffset := DataOffset;
    Inc(DataOffset, DirEntry.BytesInRes);
    Result.WriteBuffer(DirEntry, SizeOf(DirEntry));
  end;
  for I := 0 to Hdr.Count - 1 do
  begin
    CursorRes := FindRes(Root, IdList[I], '');
    RawData := CursorRes.Childs[0].Data;
    RawData.Position := 4;
    Result.CopyFrom(RawData, RawData.Size - 4);
  end;
end;

function GetIconGroupStream(ARes: TResource; out IdList: TIdList): TMemoryStream;
var
  Hdr: TCursorOrIcon;
  Entry: TGrpIconEntry;
  DirEntry: TIconFileDirEntry;
  Root, CursorRes: TResource;
  I, DataOffset: Integer;
  RawData: TMemoryStream;
begin
  Result := TMemoryStream.Create;
  if not IsValidRes(ARes, RT_GROUP_ICON) then Exit;
  Root := GetResRoot(ARes);
  if Root = nil then Exit;
  Root := FindRes(Root, Word(RT_ICON), '');
  ARes.Data.Position := 0;
  ARes.Data.ReadBuffer(Hdr, SizeOf(Hdr));
  if Hdr.Count = 0 then Exit;
  Result.WriteBuffer(Hdr, SizeOf(Hdr));
  DataOffset := SizeOf(Hdr) + Hdr.Count * SizeOf(DirEntry);
  SetLength(IdList, Hdr.Count);
  for I := 0 to Hdr.Count - 1 do
  begin
    ARes.Data.ReadBuffer(Entry, SizeOf(Entry));
    IdList[I] := Entry.Id;
    CursorRes := FindRes(Root, IdList[I], '');
    RawData := CursorRes.Childs[0].Data;
    DirEntry := GetIconFileDirEntry(RC3_ICON, RawData);
    DirEntry.Planes := Entry.Planes;
    DirEntry.BitCount := Entry.BitCount;
    DirEntry.ImageOffset := DataOffset;
    Inc(DataOffset, DirEntry.BytesInRes);
    Result.WriteBuffer(DirEntry, SizeOf(DirEntry));
  end;
  for I := 0 to Hdr.Count - 1 do
  begin
    CursorRes := FindRes(Root, IdList[I], '');
    RawData := CursorRes.Childs[0].Data;
    Result.CopyFrom(RawData, 0);
  end;
end;

procedure AlignRes(ARes: TResource);
begin
  ARes.Data.Position := (ARes.Data.Position + 3) and not 3;
end;

function StringEscape(const Value: string): string;
begin
  Result := StringReplace(Trim(Value), '\',  '\\', [rfReplaceAll]);
  Result := StringReplace(Result, '"',  '\"', [rfReplaceAll]);
  Result := StringReplace(Result, #$D, '\r', [rfReplaceAll]);
  Result := StringReplace(Result, #$A, '\n', [rfReplaceAll]);
end;

function VersionToRC(ARes: TResource): TStringList;
var
  VerStream: TResVersionStream;
  StringFileInfo: TStringFileInfo;
  StringKeyValue: TStringKeyValue;
  Translation: TTranslation;
  TranslationItem: TTranslationItem;
  TranslationItemString: string;
begin
  Result := TStringList.Create;
  if not IsValidRes(ARes, RT_VERSION) then Exit;
  VerStream := TResVersionStream.Create;
  try
    VerStream.Load(ARes.Data);
    Result.Add(Format('%s VERSIONINFO', [ARes.Owner.DisplayName]));
    Result.Add(Format('FILEVERSION %d,%d,%d,%d', [
      VerStream.FixedFileInfo.FileVersionMS.LowPart,
      VerStream.FixedFileInfo.FileVersionMS.HiPart,      
      VerStream.FixedFileInfo.FileVersionLS.LowPart,      
      VerStream.FixedFileInfo.FileVersionLS.HiPart
    ]));
    Result.Add(Format('PRODUCTVERSION %d,%d,%d,%d', [
      VerStream.FixedFileInfo.ProductVersionMS.LowPart,
      VerStream.FixedFileInfo.ProductVersionMS.HiPart,      
      VerStream.FixedFileInfo.ProductVersionLS.LowPart,      
      VerStream.FixedFileInfo.ProductVersionLS.HiPart
    ]));   
    Result.Add(Format('FILEOS 0x%.1X', [VerStream.FixedFileInfo.FileOS])); 
    Result.Add(Format('FILETYPE 0x%.1X', [VerStream.FixedFileInfo.FileType]));
    Result.Add('BEGIN');
    Result.Add(#9'BLOCK "StringFileInfo"');
    Result.Add(#9'BEGIN');
    for StringFileInfo in VerStream.StringFileInfo do
    begin
      Result.Add(Format(#9#9'BLOCK "%s"', [StringFileInfo.Name]));
      Result.Add(#9#9'BEGIN');
      for StringKeyValue in StringFileInfo.Items do
        Result.Add(Format(#9#9#9'VALUE "%s", "%s"', [StringKeyValue.Key, StringKeyValue.Value]));
      Result.Add(#9#9'END');
    end;
    Result.Add(#9'END');
    Result.Add(#9'BLOCK "VarFileInfo"');
    Result.Add(#9'BEGIN');
    for Translation in VerStream.VarFileInfo do
    begin
      TranslationItemString := Format(#9#9'VALUE "%s"', [Translation.Name]);
      for TranslationItem in Translation.Items do
        TranslationItemString := Format('%s, 0x%.1X, %d', 
          [TranslationItemString, TranslationItem.LangID, TranslationItem.CodePage]);
      Result.Add(TranslationItemString);
    end;
    Result.Add(#9'END');
    Result.Add('END');
  finally
    VerStream.Free;
  end;
end;

function LookupLangID(ALangID: LANGID; out ALangName, ASubName: string): Boolean;
var
  I: Integer;
  Primary: Word;
begin
  for I := 0 to Length(LangIDTable) - 1 do
    if LangIDTable[I].LangID = ALangID then
    begin
      ALangName := LangIDTable[I].LangName;
      ASubName  := LangIDTable[I].SubName;
      Exit(True);
    end;

  if SUBLANGID(ALangID) = SUBLANG_NEUTRAL then
  begin
    Primary := PRIMARYLANGID(ALangID);
    for I := 0 to Length(LangIDTable) - 1 do
      if PRIMARYLANGID(LangIDTable[I].LangID) = Primary then
      begin
        ALangName := LangIDTable[I].LangName;
        ASubName  := 'SUBLANG_NEUTRAL';
        Exit(True);
      end;
  end;

  ALangName := '0x' + IntToHex(PRIMARYLANGID(ALangID), 3);
  ASubName  := IntToStr(SUBLANGID(ALangID));
  Result := False;
end;

procedure AddLangInfo(ARes: TResource; AList: TStringList);
var
  ALangName, ASubName: string;
begin
  LookupLangID(ARes.Id, ALangName, ASubName);
  AList.Add(Format('LANGUAGE %s, %s', [ALangName, ASubName]));
end;

function StringsToRC(ARes: TResource): TStringList;
var
  Str: string;
  BaseID, I, Len: Integer;
begin
  Result := TStringList.Create;
  if not IsValidRes(ARes, RT_STRING) then Exit;
  Result.Add('STRINGTABLE');
  AddLangInfo(ARes, Result);
  Result.Add('BEGIN');
  BaseID := (ARes.Owner.Id - 1) shl 4;
  Len := 0;
  ARes.Data.Position := 0;
  for I := 0 to 15 do
  begin
    ARes.Data.ReadBuffer(Len, 2);
    if Len = 0 then Continue;
    SetLength(Str, Len);
    ARes.Data.ReadBuffer(Str[1], Len shl 1);
    Result.Add(Format(#9'%d, "%s"', [BaseID + I, Str]));
  end;
  Result.Add('END');
end;

function MessageTableToString(ARes: TResource): TStringList;
var
  Str: string;
  StrBuff: array of Byte;
  Data: TMessageResourceData;
  Block: TMessageResourceBlock;
  BlockIdx: DWORD;
  Entry: PMessageResourceEntry;
  I: Integer;
begin
  // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-message_resource_data
  // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-message_resource_block
  // https://learn.microsoft.com/en-us/windows/win32/api/Winnt/ns-winnt-message_resource_entry
  Result := TStringList.Create;
  if not IsValidRes(ARes, RT_MESSAGETABLE) then Exit;
  Result.Add('// This is a text-based representation of the MessageTable resource.');
  Result.Add('// It cannot be compiled by calling brcc32 or rc.exe!!!');
  Result.Add('');
  AddLangInfo(ARes, Result);
  Result.Add(ARes.Owner.DisplayName + ' MESSAGETABLE');
  Result.Add('BEGIN');
  ARes.Data.Position := 0;
  ARes.Data.ReadBuffer(Data, SizeOf(Data));
  for I := 0 to Integer(Data.NumberOfBlocks) - 1 do
  begin
    ARes.Data.ReadBuffer(Block, SizeOf(Block));
    Entry := PMessageResourceEntry(PByte(ARes.Data.Memory) + Block.OffsetToEntries);
    for BlockIdx := Block.LowId to Block.HighId do
    begin
      StrBuff := nil;
      SetLength(StrBuff, Entry.Length);
      Move(Entry.Text, StrBuff[0], Entry.Length - 4);
      if Entry.Flags and MESSAGE_RESOURCE_UNICODE = 0 then
        Str := string(PAnsiChar(@StrBuff[0]))
      else
        Str := PChar(@StrBuff[0]);
      Str := StringEscape(Str);
      Result.Add(Format(#9'0x%.8X, "%s"', [BlockIdx, Str]));
      Entry := PMessageResourceEntry(PByte(Entry) + Entry.Length);
    end;
  end;
  Result.Add('END');
end;

function AcceleratorsToRC(ARes: TResource): TStringList;
var
  Entry: TAccelEntry;
  Line, LineEnd: string;
begin
  // https://learn.microsoft.com/en-us/windows/win32/menurc/acceltableentry
  Result := TStringList.Create;
  if not IsValidRes(ARes, RT_ACCELERATOR) then Exit;
  AddLangInfo(ARes, Result);
  Result.Add(ARes.Owner.DisplayName + ' ACCELERATORS');
  Result.Add('BEGIN');
  ARes.Data.Position := 0;
  ARes.Data.ReadBuffer(Entry, SizeOf(Entry));
  while Entry.fFlags <> FEND do
  begin
    if Entry.fFlags and FVIRTKEY <> 0 then
    begin
      LineEnd := ', VIRTKEY';
      case Entry.wAnsi of
        $08: Line := 'VK_BACK';
        $09: Line := 'VK_TAB';
        $0C: Line := 'VK_CLEAR';
        $0D: Line := 'VK_RETURN';
        $12: Line := 'VK_MENU';
        $13: Line := 'VK_PAUSE';
        $14: Line := 'VK_CAPITAL';
        $15: Line := 'VK_KANA';
        $17: Line := 'VK_JUNJA';
        $18: Line := 'VK_FINAL';
        $19: Line := 'VK_HANJA';
        $1B: Line := 'VK_ESCAPE';
        $1C: Line := 'VK_CONVERT';
        $1D: Line := 'VK_NONCONVERT';
        $1E: Line := 'VK_ACCEPT';
        $1F: Line := 'VK_MODECHANGE';
        $20: Line := 'VK_SPACE';
        $21: Line := 'VK_PRIOR';
        $22: Line := 'VK_NEXT';
        $23: Line := 'VK_END';
        $24: Line := 'VK_HOME';
        $25: Line := 'VK_LEFT';
        $26: Line := 'VK_UP';
        $27: Line := 'VK_RIGHT';
        $28: Line := 'VK_DOWN';
        $29: Line := 'VK_SELECT';
        $2A: Line := 'VK_PRINT';
        $2B: Line := 'VK_EXECUTE';
        $2C: Line := 'VK_SNAPSHOT';
        $2D: Line := 'VK_INSERT';
        $2E: Line := 'VK_DELETE';
        $2F: Line := 'VK_HELP';
        $5B: Line := 'VK_LWIN';
        $5C: Line := 'VK_RWIN';
        $5D: Line := 'VK_APPS';
        $5F: Line := 'VK_SLEEP';
        $60..$69: Line := Format('VK_NUMPAD%d', [Entry.wAnsi - $60]);
        $6A: Line := 'VK_MULTIPLY';  // * на цифровой клавиатуре
        $6B: Line := 'VK_ADD';       // + на цифровой клавиатуре
        $6C: Line := 'VK_SEPARATOR';
        $6D: Line := 'VK_SUBTRACT';  // - на цифровой клавиатуре
        $6E: Line := 'VK_DECIMAL';   // . на цифровой клавиатуре
        $6F: Line := 'VK_DIVIDE';    // / на цифровой клавиатуре
        $70..$87: Line := Format('VK_F%d', [Entry.wAnsi - $6F]); // F1-F24
        $90: Line := 'VK_NUMLOCK';
        $91: Line := 'VK_SCROLL';
        $A0: Line := 'VK_LSHIFT';
        $A1: Line := 'VK_RSHIFT';
        $A2: Line := 'VK_LCONTROL';
        $A3: Line := 'VK_RCONTROL';
        $A4: Line := 'VK_LMENU';
        $A5: Line := 'VK_RMENU';
        $A6: Line := 'VK_BROWSER_BACK';
        $A7: Line := 'VK_BROWSER_FORWARD';
        $A8: Line := 'VK_BROWSER_REFRESH';
        $A9: Line := 'VK_BROWSER_STOP';
        $AA: Line := 'VK_BROWSER_SEARCH';
        $AB: Line := 'VK_BROWSER_FAVORITES';
        $AC: Line := 'VK_BROWSER_HOME';
        $AD: Line := 'VK_VOLUME_MUTE';
        $AE: Line := 'VK_VOLUME_DOWN';
        $AF: Line := 'VK_VOLUME_UP';
        $B0: Line := 'VK_MEDIA_NEXT_TRACK';
        $B1: Line := 'VK_MEDIA_PREV_TRACK';
        $B2: Line := 'VK_MEDIA_STOP';
        $B3: Line := 'VK_MEDIA_PLAY_PAUSE';
        $B4: Line := 'VK_LAUNCH_MAIL';
        $B5: Line := 'VK_LAUNCH_MEDIA_SELECT';
        $B6: Line := 'VK_LAUNCH_APP1';
        $B7: Line := 'VK_LAUNCH_APP2';
        $BA: Line := 'VK_OEM_1';       // ; :
        $BB: Line := 'VK_OEM_PLUS';    // = +
        $BC: Line := 'VK_OEM_COMMA';   // , <
        $BD: Line := 'VK_OEM_MINUS';   // - _
        $BE: Line := 'VK_OEM_PERIOD';  // . >
        $BF: Line := 'VK_OEM_2';       // / ?
        $C0: Line := 'VK_OEM_3';       // ` ~
        $DB: Line := 'VK_OEM_4';       // [ {
        $DC: Line := 'VK_OEM_5';       // \ |
        $DD: Line := 'VK_OEM_6';       // ] }
        $DE: Line := 'VK_OEM_7';       // ' "
        $DF: Line := 'VK_OEM_8';
        $E2: Line := 'VK_OEM_102';
        $FE: Line := 'VK_OEM_CLEAR';
      else
        if Entry.wAnsi in [$30..$39, $41..$5A] then
          Line := Format('VK_%s', [Chr(Entry.wAnsi)])
        else
        begin
          Line := Format('%d', [Entry.wAnsi]);
          LineEnd := ', ASCII';
        end;
      end;
    end
    else
    begin
      if Entry.wAnsi in [$30..$39, $41..$5A] then
      begin
        Line := Format('"%s"', [Chr(Entry.wAnsi)]);
        LineEnd := '';
      end
      else
      begin
        Line := Format('%d', [Entry.wAnsi]);
        LineEnd := ', ASCII';
      end;
    end;

    Line := Format('%s, %d', [Line, Entry.wId]);
    if Entry.fFlags and FNOINVERT <> 0 then Line := Line + ', NOINVERT';
    if Entry.fFlags and FSHIFT <> 0 then Line := Line + ', SHIFT';
    if Entry.fFlags and FCONTROL <> 0 then Line := Line + ', CONTROL';
    if Entry.fFlags and FALT <> 0 then Line := Line + ', ALT';
    Result.Add(Format(#9'%s%s', [Line, LineEnd]));

    if ARes.Data.Position = ARes.Data.Size then Break;
    ARes.Data.ReadBuffer(Entry, SizeOf(Entry));
  end;
  Result.Add('END');
end;

function ReadResString(ARes: TResource): string;
var
  W: WideChar;
begin
  Result := '';
  while ARes.Data.Position < ARes.Data.Size - 1 do
  begin
    ARes.Data.ReadBuffer(W, 2);
    if W = #0 then Break;
    Result := Result + W;
  end;
end;

procedure MenuTemplateToRC(ARes: TResource; RCData: TStringList);

  function ExtractFlags(Value: Word): string;
  begin
    Result := '';
    if Value and MF_GRAYED <> 0 then Result := Result + ', GRAYED';
    if Value and MF_DISABLED <> 0 then Result := Result + ', INACTIVE';
    if Value and MF_CHECKED <> 0 then Result := Result + ', CHECKED';
    if Value and MF_MENUBARBREAK <> 0 then Result := Result + ', MENUBARBREAK';
    if Value and MF_MENUBREAK <> 0 then Result := Result + ', MENUBREAK';
  end;

  procedure LoadMenuItems(AIndent: Integer);
  var
    Flags, ItemID: Word;
    Text: string;
  begin
    repeat
      ARes.Data.ReadBuffer(Flags, 2);
      if Flags and MF_POPUP <> 0 then
      begin
        Text := ReadResString(ARes);
        RCData.Add(Format('%sPOPUP "%s"%s', [StringOfChar(#9, AIndent), Text, ExtractFlags(Flags)]));
        RCData.Add(Format('%s{', [StringOfChar(#9, AIndent)]));
        LoadMenuItems(AIndent + 1);
        RCData.Add(Format('%s}', [StringOfChar(#9, AIndent)]));
        Continue;
      end;
      ARes.Data.ReadBuffer(ItemID, 2);
      Text := ReadResString(ARes);
      if (Text = '') and (ItemID  = 0) then
        RCData.Add(Format('%sMENUITEM SEPARATOR', [StringOfChar(#9, AIndent)]))
      else
        RCData.Add(Format('%sMENUITEM "%s", %d%s', [StringOfChar(#9, AIndent), Text, ItemID, ExtractFlags(Flags)]));
    until (Flags and MF_END <> 0) or (ARes.Data.Position >= ARes.Data.Size - 1);
  end;

begin
  // https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-menuitemtemplateheader
  // https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-menuitemtemplate
  // https://learn.microsoft.com/en-us/windows/win32/menurc/menuhelpid
  AddLangInfo(ARes, RCData);
  RCData.Add(ARes.Owner.DisplayName + ' MENU');
  RCData.Add('BEGIN');
  LoadMenuItems(1);
  RCData.Add('END');
end;

procedure MenuExTemplateToRC(ARes: TResource; RCData: TStringList);

  function ExtractFlags(const Item: TMenuExTemplateItem; dwHelpID: DWORD): string;
  var
    sType, sState: string;
  begin
    Result := '';
    if (Item.dwType = 0) and (Item.dwState = 0) and (dwHelpID = 0) then Exit;

    sType := '';
    if Item.dwType and MFT_BITMAP <> 0 then sType := sType + 'MFT_BITMAP ';
    if Item.dwType and MFT_MENUBARBREAK <> 0 then sType := sType + 'MFT_MENUBARBREAK ';
    if Item.dwType and MFT_MENUBREAK <> 0 then sType := sType + 'MFT_MENUBREAK ';
    if Item.dwType and MFT_OWNERDRAW <> 0 then sType := sType + 'MFT_OWNERDRAW ';
    if Item.dwType and MFT_RADIOCHECK <> 0 then sType := sType + 'MFT_RADIOCHECK ';
    if Item.dwType and MFT_RIGHTORDER <> 0 then sType := sType + 'MFT_RIGHTORDER ';
    if Item.dwType and MFT_RIGHTJUSTIFY <> 0 then sType := sType + 'MFT_RIGHTJUSTIFY ';
    if sType = '' then
      sType := 'MFT_STRING'
    else
      sType := StringReplace(Trim(sType), ' ', '|', [rfReplaceAll]);

    sState := '';
    if Item.dwState and MFS_DISABLED <> 0 then sState := sState + 'MFS_DISABLED ';
    if Item.dwState and MFS_CHECKED <> 0 then sState := sState + 'MFS_CHECKED ';
    if Item.dwState and MFS_HILITE <> 0 then sState := sState + 'MFS_HILITE ';
    if Item.dwState and MFS_DEFAULT <> 0 then sState := sState + 'MFS_DEFAULT ';
    if sState = '' then
      sState := 'MFS_ENABLED'
    else
      sState := StringReplace(Trim(sState), ' ', '|', [rfReplaceAll]);

    Result := Format('%s, %s', [sType, sState]);
  end;

  procedure LoadMenuItems(AIndent: Integer);
  const
    MF_POPUP_EX = 1;
  var
    Item: TMenuExTemplateItem;
    FormatStr, Text, Flags: string;
    dwHelpId: DWORD;
  begin
    repeat
      ARes.Data.ReadBuffer(Item, SizeOf(Item));
      Text:= ReadResString(ARes);
      // This member is a null-terminated Unicode string, aligned on a word boundary
      AlignRes(ARes);
      dwHelpId := 0;
      if Item.wFlags and MF_POPUP_EX <> 0 then
      begin
        ARes.Data.ReadBuffer(dwHelpId, SizeOf(dwHelpId));
        Flags := ExtractFlags(Item, dwHelpId);
        FormatStr := StringOfChar(#9, AIndent) + 'POPUP "%s"';
        if (Item.uId > 0) or (Flags <> '') or (dwHelpId <> 0) then
        begin
          FormatStr := FormatStr + ', %d';
          if (Flags <> '') or (dwHelpId <> 0) then
            FormatStr := FormatStr + ', %s';
          if dwHelpId <> 0 then
            FormatStr := FormatStr + ', %d';
        end;
        RCData.Add(Format(FormatStr, [Text, Item.uId, Flags, dwHelpId]));
        RCData.Add(Format('%s{', [StringOfChar(#9, AIndent)]));
        LoadMenuItems(AIndent + 1);
        RCData.Add(Format('%s}', [StringOfChar(#9, AIndent)]));
        Continue;
      end
      else
      begin
        Flags := ExtractFlags(Item, dwHelpId);
        if (Item.uId > 0) or (Flags <> '') then
        begin
          FormatStr := StringOfChar(#9, AIndent) + 'MENUITEM "%s", %d';
          if Flags <> '' then
            FormatStr := FormatStr + ', %s';
          RCData.Add(Format(FormatStr, [Text, Item.uId, Flags]));
        end
        else
          RCData.Add(Format('%sMENUITEM SEPARATOR', [StringOfChar(#9, AIndent)]));
      end;
    until (Item.wFlags and MF_END <> 0) or (ARes.Data.Position > ARes.Data.Size - SizeOf(TMenuExTemplateItem));
  end;

var
  Header: TMenuExTemplateHeader;
begin
  // https://learn.microsoft.com/en-us/windows/win32/menurc/menuex-template-item
  ARes.Data.Position := 0;
  ARes.Data.ReadBuffer(Header, SizeOf(Header));
  AddLangInfo(ARes, RCData);
  RCData.Add(ARes.Owner.DisplayName + ' MENUEX');
  RCData.Add('BEGIN');
  LoadMenuItems(1);
  RCData.Add('END');
end;

function MenuToRC(ARes: TResource): TStringList;
var
  Header: TMenuHeader;
begin
  Result := TStringList.Create;
  if not (IsValidRes(ARes, RT_MENUEX) or IsValidRes(ARes, RT_MENU)) then Exit;
  ARes.Data.Position := 0;
  ARes.Data.ReadBuffer(Header, SizeOf(Header));
  case Header.wVersion of
    0: if Header.cbHeaderSize = 0 then MenuTemplateToRC(ARes, Result);
    1: if Header.cbHeaderSize = 4 then MenuExTemplateToRC(ARes, Result);
  end;
end;

procedure ReadSzOrOrd(ARes: TResource; out AStr: string; out AOrdinal: Integer);
var
  W: Word;
begin
  AOrdinal := -1;
  ARes.Data.ReadBuffer(W, 2);
  case W of
    0: AStr := '';
    $FFFF:
    begin
      AOrdinal := 0;
      ARes.Data.ReadBuffer(AOrdinal, 2);
      AStr := '#' + IntToStr(AOrdinal);
    end;
  else
    AStr := StringEscape(WideChar(W) + ReadResString(ARes));
  end;
end;

procedure DumpSzOrOrd(ARes: TResource; const AName: string; RCData: TStringList);
var
  AStr: string;
  AOrdinal: Integer;
begin
  ReadSzOrOrd(ARes, AStr, AOrdinal);
  if AOrdinal >= 0 then
  begin
    RCData.Add(Format('%s %d', [AName, AOrdinal]));
    Exit;
  end;
  if AStr <> '' then
    RCData.Add(Format('%s "%s"', [AName, AStr]));
end;

procedure DumpControl(const Template: TDlgItemTemplate;
  nID, nClass: Integer; const szClass, szText: string; RCData: TStringList);
const
  DEFAULT_STYLE: array [0..13] of record
    Keyword: string;
    Style: DWORD;
  end = (
    (Keyword: 'DEFPUSHBUTTON';   Style: $50010001),  // WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON
    (Keyword: 'PUSHBUTTON';      Style: $50010000),  // WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON
    (Keyword: 'CHECKBOX';        Style: $50010003),  // WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX
    (Keyword: 'AUTO3STATE';      Style: $50010006),  // WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTO3STATE
    (Keyword: 'RADIOBUTTON';     Style: $50000004),  // WS_CHILD|WS_VISIBLE|BS_RADIOBUTTON
    (Keyword: 'AUTORADIOBUTTON'; Style: $50000009),  // WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON
    (Keyword: 'GROUPBOX';        Style: $50000007),  // WS_CHILD|WS_VISIBLE|BS_GROUPBOX
    (Keyword: 'LTEXT';           Style: $50020000),  // WS_CHILD|WS_VISIBLE|WS_GROUP|SS_LEFT
    (Keyword: 'RTEXT';           Style: $50020001),  // WS_CHILD|WS_VISIBLE|WS_GROUP|SS_RIGHT
    (Keyword: 'CTEXT';           Style: $50020002),  // WS_CHILD|WS_VISIBLE|WS_GROUP|SS_CENTER
    (Keyword: 'ICON';            Style: $50000003),  // WS_CHILD|WS_VISIBLE|SS_ICON
    (Keyword: 'EDITTEXT';        Style: $50810000),  // WS_CHILD|WS_VISIBLE|WS_BORDER|WS_TABSTOP
    (Keyword: 'LISTBOX';         Style: $50A00001),  // WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_BORDER|LBS_NOTIFY
    (Keyword: 'COMBOBOX';        Style: $50000000)   // WS_CHILD|WS_VISIBLE
  );
var
  DefClassName, ClassName, StyleStr, ExStyleStr: string;
  DefStyle: DWORD;
  I: Integer;
begin
  DefClassName := '';
  DefStyle := 0;
  if nClass >= 0 then
  begin
    case nClass of
      $80:
      begin
        case Template.style and $F of
          BS_PUSHBUTTON: DefClassName := 'PUSHBUTTON';
          BS_DEFPUSHBUTTON: DefClassName := 'DEFPUSHBUTTON';
          BS_CHECKBOX, BS_3STATE: DefClassName := 'CHECKBOX';
          BS_AUTOCHECKBOX, BS_AUTO3STATE: DefClassName := 'AUTO3STATE';
          BS_RADIOBUTTON: DefClassName := 'RADIOBUTTON';
          BS_GROUPBOX, $D: DefClassName := 'GROUPBOX';
          BS_AUTORADIOBUTTON: DefClassName := 'AUTORADIOBUTTON';
        end;
      end;
      $81: DefClassName := 'EDITTEXT';
      $82:
      begin
        case Template.style and $F of
          $00: DefClassName := 'LTEXT';
          $01: DefClassName := 'RTEXT';
          $02: DefClassName := 'CTEXT';
          $03: DefClassName := 'ICON';
          $04: DefClassName := 'BLACKRECT';
          $05: DefClassName := 'GRAYRECT';
          $06: DefClassName := 'WHITERECT';
          $07: DefClassName := 'BLACKFRAME';
          $08: DefClassName := 'GRAYFRAME';
          $09: DefClassName := 'WHITEFRAME';
          $0D: DefClassName := 'GROUPBOX';
          $0E: DefClassName := 'USERITEM';
          $0F: DefClassName := 'OWNERDRAW';
        end;
      end;
      $83: DefClassName := 'LISTBOX';
      $84: DefClassName := 'SCROLLBAR';
      $85: DefClassName := 'COMBOBOX';
    end;
    if DefClassName <> '' then
    begin
      for I := Low(DEFAULT_STYLE) to High(DEFAULT_STYLE) do
        if DEFAULT_STYLE[I].Keyword = DefClassName then
        begin
          DefStyle := DEFAULT_STYLE[I].Style;
          Break;
        end;
    end;
  end;
  if (DefClassName <> '') and (Template.style = DefStyle) then
    RCData.Add(Format(#9'%s "%s", %d, %d, %d, %d, %d', [DefClassName, szText, nID,
      Template.x, Template.y, Template.cx, Template.cy]))
  else
  begin
    // https://learn.microsoft.com/en-us/windows/win32/menurc/control-control
    case nClass of
      $80: ClassName := 'BUTTON';
      $81: ClassName := 'EDIT';
      $82: ClassName := 'STATIC';
      $83: ClassName := 'LISTBOX';
      $84: ClassName := 'SCROLLBAR';
      $85: ClassName := 'COMBOBOX';
    else
      ClassName := Format('%s', [szClass]);
    end;
    if nClass in [$80..$85] then
    begin
      StyleStr := FillStyleLists(ClassName, Template.style, 0);
      if Template.dwExtendedStyle <> 0 then
        ExStyleStr := ', ' + FillStyleLists(ClassName, 0, Template.dwExtendedStyle);
    end
    else
    begin
      StyleStr := FillStyleLists(szClass, Template.style, 0);
      if Template.dwExtendedStyle <> 0 then
        ExStyleStr := ', ' + FillStyleLists(szClass, 0, Template.dwExtendedStyle);
    end;
    RCData.Add(Format(#9'CONTROL "%s", %d, "%s", %s, %d, %d, %d, %d%s', [szText, nID,
      ClassName, StyleStr, Template.x, Template.y, Template.cx, Template.cy,
      ExStyleStr]));
  end;
end;

procedure DialogTemplateToRC(ARes: TResource; const AHeader: TDlgTemplate; RCData: TStringList);

  procedure LoadControl(ARes: TResource; RCData: TStringList);
  var
    Template: TDlgItemTemplate;
    szClass, szText: string;
    nClass, nText: Integer;
    cbCreationData: Byte;
  begin
    AlignRes(ARes);
    ARes.Data.ReadBuffer(Template, SizeOf(Template));
    ReadSzOrOrd(ARes, szClass, nClass);
    ReadSzOrOrd(ARes, szText, nText);
    ARes.Data.ReadBuffer(cbCreationData, 1);
    if cbCreationData > 0 then
      ARes.Data.Seek(cbCreationData, soCurrent);
    DumpControl(Template, Template.id, nClass, szClass, szText, RCData);
  end;

var
  AStr: string;
  PointSize: Word;
  I: Integer;
begin
  RCData.Add(Format('%s DIALOG %d, %d, %d, %d', [ARes.Owner.DisplayName,
    AHeader.x, AHeader.y, AHeader.cx, AHeader.cy]));
  RCData.Add(Format('STYLE %s', [FillStyleLists(TYPE_DIALOG, AHeader.style, 0)]));
  if AHeader.dwExtendedStyle <> 0 then
    RCData.Add(Format('EXSTYLE %s', [FillStyleLists(TYPE_DIALOG, 0, AHeader.dwExtendedStyle)]));
  DumpSzOrOrd(ARes, 'MENU', RCData);
  DumpSzOrOrd(ARes, 'CLASS', RCData);
  AStr := ReadResString(ARes);
  if AStr <> '' then
    RCData.Add(Format('CAPTION "%s"', [AStr]));
  if AHeader.style and DS_SETFONT <> 0 then
  begin
    ARes.Data.ReadBuffer(PointSize, 2);
    AStr := ReadResString(ARes);
    RCData.Add(Format('FONT %d, "%s"', [PointSize, AStr]));
  end;
  RCData.Add('BEGIN');
  for I := 0 to Integer(AHeader.cdit) - 1 do
    LoadControl(ARes, RCData);
  RCData.Add('END');
end;

procedure DialogTemplateExToRC(ARes: TResource; RCData: TStringList);

  procedure LoadControl(ARes: TResource; RCData: TStringList);
  var
    Template: TDlgItemTemplate;
    TemplateEx: TDlgItemTemplateEx;
    szClass, szText: string;
    nClass, nText: Integer;
    cbCreationData: Word;
  begin
    AlignRes(ARes);
    ARes.Data.ReadBuffer(TemplateEx, SizeOf(TemplateEx));
    ReadSzOrOrd(ARes, szClass, nClass);
    ReadSzOrOrd(ARes, szText, nText);
    ARes.Data.ReadBuffer(cbCreationData, 2);
    if cbCreationData > 0 then
      ARes.Data.Seek(cbCreationData, soCurrent);
    Template.style := TemplateEx.style;
    Template.dwExtendedStyle := TemplateEx.exStyle;
    Template.x := TemplateEx.x;
    Template.y := TemplateEx.y;
    Template.cx := TemplateEx.cx;
    Template.cy := TemplateEx.cy;
    DumpControl(Template, Integer(TemplateEx.id), nClass, szClass, szText, RCData);
  end;

var
  AHeader: TDlgTemplateEx;
  AStr: string;
  AFont: TDialogFontInfo;
  I: Integer;
begin
  // https://learn.microsoft.com/en-us/windows/win32/menurc/dialogex-resource
  // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-logfonta
  ARes.Data.Position := 0;
  ARes.Data.ReadBuffer(AHeader, SizeOf(AHeader));
  RCData.Add(Format('%s DIALOGEX %d, %d, %d, %d', [ARes.Owner.DisplayName,
    AHeader.x, AHeader.y, AHeader.cx, AHeader.cy]));
  RCData.Add(Format('STYLE %s', [FillStyleLists(TYPE_DIALOG, AHeader.style, 0)]));
  if AHeader.exStyle <> 0 then
    RCData.Add(Format('EXSTYLE %s', [FillStyleLists(TYPE_DIALOG, 0, AHeader.exStyle)]));
  DumpSzOrOrd(ARes, 'MENU', RCData);
  DumpSzOrOrd(ARes, 'CLASS', RCData);
  AStr := ReadResString(ARes);
  if AStr <> '' then
    RCData.Add(Format('CAPTION "%s"', [AStr]));
  if AHeader.helpID <> 0 then
    RCData.Add(Format('HELPID %d', [AHeader.helpID]));
  if AHeader.style and DS_SETFONT <> 0 then
  begin
    ARes.Data.ReadBuffer(AFont, SizeOf(AFont));
    AStr := ReadResString(ARes);
    RCData.Add(Format('FONT %d, "%s", %d, %d, %d',
      [AFont.wPointSize, AStr, AFont.wWeight, AFont.bItalic, AFont.bCharset]));
  end;
  RCData.Add('BEGIN');
  for I := 0 to Integer(AHeader.cDlgItems) - 1 do
    LoadControl(ARes, RCData);
  RCData.Add('END');
end;

function DialogToRC(ARes: TResource): TStringList;
var
  Header: TDlgTemplate;
begin
  Result := TStringList.Create;
  if not (IsValidRes(ARes, RT_DIALOGEX) or IsValidRes(ARes, RT_DIALOG)) then Exit;
  ARes.Data.Position := 0;
  ARes.Data.ReadBuffer(Header, SizeOf(Header));
  if Header.style = $FFFF0001 then
    DialogTemplateExToRC(ARes, Result)
  else
    DialogTemplateToRC(ARes, Header, Result);
end;

function DVCLALToString(ARes: TResource): TStringList;
var
  Sign: Int64;
  I: Integer;
begin
  Result := TStringList.Create;
  Sign := GDAL(ARes.Data.Memory);
  for I := 0 to 2 do
    if DLicHashAL1s[I] = Sign then
    begin
      Result.Add('- Licence valid');
      case I of
        0: Result.Add('- Personal/Standard');
        1: Result.Add('- Professional');
        2: Result.Add('- Enterprise');
      end;
      Exit;
    end;
  Result.Add('- Licence invalid');
end;

function PackageInfoToString(ARes: TResource): TStringList;
const
  LineSeparator = '=============================================================';

  function AlignString(const Value: string): string;
  begin
    Result := Value + StringOfChar(' ', 40 - Length(Value));
  end;

var
  M: TMemoryStream;
  Line, AName: string;
  I, RequiresCount, ContainsCount: Integer;
  Flags, Hash: Byte;

  procedure CheckFlag(Flag: Byte; const Description: string);
  begin
    if Flags and Flag <> Flag then Exit;
    Flags := Flags and not Flag;
    if Line = '' then
      Line := ' ' + Description
    else
      Line := Line + ', ' + Description;
  end;

begin
  Result := TStringList.Create;
  Result.Add('PACKAGE INFO:');
  Result.Add('');
  M := ARes.Data;
  case PCardinal(M.Memory)^ and pfModuleTypeMask of
    pfExeModule: Line := 'Type: ExeModule';
    pfPackageModule: Line := 'Type: PackageModule';
    pfLibraryModule: Line := 'Type: LibraryModule';
  else
    Line := 'Type: Undefined';
  end;
  Result.Add(Line);
  case PCardinal(M.Memory)^ and pfProducerMask of
    pfV3Produced: Line := 'Producer: V3';
    pfBCB4Produced: Line := 'Producer: BCB4';
    pfDelphi4Produced: Line := 'Producer: Delphi4';
  else
    Line := 'Producer: Undefined';
  end;
  Result.Add(Line);
  case PCardinal(M.Memory)^ and pfConsumerMask of
    pfConsumerCompat: Line := 'Consumer: Compat';
    pfConsumerDelphi: Line := 'Consumer: Delphi';
    pfConsumerBCB: Line := 'Consumer: BCB';
  else
    Line := 'Consumer: Undefined';
  end;
  Result.Add(Line);
  Line := 'Flags: ' +
    IfThen(PCardinal(M.Memory)^ and pfNeverBuild = 0, 'always build, ', 'never-build, ');
  if PCardinal(M.Memory)^ and pfDesignOnly = pfDesignOnly then
    Line := Line + 'design-time only, ';
  if PCardinal(M.Memory)^ and pfRunOnly = pfRunOnly then
    Line := Line + 'run-time only, ';
  Line := Line +
    IfThen(PCardinal(M.Memory)^ and pfIgnoreDupUnits = 0,
      'perform normal dup unit check', 'do not check for dup units');
  Result.Add(Line);
  Result.Add('');
  M.Position := 4;
  M.ReadBuffer(RequiresCount, 4);
  Result.Add('Requires: ' + IntToStr(RequiresCount));
  if RequiresCount > 0 then
  begin
    Result.Add('Hash:   UnitName:');
    Result.Add(LineSeparator);
    for I := 0 to RequiresCount - 1 do
    begin
      M.ReadBuffer(Hash, 1);
      AName := string(AnsiString(PAnsiChar(M.Memory) + M.Position));
      Line := Format('0x%.2X    %s', [Hash, AName]);
      M.Seek(Length(AName) + 1, soCurrent);
      Result.Add(Line);
    end;
    Result.Add(LineSeparator);
  end;
  M.ReadBuffer(ContainsCount, 4);
  Result.Add('');
  Result.Add('Contains: ' + IntToStr(ContainsCount));
  if ContainsCount > 0 then
  begin
    Result.Add('Hash:   UnitName:                                Flags:');
    Result.Add(LineSeparator);
    for I := 0 to ContainsCount - 1 do
    begin
      M.ReadBuffer(Flags, 1);
      M.ReadBuffer(Hash, 1);
      AName := string(AnsiString(PAnsiChar(M.Memory) + M.Position));
      Line := '';
      CheckFlag(ufMainUnit, 'main unit');
      CheckFlag(ufWeakPackageUnit, '$WEAKPACKAGEUNIT unit (dpk source)');
      CheckFlag(ufPackageUnit, 'package unit (dpk source)');
      CheckFlag(ufWeakUnit, '$WEAKPACKAGEUNIT unit');
      CheckFlag(ufOrgWeakUnit, 'original containment of $WEAKPACKAGEUNIT');
      CheckFlag(ufImplicitUnit, 'implicitly imported');
      Line := Format('0x%.2X    %s%s', [Hash, AlignString(AName), Line]);
      M.Seek(Length(AName) + 1, soCurrent);
      Result.Add(Line);
    end;
    Result.Add(LineSeparator);
  end;
end;

function DFMToString(ARes: TResource): TStringList;
var
  Txt: TMemoryStream;
begin
  Result := TStringList.Create;
  Txt := TMemoryStream.Create;
  try
    ARes.Data.Position := 0;
    ObjectBinaryToText(ARes.Data, Txt);
    Txt.Position := 0;
    Result.LoadFromStream(Txt);
  finally
    Txt.Free;
  end;
end;

end.
