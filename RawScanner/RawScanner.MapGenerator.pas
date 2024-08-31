////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.MapGenerator.pas
//  * Purpose   : Генератор отладочного MAP файла на основе DWARF информации.
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2024.
//  * Version   : 1.1.20
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.MapGenerator;

interface

uses
  Windows,
  SysUtils,
  Classes,
  Math,
  Generics.Defaults,
  Generics.Collections,
  RawScanner.CoffDwarf;

  function MakeDebugMap(const FilePath, MapFilePath: string;
    ADebugInfo: TDwarfDebugInfo; Entry: UInt64): Boolean;

implementation

const
  SectionsHeader = ' Start         Length     Name                   Class';
  SectionsFmt = ' %.4x:%.8x %.8xH %s%s';
  PublicsByNameHeader = '  Address             Publics by Name';
  PublicsByValueHeader = '  Address             Publics by Value';
  PublicsByFmt = ' %.4x:%.8x       %s';
  LineNumbersHeader = 'Line numbers for %s(%s) segment %s';
  LineNumbersFmt = '%s%s %.4x:%.8x';
  EntryPointHeader = 'Program entry point at %.4x:%.8x';

type
  TFunction = record
    AddrVA: UInt64;
    SecIdx: Integer;
    DisplayName: string;
  end;

procedure UpdateFileTime(const FilePath, MapFilePath: string);
var
  FFD: TWin32FindData;
  hFile: THandle;
begin
  Windows.FindClose(FindFirstFile(PChar(FilePath), FFD));
  hFile := FileOpen(MapFilePath, fmOpenWrite);
  try
    SetFileTime(hFile,
      @FFD.ftCreationTime,
      @FFD.ftLastAccessTime,
      @FFD.ftLastWriteTime);
  finally
    FileClose(hFile);
  end;
end;

function MakeDebugMap(const FilePath, MapFilePath: string;
  ADebugInfo: TDwarfDebugInfo; Entry: UInt64): Boolean;
var
  AMap: TStringList;

  procedure Add(const Value: string = '');
  begin
    AMap.Add(Value);
  end;

  function StrLength(const Value: string; ALength: Integer): string;
  begin
    Result := Value + StringOfChar(' ', ALength - Length(Value));
  end;

  function SectionClass(const Section: TSectionParams): string;
  begin
    if Section.IsExecutable then
      Exit('CODE');
    if AnsiSameText('.bss', Section.DisplayName) then
      Exit('BSS');
    if AnsiSameText('.tls', Section.DisplayName) then
      Exit('TLS');
    if AnsiSameText('.itext', Section.DisplayName) then
      Exit('ICODE');
    Result := 'DATA';
  end;

var
  I, Index: Integer;
  Section: TSectionParams;
  Sections: TList<TSectionParams>;
  AFunction: TFunction;
  Functions: TList<TFunction>;
  AUnit: TDwarfInfoUnit;
  ALine: TDwarfLinesUnit;
  ALineData: TLineData;
  Die: TDebugInformationEntry;
  LineStr: string;
  LineStrCount, CurrentFileIdx, LinesCount: Integer;
  LinesHeaderAdded: Boolean;

  function AddrToSection(AddrVA: UInt64; var ASection: TSectionParams): Boolean;
  begin
    ASection.AddressVA := AddrVA;
    Sections.BinarySearch(ASection, Index);
    if AddrVA < Sections.List[Index].AddressVA then
      Dec(Index);
    ASection := Sections[Index];
    Result := (AddrVA >= Section.AddressVA) and
      (AddrVA < Section.AddressVA + Section.SizeOfRawData);
  end;

  function DecToStr(Value: Integer): string;
  begin
    Result := IntToStr(Value);
    Result := StringOfChar(' ', 5 - Length(Result)) + Result;
  end;

begin
  AMap := TStringList.Create;
  try

    Add;
    Add(SectionsHeader);

    I := 0;
    Index := 1;
    Sections := TList<TSectionParams>.Create(
      TComparer<TSectionParams>.Construct(
        function (const A, B: TSectionParams): Integer
        begin
          Result := IfThen(A.AddressVA < B.AddressVA, -1, IfThen(A.AddressVA > B.AddressVA, 1, 0));
        end
      ));
    try

      while ADebugInfo.Image.SectionAtIndex(I, Section) do
      begin
        Add(Format(SectionsFmt, [Index,
          Section.AddressVA, Section.SizeOfRawData,
          StrLength(Section.DisplayName, 24), SectionClass(Section)]));
        Section.AddressRaw := Index;
        Sections.Add(Section);
        Inc(Index);
        Inc(I);
      end;
      Add;

      Sections.Sort;

      Functions := TList<TFunction>.Create;
      try

        AFunction.SecIdx := -1;
        for AUnit in ADebugInfo.UnitInfos do
          for Die in AUnit.Data do
          begin
            AFunction.AddrVA := Die.AddrVA;
            AFunction.DisplayName := Die.AName;
            Functions.Add(AFunction);
          end;

        for I := 0 to Functions.Count - 1 do
        begin
          AFunction := Functions[I];
          if AddrToSection(AFunction.AddrVA, Section) then
          begin
            AFunction.SecIdx := Section.AddressRaw;
            Dec(AFunction.AddrVA, Section.AddressVA);
            Functions[I] := AFunction;
          end;
        end;

        Functions.Sort(TComparer<TFunction>.Construct(
          function (const A, B: TFunction): Integer
          begin
            Result := AnsiCompareText(A.DisplayName, B.DisplayName);
          end
        ));

        Add;
        Add(PublicsByNameHeader);
        Add;

        for AFunction in Functions do
          Add(Format(PublicsByFmt, [AFunction.SecIdx, AFunction.AddrVA, AFunction.DisplayName]));

        Add;

        Functions.Sort(TComparer<TFunction>.Construct(
          function (const A, B: TFunction): Integer
          begin
            Result := IfThen(A.SecIdx < B.SecIdx, -1, IfThen(A.SecIdx > B.SecIdx, 1, 0));
            if Result = 0 then
              Result := IfThen(A.AddrVA < B.AddrVA, -1, IfThen(A.AddrVA > B.AddrVA, 1, 0));
          end
        ));

        Add;
        Add(PublicsByValueHeader);
        Add;

        for AFunction in Functions do
          Add(Format(PublicsByFmt, [AFunction.SecIdx, AFunction.AddrVA, AFunction.DisplayName]));

        Add;

      finally
        Functions.Free;
      end;

      Add;

      LinesCount := 0;
      LinesHeaderAdded := False;
      for ALine in ADebugInfo.UnitLines do
      begin
        AUnit := ADebugInfo.UnitInfos[ALine.MappedUnitIndex];
        if AddrToSection(AUnit.AddrStart, Section) then
        begin
          LineStr := '';
          LineStrCount := 0;
          CurrentFileIdx := -1;
          for ALineData in ALine.Lines do
          begin
            if CurrentFileIdx <> ALineData.FileId then
            begin
              LineStrCount := 0;
              if LineStr <> '' then
                Add(LineStr);
              LineStr := '';
              if (LinesCount = 0) and LinesHeaderAdded then
                AMap[AMap.Count - 2] := Format(LineNumbersHeader, [AUnit.UnitName,
                ExtractFileName(ALine.GetFilePath(CurrentFileIdx)), Section.DisplayName])
              else
              begin
                Add;
                CurrentFileIdx := ALineData.FileId;
                Add(Format(LineNumbersHeader, [AUnit.UnitName,
                  ExtractFileName(ALine.GetFilePath(CurrentFileIdx)), Section.DisplayName]));
                Add;
              end;
              LinesHeaderAdded := True;
              LinesCount := 0;
            end;
            if ALineData.IsStmt then
            begin
              Inc(LinesCount);
              LineStr := Format(LineNumbersFmt, [LineStr,
                DecToStr(ALineData.Line), Section.AddressRaw,
                ALineData.AddrVA - Section.AddressVA]);
              Inc(LineStrCount);
              if LineStrCount = 4 then
              begin
                LineStrCount := 0;
                Add(LineStr);
                LineStr := '';
              end;
            end;
          end;
          if LineStr <> '' then
            Add(LineStr);
        end;

      end;

      Add;

      Add;

      if AddrToSection(Entry, Section)then
      begin
        Dec(Entry, Section.AddressVA);
        Add(Format(EntryPointHeader, [Section.AddressRaw, Entry]));
      end;

      Add;

    finally
      Sections.Free;
    end;

    AMap.SaveToFile(MapFilePath);
    Result := ADebugInfo.UnitInfos.Count > 0;
  finally
    AMap.Free;
  end;

  UpdateFileTime(FilePath, MapFilePath);
end;

end.
