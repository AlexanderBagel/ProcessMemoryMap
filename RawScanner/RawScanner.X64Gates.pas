////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.X64Gates.pas
//  * Purpose   : Универсальный генератор шлюзов вызова 64 битных API
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.0.8
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.X64Gates;

interface

uses
  Windows,
  SysUtils,
  RawScanner.Types;

type
  TParamSize = (ps4Byte = 2, ps8Byte = 3);

  /// <summary>
  ///  MakeX64Gate - генерирует шлюз вызова 64 битныой API функции.
  ///  FuncAddr - адрес 64 битной stdcall функции в текущем процессе
  ///  Params - масив размеров параметров на 32 битном стеке
  /// </summary>
  function MakeX64Gate(FuncAddr: ULONG_PTR64; Params: array of TParamSize): Pointer;
  procedure ReleaseX64Gate(Value: Pointer);

implementation

function MakeX64Gate(FuncAddr: ULONG_PTR64; Params: array of TParamSize): Pointer;
{$IFDEF WIN64}
begin
  Result := Pointer(FuncAddr);
{$ELSE}

var
  InsPoint: PByte;

  procedure Push(Instructions: array of Byte);
  begin
    Move(Instructions[0], InsPoint^, Length(Instructions));
    Inc(InsPoint, Length(Instructions));
  end;

  procedure PushDWord(Value: DWORD);
  begin
    Move(Value, InsPoint^, 4);
    Inc(InsPoint, 4);
  end;

  procedure PushDWord64(Value: DWORD64);
  begin
    Move(Value, InsPoint^, 8);
    Inc(InsPoint, 8);
  end;

var
  I, ParamsCount, ParamSize, ParamsLeft: Integer;
  x32StackPtr, x64StackPtr: Byte;
begin
  Result := VirtualAlloc(nil, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  InsPoint := Result;

  // рассчет количества и общего размера переданых параметров
  ParamsCount := Length(Params);

  // в автогенерации используются короткие инструкции работающие с байтом
  // поэтому нужен контроль чтобы ParamsCount * 8 не вылез за его пределы
  if ParamsCount > 31 then
    raise Exception.Create('Too many params');

  ParamSize := 0;
  for I := 0 to ParamsCount - 1 do
    Inc(ParamSize, 1 shl Byte(Params[I]));

  // пролог
  Push([$55]);                              // push ebp
  Push([$8B, $EC]);                         // mov ebp, esp

  // выравнивание стека
  Push([$89, $E0]);                         // mov eax, esp
  Push([$83, $E0, $07]);                    // and eax, $07
  Push([$83, $F8, $00]);                    // cmp eax, $00
  Push([$74, $02]);                         // jz +2
  Push([$29, $C4]);                         // sub esp, eax

  // переключение в 64 битный режим
  Push([$EA]);                              // jmp far 0x33:+SizeOf(jmp)
  PushDWord(DWORD(InsPoint) + 6);
  Push([$33, 0]);

  // формирование 64 битного фрейма
  Push([$55]);                              // push rbp
  if ParamsCount > 0 then
    Push([$48, $83, $EC, ParamsCount * 8]); // sub rsp, 64 params size
  Push([$48, $89, $E5]);                    // mov rbp, rsp

  // перенос параметров для 64 битного вызова

  if ParamsCount > 0 then
  begin
    // выставление указателя на последний параметр с 32 битного стека
    Push([$48, $8D, $84, $04]);             // lea rax, [rsp + rax + ...]
    PushDWord(
      ParamsCount * 8 +                     // размер 64 битных параметров
      8 +                                   // 64 битный push rbp
      ParamSize +                           // размер 32 битных параметров
      4 +                                   // 32 битный push ebp
      4                                     // 32 битный адрес возврата
      );
    ParamsLeft := ParamsCount - 1;
    x32StackPtr := 0;
    x64StackPtr := ParamsCount * 8;
    while ParamsLeft >= 0 do
    begin
      // сдвигаем указатель на начало следующего параметра на 32 битном стеке
      Inc(x32StackPtr, 1 shl Byte(Params[ParamsLeft]));
      case ParamsLeft of
        0: // mov rcx, [rax - "оффсет на 32 битный параметр со стека"]]
        begin
          if Params[ParamsLeft] = ps8Byte then
            Push([$48]); // REX Pfx здесь и далее
          Push([$8B, $48, Byte(-x32StackPtr)]);
        end;
        1: // mov rdx, [rax - "оффсет на 32 битный параметр со стека"]
        begin
          if Params[ParamsLeft] = ps8Byte then
            Push([$48]);
          Push([$8B, $50, Byte(-x32StackPtr)]);
        end;
        2: // mov r8, [rax - "оффсет на 32 битный параметр со стека"]
        begin
          if Params[ParamsLeft] = ps8Byte then
            Push([$4C, $8B, $40, Byte(-x32StackPtr)])
          else
            Push([$44, $8B, $40, Byte(-x32StackPtr)]);
        end;
        3: // mov r9, [rax - "оффсет на 32 битный параметр со стека"]
        begin
          if Params[ParamsLeft] = ps8Byte then
            Push([$4C, $8B, $48, Byte(-x32StackPtr)])
          else
            Push([$44, $8B, $48, Byte(-x32StackPtr)]);
        end;
      else
        Dec(x64StackPtr, 8);
        // mov RCX, [rax - "оффсет на 32 битный параметр со стека"]
        if Params[ParamsLeft] = ps8Byte then
          Push([$48]);
        Push([$8B, $48, Byte(-x32StackPtr)]);
        // mov [rsp + "оффсет на 64 битный параметр на сетке"], rcx
        Push([$48, $89, $4C, $24, x64StackPtr]);
      end;
      Dec(ParamsLeft);
    end;
  end;

  // вызов фунции
  Push([$FF, $15, $02, 0, 0, 0]);           // call qword ptr [rel $00000002]
  Push([$EB, $08]);                         // jmp +8
  PushDWord64(FuncAddr);                    // реальный адрес функции

  // перемещение результата из RAX в пару EAX + EDX
  Push([$48, $89, $C2]);                    // mov rdx, rax
  Push([$48, $C1, $EA, $20]);               // shr rdx, $20

  // закрытие 64 битного фрейма
  if ParamsCount > 0 then
    Push([$48, $83, $C4, ParamsCount * 8]); // add rsp, 64 params size
  Push([$5D]);                              // pop rbp

  // переключение в 32 битный режим
  Push([$FF, $2D, 0, 0, 0, 0]);             // jmp far word ptr ds:[0]
  PushDWord(DWORD(InsPoint) + 6);           // jmp addr
  Push([$23, 0]);                           // CS param

  // восстановление 32 битного стека
  Push([$89, $EC]);                         // mov esp, ebp

  // эпилог
  Push([$5D]);                              // pop ebp
  Push([$C2, ParamSize, 0]);                // ret + 32 params size
{$ENDIF}
end;

procedure ReleaseX64Gate(Value: Pointer);
begin
  {$IFDEF WIN32}
  if Value <> nil then
    VirtualFree(Value, 0, MEM_RELEASE);
  {$ENDIF}
end;

end.
