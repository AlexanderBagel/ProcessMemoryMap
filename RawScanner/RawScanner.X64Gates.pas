////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.X64Gates.pas
//  * Purpose   : Генератор шлюзов вызова 64 битных stdcall API
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.0.9
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
  Math,
  RawScanner.Types;

type
  TParamSize = (ps4Byte = 2, ps8Byte = 3{, psXMM - XMM пока не поддерживается});

  /// <summary>
  ///  MakeX64Gate - генерирует шлюз вызова 64 битной API функции.
  ///  FuncAddr - адрес 64 битной stdcall функции в текущем процессе
  ///  Params - массив размеров параметров на 32 битном стеке
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
  I, ParamsCount, ShadowSpace, ParamSize, ParamsLeft: Integer;
  x32StackPtr, x64StackPtr: Byte;
begin
  Result := VirtualAlloc(nil, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  InsPoint := Result;

  if Result = nil then
    RaiseLastOSError;

  // рассчет количества и общего размера переданых параметров
  ParamsCount := Length(Params);

  // в автогенерации используются короткие инструкции работающие с байтом
  // поэтому нужен контроль чтобы ParamsCount * 8 не вылез за его пределы
  if ParamsCount > 31 then
    raise Exception.Create('Too many params');

  ParamSize := 0;
  for I := 0 to ParamsCount - 1 do
    Inc(ParamSize, 1 shl Byte(Params[I]));
  // Теневое пространство требует минимум 32 байта под 4 дефолтных регистра
  ShadowSpace := Max(32, ParamsCount * 8);

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
  Push([$48, $83, $EC, ShadowSpace]);       // sub rsp, 64 ShadowSpace
  Push([$48, $89, $E5]);                    // mov rbp, rsp

  // перенос параметров для 64 битного вызова

  if ParamsCount > 0 then
  begin
    // выставление указателя на последний параметр с 32 битного стека
    Push([$48, $8D, $84, $04]);             // lea rax, [rsp + rax + ...]
    PushDWord(
      ShadowSpace +                         // размер 64 битного теневого пространства
      8 +                                   // 64 битный push rbp
      ParamSize +                           // размер 32 битных параметров
      4 +                                   // 32 битный push ebp
      4                                     // 32 битный адрес возврата
      );
    ParamsLeft := ParamsCount - 1;
    x32StackPtr := 0;
    x64StackPtr := ShadowSpace;
    while ParamsLeft >= 0 do
    begin
      // сдвигаем указатель на начало следующего параметра на 32 битном стеке
      Inc(x32StackPtr, 1 shl Byte(Params[ParamsLeft]));
      case ParamsLeft of
        0: // mov rcx(ecx), [rax - x32StackPtr]]
        begin
          if Params[ParamsLeft] = ps8Byte then
            Push([$48]); // REX Pfx здесь и далее. Используется для модификации ecx->rcx
          Push([$8B, $48, Byte(-x32StackPtr)]);
        end;
        1: // mov rdx(edx), [rax - x32StackPtr]
        begin
          if Params[ParamsLeft] = ps8Byte then
            Push([$48]);
          Push([$8B, $50, Byte(-x32StackPtr)]);
        end;
        2: // mov r8(r8d), [rax - x32StackPtr]
        begin
          if Params[ParamsLeft] = ps8Byte then
            Push([$4C, $8B, $40, Byte(-x32StackPtr)])
          else
            Push([$44, $8B, $40, Byte(-x32StackPtr)]);
        end;
        3: // mov r9(r9d), [rax - x32StackPtr]
        begin
          if Params[ParamsLeft] = ps8Byte then
            Push([$4C, $8B, $48, Byte(-x32StackPtr)])
          else
            Push([$44, $8B, $48, Byte(-x32StackPtr)]);
        end;
      else
        // mov rcx(ecx), [rax - x32StackPtr]
        if Params[ParamsLeft] = ps8Byte then
          Push([$48]);
        Push([$8B, $48, Byte(-x32StackPtr)]);
        Dec(x64StackPtr, 8);
        // mov [rsp + "оффсет на 64 битный параметр на сетке"], rcx
        Push([$48, $89, $4C, $24, x64StackPtr]);
      end;
      Dec(ParamsLeft);
    end;
  end;

  // вызов фунции
  Push([$48, $B8]);                         // mov rax, FuncAddr
  PushDWord64(FuncAddr);
  Push([$FF, $D0]);                         // call rax

  // перемещение результата из RAX в пару EAX + EDX
  Push([$48, $89, $C2]);                    // mov rdx, rax
  Push([$48, $C1, $EA, $20]);               // shr rdx, $20

  // закрытие 64 битного фрейма
  Push([$48, $83, $C4, ShadowSpace]);       // add rsp, 64 ShadowSpace
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
