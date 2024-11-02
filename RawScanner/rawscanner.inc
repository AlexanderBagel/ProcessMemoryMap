////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : rawscanner.inc
//  * Purpose   : Настройки фреймворка
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2024.
//  * Version   : 1.0.24
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

// Данный модуль предназначен для глобального включения
// директив настройки пакета RawScanner

// Если необходимо отключить работу с контекстом активации раскоментируйте
// директиву DISABLE_ACTCTX при этом модуль RawScanner.ActivationContext
// можно изьять из состава проекта

//  {$DEFINE DISABLE_ACTCTX}


// Если необходимо отключить работу с логером раскоментируйте
// директиву DISABLE_LOGGER при этом модуль RawScanner.Logger
// можно изьять из состава проекта

//  {$DEFINE DISABLE_LOGGER}

// Если необходимо отключить вывод профилирования, закоментируйте
// директиву USE_PROFILING

{$DEFINE USE_PROFILING}

