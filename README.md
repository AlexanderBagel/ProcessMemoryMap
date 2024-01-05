﻿Process Memory Map
================

Утилита предназначена для отображения карты памяти процесса.

![1](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/1.png?raw=true "Внешний вид")

Отображает следующие данные:

* кучи процесса
* данные по нитям, как то: стек, TEB, SEH фреймы и CallStack
* информация по подгруженным PE файлам с разбивкой на секции, точки входа в каждый загруженный образ, их структуры
* данные из PEB
* данные из KUSER_SHARED_DATA
* встроенный x86/x64 дизассемблер (на базе DiStorm)

Предоставляет возможность:
* анализа памяти на предмет установленных перехватчиков в таблицах импорта/экспорта/отложенного импорта 
* анализа установленных перехватчиков в экспортируемых функциях, точках входа и TLS калбэках
* анализа блоков памяти на основе их контрольных сумм (например отображение изменений во взломанном ПО).
* поиска в памяти процесса.

Из дополнительных возможностей:
* выводит список экспортируемых функций.
* поддерживает отладочные MAP файлы. (влияет на список распознанных функций и выхлоп дизассемблера)
* отображает изменения в выделенных блоках памяти (alloc/realloc/free)
* быстрая подсказка по известным блокам памяти

### Сборка проекта:

Для самостоятельной сборки потребуется:

* установленный пакет компонентов Virtual TreeView версии 8.0 и выше: https://github.com/JAM-Software/Virtual-TreeView
* установленный набор классов для работы с ZIP архивами FWZip версии 1.0.9 и выше: https://github.com/AlexanderBagel/FWZip

Сборка осуществляется с использованием Delphi 10.4.2 Seattle в режиме "Win32/Release", при этом автоматически будет собрана и подключена (в виде ресурса) 64-битная версия данной утилиты.
Под более старыми версиями Delphi работоспособность ProcessMemoryMap не проверялась и не гарантируется.

### Внутренние версии фреймворков:
* MemoryMap Core - 1.4.34
* RawScanner Core - 1.0.18
* FWZip - 2.0.2
* Distorm - 3.5.3

### RoadMap (с предположительными версиями):

* 1.5 полная поддержка DWARF 4 и 5 версий, поддержка типов STUB
* 1.6 вывод размапленой информации по директории resources
* 1.6 вывод используемых ресурсов в виде дерева
* 1.7 вывод размапленой информации по директорям exceptions, security
* 1.7 вывод размапленой информации по директории com+ в виде дерева
* 1.8 вывод размапленой информации по директории debug
* 1.8 поддержка отладочных PDB файлов
* 1.8 перевод вывода системных структур на основе полученных данных из PDB
* 1.9 поддержка отладочной информации JclDebug (возможно в виде плагина)
* 2.0 перевод Hex дампов и дизассемблера на FWHexView

### Обновления:

1.5.36 от 05.01.2024
* фикс критической ошибки в RawScaner из-за которой отвалился форвард функций.

1.5.35 от 29.12.2023
* добавлен вывод CallStack потоков с поддержкой CallStack снятого утилитой ProcessExplorer
* исправлена незначительная ошибка вывода пустых блоков при включенном детекте выравниваний

1.4.34 от 19.12.2023
* в дизассемблере отключен вывод имени текущего модуля, имя модуля указывается только для внешних адресов
* переделан механизм фильтров страниц для вывода данных по приоритетному фильтру в случае если страница имеет несколько аттрибутов (Shared/Mapped etc...)
* добавлена обработка загрузки аттрибута DW_AT_location из секции .debug_loc
* добавлена обработка загрузки модулей из секции .debug_info в которых присутствует только DW_TAG_compile_unit, или только файлы/директории из секции .debug_line.
* исправлен неверный размер аттрибута DW_AT_language у тэга DW_TAG_compile_unit
* добавлено детектирование имен секций в отладочном COFF по символу IMAGE_SYM_CLASS_STATIC (и проверку на имя начинающееся с точки). Такие записи исключены из вывода.

Полный список обновлений в файле updates.txt

### Скриншоты:

Как и в оригинальной утилите от Марка Руссиновича, присутствует фильтрация по типам данных.
В данном случае отображаются только те блоки памяти, которые содержат системные данные (KUSER_SHARED_DATA, PEB, etc...)

![2](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/2.png?raw=true "Фильтрация")

Данные всех поддерживаемых структур размаплены для их более удобного восприятия.
К примеру, вот так выглядит отображение блока окружения 64 битного процесса.

![3](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/3.png?raw=true "PEB")

А вот так выглядит IMAGE_DOS_HEADER

![4](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/4.png?raw=true "IMAGE_DOS_HEADER")

Если не известно что за структура мапится на текущий адрес памяти, то данные отобрадаются в RAW режиме.
Например вот так выглядит код на точке входа kernel32.dll

![5.1](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/5.png?raw=true "Entry Point RAW")

Он же, но в виде дизассемблированного кода (переключение между видами в меню по правой клавише мышки "Show as disassembly" или по горячей клавише Ctrl+D):

![5.2](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/6.png?raw=true "Entry Point Disassembled")

* Для нагрядности дизассемблерный выхлоп форматирован.
* Код известных экспортируемых функций предваряется описанием. 
* Выхлоп форматируется дабы не мозолили глаза NOP и INT3 инструкции, выделяется окончание функций (RET/IRET/RETF).

![5.3](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/9.png?raw=true "NTDLL Export")

Для быстрой навигации по известным структурам предсмотрено оглавление, доступное через меню View -> Show Known Data... или по горячей клавише F2

![6](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/12.png?raw=true "Known Data")

Присутствует список всех импортируемых/экспортируемых функций (Ctrl+E).
В него же добавляются данные из отладочного МАР файла (если присутствует - поддерживаются MAP файлы Delphi/С++)
К нему добавлен поиск как по адресу, так и по имени функции (поиск по наименованию библиотеки не производится)

![7](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/7.png?raw=true "Export list")

При наличии информации известные вызовы в дизассемблере коментируются.
![7.1](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/10.png?raw=true "CALL hint")

Включая вызовы через таблицу импорта.
![7.2](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/11.png?raw=true "CALL import hint")

Присутствует модуль анализа процесса на предмет установленых перехватчиков фунций (F8)
![8](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/14.png?raw=true "Hook scanner output")

Присутствует модуль деманглинга стека вызовов потоков включая 32 и 64 бита + 32SEH (F4)
![9](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/15.png?raw=true "Threads CallStack")

Ну и вот так выглядит список изменений в выделенных блоках с последней проверки (F5)

![10](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/8.png?raw=true "Compare result")

Ну и много много чего еще интересного.