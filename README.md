ProcessMemoryMap
================

Утилита предназначена для отображения карты памяти процесса.

Отображает следующие данные:

* кучи процесса
* данные по нитям, как то: стек, TEB, SEH фреймы и CallStack
* информация по подгруженным PE файлам с разбивкой на секции, точки входа в каждый загруженный образ
* данные из PEB
* данные из KUSER_SHARED_DATA
* встроенный x86/x64 дизассемблер (на базе BeaEngine 3.1)

Предоставляет возможность поиска блока данных по памяти процесса.
Выводит список экспортируемых функций.
Отображает изменения в выделенных блоках памяти (alloc/realloc/free)

###Сборка проекта:

Для самостоятельной сборки потребуется:
1. установленный пакет компонентов Virtual TreeView версии 5 и выше: http://www.soft-gems.net/ 
2. установленный набор классов для работы с ZIP архивами FWZip версии 1.0.9 и выше: https://github.com/AlexanderBagel/FWZip

Сборка осуществляется с использованием Delphi XE4 и выше в режиме "Win32/Release", при этом автоматически будет собрана и подключена (в виде ресурса) 64-битная версия данной утилиты.
Под более старыми версиями Delphi работоспособность ProcessMemoryMap не проверялась.

Внешний вид:

![1](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/1.png?raw=true "Внешний вид")

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

![5](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/5.png?raw=true "Entry Point RAW")

Он же, но в виде дизассемблированного кода (переключение между видами в меню по правой клавише мышки "Show as disassembly" или по горячей клавише Ctrl+D):

![6.1](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/6.png?raw=true "Entry Point Disassembled")

Либо вот так (уже на основе нового движка)

![6.2](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/9.png?raw=true "NTDLL Export")

Присутствует список всех импортируемых/экспортируемых функций (Ctrl+E).
К нему добавлен поиск как по адресу, так и по имени функции (поиск по наименованию библиотеки не производится)

![7](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/7.png?raw=true "Export list")

Ну и вот так выглядит список изменений в выделенных блоках с последней проверки (F5)

![8](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/8.png?raw=true "Compare result")

Ну и много много чего еще интересного.