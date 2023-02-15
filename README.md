Process Memory Map
================

Утилита предназначена для отображения карты памяти процесса.

Отображает следующие данные:

* кучи процесса
* данные по нитям, как то: стек, TEB, SEH фреймы и CallStack
* информация по подгруженным PE файлам с разбивкой на секции, точки входа в каждый загруженный образ, их структуры
* данные из PEB
* данные из KUSER_SHARED_DATA
* встроенный x86/x64 дизассемблер (на базе DiStorm)

Предоставляет возможность:
* анализа памяти на предмет установленых перехватчиков в таблицах импорта/эскспора/отложеного импорта 
* анализа установленых перехватчиков в экспортируемых функциях, точках входа и TLS калбэках
* анализа блоков памяти на основе их контрольных сумм (например отображение изменений во взломаном ПО).
* поиска в памяти процесса.

Из дополнительных возможностей:
* выводит список экспортируемых функций.
* поддерживает отладочные MAP файлы. (влияет на список распознанных функций и выхлоп дизассемблера)
* отображает изменения в выделенных блоках памяти (alloc/realloc/free)
* быстрая подсказка по известным блокам памяти

###Сборка проекта:

Для самостоятельной сборки потребуется:

* установленный пакет компонентов Virtual TreeView версии 5 и выше: https://www.jam-software.com/virtual-treeview
* установленный набор классов для работы с ZIP архивами FWZip версии 1.0.9 и выше: https://github.com/AlexanderBagel/FWZip

Сборка осуществляется с использованием Delphi 10.4.2 Seattle в режиме "Win32/Release", при этом автоматически будет собрана и подключена (в виде ресурса) 64-битная версия данной утилиты.
Под более старыми версиями Delphi работоспособность ProcessMemoryMap не проверялась и не грантируется.

###Обновления:

1.3.25 от 15.02.2023
* Добавлена поддержка обновления Win11 KB5022845 (Build 22621.1265) в котором изменился размер структуры _RTL_HEAP_INFORMATION
* Добавлена проверка битности плагинов перед их загрузкой

Полный список обновлений в файле updates.txt

###Внешний вид:

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

Ну и вот так выглядит список изменений в выделенных блоках с последней проверки (F5)

![9](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/8.png?raw=true "Compare result")

Ну и много много чего еще интересного.