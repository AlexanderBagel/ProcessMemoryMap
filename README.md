Process Memory Map
================

Утилита предназначена для отображения карты памяти процесса.

Отображает следующие данные:

* кучи процесса
* данные по нитям, как то: стек, TEB, SEH фреймы и CallStack
* информация по подгруженным PE файлам с разбивкой на секции, точки входа в каждый загруженный образ
* данные из PEB
* данные из KUSER_SHARED_DATA
* встроенный x86/x64 дизассемблер (на базе DiStorm)

Предоставляет возможность поиска блока данных по памяти процесса.
* Анализ блоков памяти на основе их контрольных сумм.
* Выводит список экспортируемых функций.
* Поддерживает отладочные MAP файлы. (влияет на список распознанных функций и выхлоп дизассемблера)
* Отображает изменения в выделенных блоках памяти (alloc/realloc/free)
* Быстрая подсказка по известным блокам памяти

###Сборка проекта:

Для самостоятельной сборки потребуется:

* установленный пакет компонентов Virtual TreeView версии 5 и выше: https://www.jam-software.com/virtual-treeview
* установленный набор классов для работы с ZIP архивами FWZip версии 1.0.9 и выше: https://github.com/AlexanderBagel/FWZip

Сборка осуществляется с использованием Delphi 10.4.2 Seattle в режиме "Win32/Release", при этом автоматически будет собрана и подключена (в виде ресурса) 64-битная версия данной утилиты.
Под более старыми версиями Delphi работоспособность ProcessMemoryMap не проверялась и не грантируется.

###Обновления:

1.2.17 от 07.11.2022
* подключен новый движок симовлов на основе RawScanner
* добавлены символы IAT/EAT + IMAGE_DIRECTORY_ENTRY_IAT
* добавлено три режима работы анализатора
* исправлены ошибка неверной работы в RvaToVa при выставленом VirtualSize = 0 в секции
* исправлена блокирующая ошибка при дампе 64-битного TEB

1.2.16 от 31.10.2022
* добавлен новый фремворк статического анализа памяти на предмет установленных перехватчиков (F8)
* добавлен механизм генерации MML файлов на основе МАР файлов (таблица конктрольных сумм процесса)
* добавлена частичная информация по структуре tagSOleTlsData (Teb->ReservedForOle)
* добавлен вывод структур загрузчика Peb->LoaderData 
* добавлен частичный вывод структур контекста активации Peb->ActivationContextData + Peb->SystemDefaultActivationContextData 
* начат плановый перевод движка символов на новый, основанный на базе RawScanner (будет ускорен вывод дизассемблирования)

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
В него же добавляются данные из отладочного МАР файла (если присутствует - поддерживаются MAP файлы начиная с Delphi 2010 и выше)
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