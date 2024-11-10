Call Stack Converter
================

Демонстрация работы с классом TDebugMap на примере конвертации стека вызовов снятого при помощи Process Explorer https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer

### Внешний вид:

![1](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/MemoryMap/demos/CallStackConverter/img/1.png?raw=true "Внешний вид")

### Принцип работы

1. Выбрать в Process Explorer требуемый процесс.
2. Перейти в свойства процесса на вкладку Threads, вызвать Stack интересующего потока.
3. Скопировать выведеный стек в буфер обмена.

![2](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/MemoryMap/demos/CallStackConverter/img/2.png?raw=true )

* В утилите установить ImageBase исполняемого файла (или библиотеки - смотря что интересует)
* Открыть исполняемый файл или библиотеку (наличие MAP файла обязательно)
* Нажать кнопку конвертации
* Результат можно скопировать через PopupMenu