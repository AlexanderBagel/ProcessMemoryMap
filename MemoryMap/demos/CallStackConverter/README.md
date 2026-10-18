**English** | [Русский](README.RU.md)

Call Stack Converter
================

A demonstration of working with the TDebugMap class, using the conversion of a call stack captured with Process Explorer as an example: https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer

### Appearance:

![1](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/MemoryMap/demos/CallStackConverter/img/1.png?raw=true "Appearance")

### How it works

1. Select the required process in Process Explorer.
2. Open the process properties, go to the Threads tab, and call Stack for the thread of interest.
3. Copy the displayed stack to the clipboard.

![2](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/MemoryMap/demos/CallStackConverter/img/2.png?raw=true )

* In the utility, set the ImageBase of the executable file (or library, depending on which one you are interested in)
* Open the executable file or library (a MAP file is required)
* Click the convert button
* The result can be copied via the PopupMenu
