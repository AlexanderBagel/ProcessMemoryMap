**English** | [Русский](README.RU.md)

Process Memory Map
================

[![Boosty](https://img.shields.io/badge/Boosty-Support-orange?logo=boosty)](https://boosty.to/processmemorymap)

A utility for displaying the memory map of a process.

![1](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/1.png?raw=true "Appearance")

Displays the following data:

* process heaps
* thread data: stack, TEB, SEH frames and CallStack
* information about loaded PE files, broken down by sections, with entry points of every loaded image and their structures
* PEB data
* KUSER_SHARED_DATA data
* built-in x86/x64 disassembler (based on DiStorm)

Provides the ability to:
* analyze memory for installed hooks in import/export/delayed import tables
* analyze installed hooks in exported functions, entry points and TLS callbacks
* analyze memory blocks based on their checksums (for example, to show changes in cracked software)
* search process memory

Additional features:
* lists exported functions
* lists resources
* displays process stacks (x86 + x64)
* supports debug MAP files (affects the list of recognized functions and the disassembler output)
* displays changes in allocated memory blocks (alloc/realloc/free)
* quick hints for known memory blocks

### Building the project:

To build it yourself, you will need:

* the Virtual TreeView component package, version 8.0 or higher: https://github.com/JAM-Software/Virtual-TreeView
* the 2D graphics class library, version 4.9 or higher: https://github.com/AngusJohnson/Image32
* the ZIP archive class library, version 1.0.9 or higher: https://github.com/AlexanderBagel/FWZip
* the Hex View Project component package, version 2.0.16 or higher: https://github.com/AlexanderBagel/FWHexView

The project is built with Delphi 13.1 Florence in "Win32/Release" mode; the 64-bit version of the utility is built automatically and embedded as a resource.
ProcessMemoryMap has not been tested with older versions of Delphi, and compatibility is not guaranteed.

### Internal framework versions:
* MemoryMap Core - 1.4.40
* RawScanner Core - 1.2.29
* FWZip - 2.0.11
* Hex View Project - 2.0.16
* Distorm - 3.5.3
* Image32 library - 4.9

### RoadMap

* optimization of the search engine, search for changes in previously found blocks
* development of a template engine for displaying arbitrary structures
* migration of all currently supported structures to the template engine
* migration of hex dumps and the disassembler to FWHexView
* display of system structures based on data obtained from PDB
* display of mapped information for the resources directory
* display of mapped information for the exceptions and security directories
* display of mapped information for the com+ directory as a tree
* support for DWARF version 5, support for STUB types
* support for JclDebug debug information (possibly as a plugin)

### Change history:

#### 1.7.54 from 18.10.2026
* Added support for debug directories to the TRawPEImage class, property DebugDirList<>
* Added output of IMAGE_DEBUG_DIRECTORY information, including extended information for IMAGE_DEBUG_TYPE_CODEVIEW, with PDB symbol configuration.
* Added support for PDB debug files. In the settings you can choose the loading mode: on attaching to a process, or manually via the storage manager.
* The new PDB symbol storage manager allows cleaning up outdated data and refreshing debug symbols after OS updates.
* Fixed an error reading the "Line Number Program Header" for DWARF4 debug information
* Fixed an error processing R_X86_64_IRELATIVE records when reading .rela.plt in ELF files
* Added checking for new versions of Process Memory Map
* Added English comments
* Cleaned up debug code in the animation control
* The correct file extension is now used when saving animated resources
* For class/dialog/window procedures, the module they reside in is now displayed

#### 1.7.53 from 16.08.2026
* Added a new mode for working with windows of a remote process
* Fixed a long-standing bug in 64-bit heap handling
* Restored correct operation of filters
* Fixed an alignment error when reading the version stream, which could cause reading beyond the stream bounds.
* Added checks when reading process parameters in TMemoryMap.AddPEBData, whose absence previously made it impossible to open some processes.
* Completed the resources mode: added display of icon and cursor groups and SVG, and saving resources to disk
* Restored Windows XP compatibility
* Fixed a DPI issue with the VirtualStringTree control

The full list of updates is in the updates.txt file

### Screenshots:

As in the original utility by Mark Russinovich, filtering by data type is available.
In this case, only memory blocks containing system data (KUSER_SHARED_DATA, PEB, etc...) are shown.

![2](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/2.png?raw=true "Filtering")

The data of all supported structures is mapped for easier comprehension.
For example, this is how the environment block of a 64-bit process looks.

![3](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/3.png?raw=true "PEB")

And this is what IMAGE_DOS_HEADER looks like

![4](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/4.png?raw=true "IMAGE_DOS_HEADER")

If it is not known which structure is mapped at the current memory address, the data is displayed in RAW mode.
For example, this is the code at the kernel32.dll entry point

![5.1](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/5.png?raw=true "Entry Point RAW")

The same, but as disassembled code (switch between views via the right-click menu "Show as disassembly" or with the Ctrl+D hotkey):

![5.2](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/6.png?raw=true "Entry Point Disassembled")

* For clarity, the disassembler output is formatted.
* The code of known exported functions is preceded by a description.
* The output is formatted so that NOP and INT3 instructions don't clutter the view, and function endings (RET/IRET/RETF) are highlighted.

![5.3](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/9.png?raw=true "NTDLL Export")

For quick navigation through known structures there is a table of contents, available via the menu View -> Show Known Data... or with the F2 hotkey

![6](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/12.png?raw=true "Known Data")

There is a list of all imported/exported functions (Ctrl+E).
Data from the debug MAP file (if present; Delphi/C++ MAP files are supported) is added to it as well.
Search by both address and function name is available (library names are not searched)

![7](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/7.png?raw=true "Export list")

When the information is available, known calls in the disassembler are annotated.
![7.1](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/10.png?raw=true "CALL hint")

Including calls through the import table.
![7.2](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/11.png?raw=true "CALL import hint")

There is a module for analyzing a process for installed function hooks (F8)
![8](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/14.png?raw=true "Hook scanner output")

There is a module for demangling thread call stacks, including 32 and 64 bits + 32SEH (F4)
![9](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/15.png?raw=true "Threads CallStack")

Search results are shown in a separate dialog (Shift+F)
![10](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/16.png?raw=true "Search Results")

There is a module that displays the windows of the inspected process, with the addresses of window and class procedures and the parameters of each window (Ctrl+W).

![11](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/18.png?raw=true "Windows")

The module that displays the resources of all executable files of the process recognizes more than 30 different resource types (Ctrl+R).
It includes built-in text viewers and decoders for RC resources and images, including SVG and animations (AVI/ANICURSOR),
as well as decoders for Delphi/Lazarus-specific resources (DFM/LFM/DVCAL/PACKAGEINFO).
Resources can be saved to disk, both as a compiled RES file and as decoded data.

![12](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/17.png?raw=true "Resources")

The new PDB symbol storage manager allows cleaning up outdated data and refreshing debug symbols after OS updates.

![19](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/img/19.png?raw=true "PDB Storage Manager")

And a lot of other interesting things.

### Support the project

If you find the project useful, you can support its development on the author's main project page:

[![Boosty](https://img.shields.io/badge/Boosty-Support-orange?logo=boosty)](https://boosty.to/processmemorymap)
