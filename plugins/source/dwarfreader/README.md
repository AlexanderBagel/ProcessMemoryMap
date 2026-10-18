**English** | [Русский](README.RU.md)

DWARF Reader
================

A small utility that displays the debug information present in an executable file.
Supported formats:
* PE32/64 - displays DWARF information and information from the COFF section (Va+Raw addressing)
* ELF32/64 - displays DWARF information and information from the symbol section (Va+Raw addressing); for object files, data is displayed in Raw addressing only.
* COFF32/64 object files - displays DWARF information and information from the COFF section. Only Raw addressing is available.

IMPORTANT:
Object files contain DWARF information without addresses, so for them it is displayed for informational purposes only.
Partial information in the form of Raw offsets is present in the symbol section (for ELF object files) and in the COFF section.

### Appearance:

![1](https://github.com/AlexanderBagel/ProcessMemoryMap/blob/master/plugins/source/dwarfreader/img/1.png?raw=true "Appearance")
