#include "elfsectiontype.h"
#include <sstream>
#include <iomanip>

using namespace std;

ElfSectionType::ElfSectionType(uint32_t value) : value(Type(value)) {}

std::string ElfSectionType::toString() const {
  switch (value) {
    case UNUSED:
      return "NULL - Unused";
    case PROGBITS:
      return "PROGBITS - Program data";
    case SYMTAB:
      return "SYMTAB - Symbol table";
    case STRTAB:
      return "STRTAB - String table";
    case RELA:
      return "RELA - Relocation entries with addends";
    case HASH:
      return "HASH - Symbol hash table";
    case DYNAMIC:
      return "DYNAMIC - Dynamic linking information";
    case NOTE:
      return "NOTE - Notes";
    case NOBITS:
      return "NOBITS - Program space with no data (bss)";
    case REL:
      return "REL - Relocation entries";
    case SHLIB:
      return "SHLIB - Reserved";
    case DYNSYM:
      return "DYNSYM - Dynamic linker symbol table";
    case INIT_ARRAY:
      return "INIT_ARRAY - Array of constructors";
    case FINI_ARRAY:
      return "FINI_ARRAY - Array of destructors";
    case PREINIT_ARRAY:
      return "PREINIT_ARRAY - Array of pre-constructors";
    case GROUP:
      return "GROUP - Section group";
    case SYMTAB_SHNDX:
      return "SYMTAB_SHNDX - Extended section indeces";
  }

  stringstream str;
  str << "OS specific - " << hex << setw(8) << setfill('0') << value;
  return str.str();
}

std::ostream& operator<<(std::ostream& ost, const ElfSectionType& type) {
  return ost << type.toString();
}
