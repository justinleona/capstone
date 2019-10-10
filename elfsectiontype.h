#pragma once

#include <string>
#include "elf.h"

/**
 * These are all copied from the defines in elf.h
 */
class ElfSectionType {
 public:
  enum Type : uint32_t {
    UNUSED = SHT_NULL,                 /* Section header table entry unused */
    PROGBITS = SHT_PROGBITS,           /* Program data */
    SYMTAB = SHT_SYMTAB,               /* Symbol table */
    STRTAB = SHT_STRTAB,               /* String table */
    RELA = SHT_RELA,                   /* Relocation entries with addends */
    HASH = SHT_HASH,                   /* Symbol hash table */
    DYNAMIC = SHT_DYNAMIC,             /* Dynamic linking information */
    NOTE = SHT_NOTE,                   /* Notes */
    NOBITS = SHT_NOBITS,               /* Program space with no data (bss) */
    REL = SHT_REL,                     /* Relocation entries, no addends */
    SHLIB = SHT_SHLIB,                 /* Reserved */
    DYNSYM = SHT_DYNSYM,               /* Dynamic linker symbol table */
    INIT_ARRAY = SHT_INIT_ARRAY,       /* Array of constructors */
    FINI_ARRAY = SHT_FINI_ARRAY,       /* Array of destructors */
    PREINIT_ARRAY = SHT_PREINIT_ARRAY, /* Array of pre-constructors */
    GROUP = SHT_GROUP,                 /* Section group */
    SYMTAB_SHNDX = SHT_SYMTAB_SHNDX    /* Extended section indeces */
  } value;

  ElfSectionType(uint32_t value);

  std::string toString() const;
};

std::ostream& operator<<(std::ostream& ost, const ElfSectionType& type);
