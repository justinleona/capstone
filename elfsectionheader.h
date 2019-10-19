#pragma once

#include <elf.h>
#include <ostream>
#include <string>
#include <vector>
#include "indent.h"
#include "elfsectiontype.h"

class ElfSectionHeader : public Indentable {
  Elf64_Shdr hdr;
 public:
  ElfSectionHeader() {}
  ElfSectionHeader(const Elf64_Shdr& hdr) : hdr(hdr) {}

  Elf64_Xword getSize() const;
  Elf64_Off getOffset() const;
  Elf64_Word getNameIndex() const;
  ElfSectionType getType() const;
  Elf64_Xword getFlags() const;

  // characteristics defined by the type and flags
  bool isNull() const;
  bool isSymbolTable() const;
  bool isDynamicSymbolTable() const;
  bool isStringTable() const;
  bool isRelocationTable() const;
  bool isDynamic() const;
  bool isWritable() const;
  bool isExecutable() const;

  friend std::ostream& operator<<(std::ostream& ist, const ElfSectionHeader&);
  friend std::istream& operator>>(std::istream& ist, ElfSectionHeader& hdr);
};
