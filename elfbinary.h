#pragma once

#include <elf.h>
#include <iostream>
#include "indent.h"
//#include <range/v3/all.hpp>

class ElfBinary : public Indentable {
  Elf64_Ehdr header;
 public:
  ElfBinary();
  ElfBinary(Indent& indent);

  size_t getSectionHeaderOffset() const;
  size_t getSectionHeaderCount() const;
  size_t getStringTableIndex() const;

  friend std::ostream& operator<<(std::ostream& ost, const ElfBinary& header);
  friend std::istream& operator>>(std::istream& ist, ElfBinary& header);
};
