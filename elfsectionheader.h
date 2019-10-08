#pragma once

#include <elf.h>
#include <ostream>
#include <string>

class ElfSectionHeader {
  const Elf64_Shdr& hdr;

 public:
  ElfSectionHeader(const Elf64_Shdr& hdr) : hdr(hdr) {}

  static ElfSectionHeader create(const Elf64_Shdr& hdr);

  Elf64_Xword getSize() const;
  Elf64_Off getOffset() const;
  Elf64_Word getNameIndex() const;
};

std::ostream& operator<<(std::ostream& ist, const ElfSectionHeader& header);
