#pragma once

#include <elf.h>
#include <istream>
#include <iterator>
#include <ostream>
#include <string>
#include <vector>
#include "indent.h"
#include "elfsectionheader.h"
#include "streamview.h"
#include <range/v3/all.hpp>

class ElfBinary : public Indentable {
  Elf64_Ehdr header;

 public:
  ElfBinary();
  ElfBinary(Indent& indent);

  size_t getSectionHeaderOffset();
  size_t getSectionHeaderCount();
  size_t getStringTableIndex();

  /* range of sections, starting with the special "init" section */
  streamview<Elf64_Shdr> getSections(std::istream& ist);

  /** get the raw section names table including embedded null terminators */
  std::vector<char> getSectionNames(std::istream& ist);

  friend std::ostream& operator<<(std::ostream& ost, const ElfBinary& header);
  friend std::istream& operator>>(std::istream& ist, ElfBinary& header);
};
