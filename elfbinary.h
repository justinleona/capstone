#pragma once

#include <elf.h>
#include <istream>
#include <ostream>
#include <string>
#include <vector>
#include "elfsectionheader.h"
#include "indent.h"

class ElfBinary : public Indentable {
  Elf64_Ehdr header;

 public:
  ElfBinary();
  ElfBinary(Indent& indent);

  size_t getSectionHeaderOffset();
  size_t getSectionHeaderCount();
  size_t getStringTableIndex();

  std::vector<ElfSectionHeader> getSections(std::istream& ist);

  /** get the raw section names table including embedded null terminators */
  std::vector<char> getSectionNames(std::istream& ist);

  /** split the section names table into individual strings */
  std::vector<std::string> parseSectionNames(std::istream& ist);

  friend std::ostream& operator<<(std::ostream& ost, const ElfBinary& header);
  friend std::istream& operator>>(std::istream& ist, ElfBinary& header);
};
