#pragma once

#include <elf.h>
#include <ostream>
#include <istream>
#include <vector>
#include <string>
#include "elfsectionheader.h"

class ElfBinary {
  Elf64_Ehdr header;
public:
  std::vector<ElfSectionHeader> getSections(std::istream& ist);
  std::vector<std::string> getSectionNames(std::istream& ist);
  
  friend std::ostream& operator<<(std::ostream& ost,const ElfBinary& header);
  friend std::istream& operator>>(std::istream& ist,ElfBinary& header);
};
