#pragma once

#include <elf.h>
#include <ostream>
#include <istream>
#include <vector>
#include <string>

class ElfBinary {
  Elf64_Ehdr header;
public:
  /** 
   * Use the Elf header to read the section names from a stream of bytes 
   */
  std::vector<std::string> getSectionNames(std::istream& ist);
  
  friend std::ostream& operator<<(std::ostream& ost,const ElfBinary& header);
  friend std::istream& operator>>(std::istream& ist,ElfBinary& header);
};
