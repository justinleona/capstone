#pragma once

#include <iostream>
#include <vector>
#include "elfbinary.h"
#include "elfsectionheader.h"
#include "indent.h"

class ElfSectionHeaders : public Indentable {
  const ElfBinary& bin;
  std::vector<ElfSectionHeader> sections;
 public:
  using const_iterator = std::vector<ElfSectionHeader>::const_iterator;

  ElfSectionHeaders(const ElfBinary& bin);
  ElfSectionHeaders(const ElfBinary& bin, Indent& indent);

  /* range of sections, starting with the special "init" section */
  const_iterator begin() const;
  const_iterator end() const;

  friend std::ostream& operator<<(std::ostream& ost, const ElfSectionHeaders&);
  friend std::istream& operator>>(std::istream& ist, ElfSectionHeaders&);
};
