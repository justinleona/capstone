#include "elfsectionheader.h"

using namespace std;

uint64_t ElfSectionHeader::getOffset() const {
  return hdr.sh_offset;
}

uint64_t ElfSectionHeader::getSize() const {
  return hdr.sh_size;
}

Elf64_Word ElfSectionHeader::getNameIndex() const {
  return hdr.sh_name;
}

ostream& operator<<(ostream& ist, const ElfSectionHeader& header) {
  ist << "string table index: " << header.getNameIndex() << endl;
  return ist;
}

ElfSectionHeader ElfSectionHeader::create(const Elf64_Shdr& hdr) {
  return ElfSectionHeader(hdr);
}
