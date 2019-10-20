#include "elfsectionheader.h"
#include <iomanip>
#include "indent.h"

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

ElfSectionType ElfSectionHeader::getType() const {
  return ElfSectionType(hdr.sh_type);
}

Elf64_Xword ElfSectionHeader::getFlags() const {
  return hdr.sh_flags;
}

bool ElfSectionHeader::isNull() const {
  return hdr.sh_type & SHT_NULL;
}

bool ElfSectionHeader::isSymbolTable() const {
  return hdr.sh_type & SHT_SYMTAB;
}

bool ElfSectionHeader::isDynamicSymbolTable() const {
  return hdr.sh_type & SHT_DYNSYM;
}

bool ElfSectionHeader::isStringTable() const {
  return hdr.sh_type & SHT_STRTAB;
}

bool ElfSectionHeader::isRelocationTable() const {
  return hdr.sh_type & SHT_RELA;
}

bool ElfSectionHeader::isDynamic() const {
  return hdr.sh_type & SHT_DYNAMIC;
}

bool ElfSectionHeader::isWritable() const {
  return hdr.sh_flags & SHF_WRITE;
}

bool ElfSectionHeader::isExecutable() const {
  return hdr.sh_flags & SHF_EXECINSTR;
}

void ElfSectionHeader::setName(const string& str) 
{
  this->n = str;
}

const string& ElfSectionHeader::name() const {
  return n;
}

ostream& operator<<(ostream& ost, const ElfSectionHeader& h) {
  Indent& i = h.indent;
  ost << i++ << "Elf Section Header {" << endl;
  ost << i << "name index: " << dec << h.getNameIndex() << endl;
  ost << i << "type: " << h.getType() << endl;
  ost << i << "size: 0x" << hex << setfill('0') << setw(16) << h.getSize() << endl;
  ost << i << "offset: 0x" << hex << setfill('0') << setw(16) << h.getOffset() << endl;
  return ost << --i << "}" << endl;
}

istream& operator>>(istream& ist, ElfSectionHeader& hdr) {
 ist.read((char*)&hdr.hdr, sizeof(Elf64_Shdr));
 return ist;
}
