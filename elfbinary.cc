#include "elfbinary.h"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <range/v3/all.hpp>

using namespace std;

ElfBinary::ElfBinary() {}

ElfBinary::ElfBinary(Indent& indent) : Indentable(indent) {}

size_t ElfBinary::getSectionHeaderOffset() {
  return header.e_shoff;
}

size_t ElfBinary::getSectionHeaderCount() {
  return header.e_shnum;
}

size_t ElfBinary::getStringTableIndex() {
  return header.e_shstrndx;
}

istream& operator>>(istream& ist, ElfBinary& elf) {
  auto& hdr = elf.header;

  ist.seekg(0);
  ist.read((char*)&hdr, sizeof(Elf64_Ehdr));

  if (!ist)
    throw "failed to read complete Elf header";
  if (hdr.e_ident[0] != 0x7f || hdr.e_ident[1] != 'E' || hdr.e_ident[2] != 'L' || hdr.e_ident[3] != 'F')
    throw "magic string failed";
  return ist;
}

ostream& operator<<(ostream& ost, const ElfBinary& elf) {
  Indent& i = elf.indent;
  auto section_offset = elf.header.e_shoff;
  auto section_table_count = elf.header.e_shnum;
  auto section_table_index = elf.header.e_shstrndx;
  auto section_size = elf.header.e_shentsize;

  ost << i++ << "Elf {" << endl;
  ost << i << hex << "section header offset 0x" << section_offset << endl;
  ost << i << dec << "section header string table index: " << section_table_index << endl;
  ost << i << hex << "section table count: 0x" << section_table_count << endl;
  ost << i << "section entry size: 0x" << section_size << endl;
  ost << --i << "}" << endl;
  return ost;
}

meta::list<> ElfBinary::getSections(istream& ist) {
  auto section_table_count = header.e_shnum;
  ptrdiff_t section_offset = header.e_shoff;

  //cout << "getSections(" << dec << section_table_count << ", 0x" << hex << section_offset << ")" << endl;

  // special section for large numbers of headers
  Elf64_Shdr init;
  ist.seekg(section_offset);
  ist.read((char*)&init, sizeof(Elf64_Shdr));
  if (section_table_count == 0x0) {
    section_table_count = init.sh_size;
  }

  ist.seekg(section_offset);

  auto create = [](Elf64_Shdr& hdr) { return ElfSectionHeader(hdr); };
  auto view = streamview<Elf64_Shdr>(ist) 
    | ranges::views::transform(create);
    | ranges::views::take(section_table_count);
  return view;
}

// vector<string> ElfBinary::parseSectionNames(istream& ist) {
// const vector<char>& v = getSectionNames(ist);
// string buf;
// vector<string> section_names;
// for (char c : v) {
// buf += c;
// if (c == '\0') {
// section_names.push_back(buf);
// buf = "";
//}
//}
// return section_names;
//}

vector<char> ElfBinary::getSectionNames(istream& ist) {
  auto section_table_index = header.e_shstrndx;

  // needs to handle SHN_XINDEX

  auto headers = getSections(ist);

  const ElfSectionHeader& str_table = headers[section_table_index];
  auto offset = str_table.getOffset();
  auto size = str_table.getSize();

  ist.seekg(offset);
  vector<char> section_names(size);
  ist.read(section_names.data(), size);
  return section_names;
}

/*
 *using iter = ElfBinary::iter;
 *using value_type = ElfSectionHeader;
 *using difference_type = ptrdiff_t;
 *using pointer = ElfSectionHeader*;
 *using reference = ElfSectionHeader&;
 *using self = ElfBinary::iter;
 *
 *iter::iter(istream& ist, difference_type n) : i(ist, n) {}
 *
 *iter::iter(const iter& copy)
 *    : i(copy.i) {}
 *
 *iter::iter() {}
 *
 *value_type iter::operator*() const {
 *  return ElfSectionHeader(*i);
 *}
 *
 *value_type iter::operator[](difference_type n) const {
 *  return operator+(n).operator*();
 *}
 *
 *difference_type ElfBinary::iter::operator-(self const& rhs) {
 *  return i - rhs.i;
 *}
 *
 *self& iter::operator++() {
 *  ++i;
 *  return *this;
 *}
 *
 *self iter::operator++(int) {
 *  iter copy(*this);
 *  ++i;
 *  return copy;
 *}
 *
 *self& iter::operator--() {
 *  --i;
 *  return *this;
 *}
 *
 *self iter::operator--(int) {
 *  iter copy(*this);
 *  --i;
 *  return copy;
 *}
 *
 *self iter::operator+(difference_type n) const {
 *  iter copy(*this);
 *  copy += n;
 *  return copy;
 *}
 *
 *self iter::operator-(difference_type n) const {
 *  iter copy(*this);
 *  copy -= n;
 *  return copy;
 *}
 *
 *self& iter::operator+=(difference_type n) {
 *  i += n;
 *  return *this;
 *}
 *
 *self& iter::operator-=(difference_type n) {
 *  i -= n;
 *  return *this;
 *}
 *
 * // implement all the relative operators in terms of the delta
 *bool operator==(iter const& lhs, iter const& rhs) {
 *  return lhs - rhs == 0;
 *}
 *
 *bool operator!=(iter const& lhs, iter const& rhs) {
 *  return lhs - rhs != 0;
 *}
 *
 *bool operator<(iter const& lhs, iter const& rhs) {
 *  return lhs - rhs < 0;
 *}
 *
 *bool operator<=(iter const& lhs, iter const& rhs) {
 *  return lhs - rhs <= 0;
 *}
 *
 *bool operator>(iter const& lhs, iter const& rhs) {
 *  return lhs - rhs > 0;
 *}
 *
 *bool operator>=(iter const& lhs, iter const& rhs) {
 *  return lhs - rhs >= 0;
 *}
 */
