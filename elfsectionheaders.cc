#include "elfsectionheaders.h"

using namespace std;
using const_iterator = ElfSectionHeaders::const_iterator;

ElfSectionHeaders::ElfSectionHeaders(const ElfBinary& bin) : bin(bin) {}

ElfSectionHeaders::ElfSectionHeaders(const ElfBinary& bin, Indent& indent) : Indentable(indent), bin(bin) {}

const_iterator ElfSectionHeaders::begin() const {
  return sections.begin();
}

const_iterator ElfSectionHeaders::end() const {
  return sections.end();
}

ostream& operator<<(ostream& ost, const ElfSectionHeaders& headers) {
  for (const ElfSectionHeader& h : headers.sections)
    ost << h;
  return ost;
}

istream& operator>>(istream& ist, ElfSectionHeaders& headers) {
  auto section_table_count = headers.bin.getSectionHeaderCount();
  auto section_offset = headers.bin.getSectionHeaderOffset();
  auto section_table_index = headers.bin.getStringTableIndex();
  vector<ElfSectionHeader>& sections = headers.sections;

  cout << "operator>>(headers)" << endl;
  cout << headers.bin;

  ist.seekg(section_offset);
  if (!ist.good())
    throw "end of stream encountered before init header";

  ElfSectionHeader init;
  ist >> init;
  if (section_table_count == 0x0)
    section_table_count = init.getSize();
  sections.push_back(init);

  for (uint64_t i = 1; i < section_table_count; ++i) {
    ElfSectionHeader s;
    ist >> s;
    sections.push_back(s);
  }
  if (!ist.good())
    throw "failed to read section headers";

  // needs to handle SHN_XINDEX
  const ElfSectionHeader& str_table = sections.at(section_table_index);
  auto offset = str_table.getOffset();
  auto size = str_table.getSize();

  cout << "str_table: " << str_table;

  // read the names table and parse them into the headers
  char names[size];
  ist.seekg(offset);
  ist.read(names, size);
  if (!ist.good())
    throw "failed to read section names table";

  for (ElfSectionHeader& s : sections) {
    auto index = s.getNameIndex();
    if (index >= size) {
      cerr << index << endl;
      throw "invalid name index";
    }
    string name(&names[index]);
    s.setName(name);
  }
  return ist;
}

// vector<string> ElfSectionHeaders::getSectionNames() {
// string buf;
// vector<string> section_names;
// for (char c : names) {
// buf += c;
// if (c == '\0') {
// section_names.push_back(buf);
// buf = "";
//}
//}
// return section_names;
//}
