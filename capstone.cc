#include "capstone.h"
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>

using namespace std;
using namespace std::placeholders;

Capstone::Capstone(csh handle, const uint8_t* code, size_t size, uint64_t address) {
  this->handle = handle;
  this->code = code;
  this->size = size;
  this->address = address;
}

Capstone::~Capstone() {
  cs_close(&handle);
}

/* discard the consts here to match the vendor signature */
Capstone::const_iterator::const_iterator(const Capstone& c)
    : handle(c.handle),
      insn(cs_malloc(c.handle)),
      code(const_cast<const uint8_t*>(c.code)),
      size(c.size),
      address(c.address) {}

Capstone::const_iterator::const_iterator() : handle(0), insn(NULL), code(NULL), size(0), address(0) {}

/* copy will allocate additional memory */
Capstone::const_iterator::const_iterator(const const_iterator& c)
    : handle(c.handle), insn(cs_malloc(c.handle)), code(c.code), size(c.size), address(c.address) {}

Capstone::const_iterator::~const_iterator() {
  if (insn) {
    cs_free(insn, 1);
    insn = NULL;
  }
}

const cs_insn& Capstone::const_iterator::operator*() const {
  return *insn;
}

Capstone::const_iterator& Capstone::const_iterator::operator++() {
  if (size == 0) {
    code = NULL;
    return *this;
  }

  // cout << "cs_disasm_iter(" << hex << handle << "," << (unsigned int)*code << "," << size << "," << address << ")" <<
  // endl;
  bool i_sz = cs_disasm_iter(handle, &code, &size, &address, insn);

  // if it fails, reset to end()
  if (!i_sz) {
    size = 0;
    code = NULL;
  }
  return *this;
}

/* postfix is notably less efficient since it allocates a cs_insn each time */
Capstone::const_iterator Capstone::const_iterator::operator++(int) {
  const_iterator old(*this);
  operator++();
  return old;
}

long operator-(Capstone::const_iterator const& lhs, Capstone::const_iterator const& rhs) {
  return lhs.code - rhs.code;
}

bool operator==(Capstone::const_iterator const& lhs, Capstone::const_iterator const& rhs) {
  return lhs.code == rhs.code && lhs.size == rhs.size;
}

bool operator!=(Capstone::const_iterator const& lhs, Capstone::const_iterator const& rhs) {
  return !(lhs == rhs);
}

Capstone::const_iterator Capstone::begin() const {
  return Capstone::const_iterator(*this);
}

Capstone::const_iterator Capstone::end() const {
  return Capstone::const_iterator();
}
