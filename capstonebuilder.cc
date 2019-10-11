#include "capstonebuilder.h"
#include <string>

using namespace std;

CapstoneBuilder::CapstoneBuilder() {}

CapstoneBuilder& CapstoneBuilder::setArchitecture(cs_arch arch) {
  this->arch = arch;
  return *this;
}

CapstoneBuilder& CapstoneBuilder::setMode(cs_mode mode) {
  this->mode = mode;
  return *this;
}

CapstoneBuilder& CapstoneBuilder::setAtt(bool att) {
  this->att = att;
  return *this;
}

CapstoneBuilder& CapstoneBuilder::setAddress(uint64_t address) {
  this->address = address;
  return *this;
}

Capstone CapstoneBuilder::operator()(const uint8_t* code, size_t size) {
  size_t handle;
  cs_err err = cs_open(arch, mode, &handle);
  if (err != CS_ERR_OK)
    throw string(cs_strerror(err));
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  if (att)
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
  return Capstone(handle, code, size, address);
}
