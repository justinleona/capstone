#include "indent.h"

Indent& Indent::operator++() {
  ++level;
  return *this;
}

Indent& Indent::operator--() {
  if (level > 0)
    --level;
  return *this;
}

Indent Indent::operator++(int) {
  auto old = *this;
  ++*this;
  return old;
}

Indent Indent::operator--(int) {
  auto old = *this;
  --*this;
  return old;
}

void Indent::setLevel(int level) {
  this->level = level;
}

void Indent::setIncrement(int inc) {
  this->inc = inc;
}

void Indent::setCharacter(char c) {
  this->c = c;
}

int Indent::getLevel() const {
  return level;
}

int Indent::getIncrement() const {
  return inc;
}

char Indent::getCharacter() const {
  return c;
}

void Indent::reset() {
  level = 0;
}

std::ostream& operator<<(std::ostream& ost, const Indent& val) {
  for (int i = 0; i != val.getLevel(); i++)
    for (int j = 0; j != val.getIncrement(); ++j)
      ost << val.getCharacter();
  return ost;
}

std::ostream& operator<<(std::ostream& ost, const ScopedIndent& val) {
  return ost << val.indent;
}

ScopedIndent::ScopedIndent(Indent& indent) : indent(indent) {
  ++indent;
}

ScopedIndent::~ScopedIndent() {
  --indent;
}

Indentable::Indentable() : indent() {}

Indentable::Indentable(Indent& indent) : indent(indent) {}
