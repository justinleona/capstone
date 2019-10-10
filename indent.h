#pragma once

#include <ostream>

class Indent {
  int level;
  int inc;
  char c;

 public:
  Indent() : level(0), inc(2), c(' '){};

  // prefix operator
  Indent& operator++();
  Indent& operator--();

  // postfix operator
  Indent operator++(int);
  Indent operator--(int);

  void reset();

  void setLevel(int level);
  void setIncrement(int inc);
  void setCharacter(char c);

  int getLevel() const;
  int getIncrement() const;
  char getCharacter() const;
};

std::ostream& operator<<(std::ostream& ost, const Indent& val);

/**
 * Update indents while this object is in scope
 */
class ScopedIndent {
  Indent& indent;

 public:
  ScopedIndent(Indent& indent);
  ~ScopedIndent();
  
  friend std::ostream& operator<<(std::ostream& ost, const ScopedIndent& val);
};

/**
 * classes implement indentable
 */
class Indentable {
 protected:
  Indentable();
  Indentable(Indent& indent);
 public:
  mutable Indent indent;
};
