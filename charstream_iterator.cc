#include "charstream_iterator.h"

using namespace std;

template <typename T>
using value_type = T;
template <typename T>
using difference_type = ptrdiff_t;
template <typename T>
using pointer = T*;
template <typename T>
using reference = T&;
template <typename T>
using self = charstream_iterator<T>;

template <typename T>
charstream_iterator<T>::charstream_iterator(std::istream& ist, difference_type n) : ist(&ist), g(ist.tellg()), n(n) {}

template <typename T>
charstream_iterator<T>::charstream_iterator(const charstream_iterator& copy)
    : ist(copy.ist), g(copy.g), i(copy.i), n(copy.n) {}

template <typename T>
charstream_iterator<T>::charstream_iterator() {}

template <typename T>
value_type<T> charstream_iterator<T>::operator*() const {
  if (n <= i)
    throw "read past end of charstream<T>";

  int64_t s = sizeof(value_type);
  int64_t curr = g + i * s;
  if (curr != ist->tellg()) {
    ist->seekg(curr);
  }

  cout << "get(0x" << hex << curr << ")" << endl;

  value_type t;
  ist->read((char*)&t, sizeof(value_type));
  return t;
}

template <typename T>
value_type<T> charstream_iterator<T>::operator[](difference_type n) const {
  return operator+(n).operator*();
}

template <typename T>
difference_type<T> charstream_iterator<T>::operator-(self const& rhs) const {
  return i - rhs.i;
}

template <typename T>
self<T>& charstream_iterator<T>::operator++() {
  ++i;
  return *this;
}

template <typename T>
self<T> charstream_iterator<T>::operator++(int) {
  charstream_iterator<T> copy(*this);
  ++i;
  return copy;
}

template <typename T>
self<T>& charstream_iterator<T>::operator--() {
  --i;
  return *this;
}

template <typename T>
self<T> charstream_iterator<T>::operator--(int) {
  charstream_iterator<T> copy(*this);
  --i;
  return copy;
}

template <typename T>
self<T> charstream_iterator<T>::operator+(difference_type n) const {
  charstream_iterator<T> copy(*this);
  copy += n;
  return copy;
}

template <typename T>
self<T> charstream_iterator<T>::operator-(difference_type n) const {
  charstream_iterator<T> copy(*this);
  copy -= n;
  return copy;
}

template <typename T>
self<T>& charstream_iterator<T>::operator+=(difference_type n) {
  i += n;
  return *this;
}

template <typename T>
self<T>& charstream_iterator<T>::operator-=(difference_type n) {
  i -= n;
  return *this;
}

#include <elf.h>

// force linking for these types
template class charstream_iterator<Elf64_Shdr>;
