#include "streamview_iterator.h"

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
using self = streamview_iterator<T>;
using sentinel = streamview_sentinel;

template <typename T>
streamview_iterator<T>::streamview_iterator(std::istream& ist)
    : ist(&ist), g(ist.tellg()), i(0) {
  // cout << "streamview_iterator " << ist.tellg() << endl;
}

template <typename T>
streamview_iterator<T>::streamview_iterator(const streamview_iterator& copy)
    : ist(copy.ist), g(copy.g), i(copy.i) {
  // cout << "streamview_iterator copy " << ist->tellg() << endl;
}

template <typename T>
value_type<T> streamview_iterator<T>::operator*() const {
  int64_t s = sizeof(value_type);
  int64_t curr = g + i * s;
  if (curr != ist->tellg()) {
    ist->seekg(curr);
  }

  // cout << hex << g << "," << n << endl;
  // cout << "get(0x" << hex << curr << ")" << endl;

  value_type t;
  ist->read((char*)&t, sizeof(value_type));
  return t;
}

template <typename T>
value_type<T> streamview_iterator<T>::operator[](difference_type n) const {
  return operator+(n).operator*();
}

template <typename T>
difference_type<T> streamview_iterator<T>::operator-(self const& rhs) const {
  //only allow for comparable iterators
  if (ist == rhs.ist) {
    return i - rhs.i;
  }
  throw "cannot difference iterators across different streams!";
}

template <typename T>
bool streamview_iterator<T>::operator==(const self& rhs) const {
  //match equal iterators on equivalent streams
  if (ist == rhs.ist )
    return ist;
  return false;
}

template <typename T>
bool streamview_iterator<T>::operator==(const sentinel& rhs) const {
  return ist;
}

template <typename T>
self<T>& streamview_iterator<T>::operator++() {
  ++i;
  return *this;
}

template <typename T>
self<T> streamview_iterator<T>::operator++(int) {
  streamview_iterator<T> copy(*this);
  ++i;
  return copy;
}

template <typename T>
self<T>& streamview_iterator<T>::operator--() {
  --i;
  return *this;
}

template <typename T>
self<T> streamview_iterator<T>::operator--(int) {
  streamview_iterator<T> copy(*this);
  --i;
  return copy;
}

template <typename T>
self<T> streamview_iterator<T>::operator+(difference_type n) const {
  streamview_iterator<T> copy(*this);
  copy += n;
  return copy;
}

template <typename T>
self<T> streamview_iterator<T>::operator-(difference_type n) const {
  streamview_iterator<T> copy(*this);
  copy -= n;
  return copy;
}

template <typename T>
self<T>& streamview_iterator<T>::operator+=(difference_type n) {
  i += n;
  return *this;
}

template <typename T>
self<T>& streamview_iterator<T>::operator-=(difference_type n) {
  i -= n;
  return *this;
}

#include <elf.h>

// force linking for these types
template class streamview_iterator<Elf64_Shdr>;
