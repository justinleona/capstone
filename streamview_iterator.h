#pragma once

#include <iostream>
#include <iterator>

/**
 * Sentinel marks the end of the streamview
 */
class streamview_sentinel {
public:
  streamview_sentinel() = default;
};

/*
 * charstream iterator enhances istream_iterator by allowing random access across data.
 * This may incur additional loads from the underlying stream on dereference, so use with care!
 */
template <typename T>
class streamview_iterator {
 public:
  using iterator_category = std::random_access_iterator_tag;
  using value_type = T;
  using difference_type = ptrdiff_t;
  using pointer = T*;
  using reference = T&;
  using self = streamview_iterator;
  using sentinel = streamview_sentinel;

  // don't allow implicit conversions to iterator
  explicit streamview_iterator(std::istream&);
  streamview_iterator(const self& copy);
  ~streamview_iterator() = default;

  value_type operator*() const;
  value_type operator[](difference_type n) const;
  difference_type operator-(self const& rhs) const;

  self& operator++();
  self operator++(int);

  self& operator--();
  self operator--(int);

  self operator+(difference_type n) const;
  self operator-(difference_type n) const;

  self& operator+=(difference_type n);
  self& operator-=(difference_type n);

  bool operator==(const self& rhs) const;
  bool operator==(const sentinel& rhs) const;
 private:
  mutable std::istream* ist = NULL;
  const int64_t g; //original position of the stream
  difference_type i = 0; //current relative to start
};

// implement all the relative operators in terms of the delta
template <typename T>
bool operator!=(const streamview_iterator<T>& lhs, const streamview_iterator<T>& rhs) {
  return !(lhs == rhs);
}

template <typename T>
bool operator!=(const streamview_sentinel& lhs, const streamview_iterator<T>& rhs) {
  return !(lhs == rhs);
}

template <typename T>
bool operator!=(const streamview_iterator<T>& lhs, const streamview_sentinel& rhs) {
  return !(lhs == rhs);
}

template <typename T>
bool operator<(const streamview_iterator<T> & lhs, const streamview_iterator<T> & rhs) {
  return lhs - rhs < 0;
}

template <typename T>
bool operator<=(const streamview_iterator<T> & lhs, const streamview_iterator<T> & rhs) {
  return lhs - rhs <= 0;
}

template <typename T>
bool operator>(const streamview_iterator<T> & lhs, const streamview_iterator<T> & rhs) {
  return lhs - rhs > 0;
}

template <typename T>
bool operator>=(const streamview_iterator<T> & lhs, const streamview_iterator<T> & rhs) {
  return lhs - rhs >= 0;
}
