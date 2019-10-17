#pragma once

#include <iostream>
#include <iterator>
#include <range/v3/view/interface.hpp>
#include "streamview_iterator.h"

/**
 * Compose stream objects to allow pulling objecst off the stream with iterators
 */
template <typename T>
class streamview : public ranges::view_interface<T> {
 public:
  using value_type = T;
  using difference_type = ptrdiff_t;
  using pointer = T*;
  using reference = T&;
  using const_reference = T&;
  using iterator = streamview_iterator<T>;
  using const_iterator = streamview_iterator<T>;
  using sentinel = streamview_sentinel;

  explicit streamview(std::istream&) : ist(&ist) {}

  /**
   * Multiple iterators can operate on a stream, but may result in lots of seeks.  Any iterator
   * reaching the end will close the stream for all consumers.
   */
  const_iterator begin() const {
    return streamview_iterator<T>(ist);
  }

  sentinel end() const {
    return sentinel();
  }
 private:
  mutable std::istream* ist = NULL;
};

