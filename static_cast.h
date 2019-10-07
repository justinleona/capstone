#pragma once

template <typename T>
struct static_cast_f {
  template <typename U>
  T operator()(const U& rhs) {
    return static_cast<T>(rhs);
  }
};
