#pragma once

#include <memory>

//credit to stackoverflow q 27440953 for this idea
//avoids overhead on the unique_ptr itself
struct free_deleter {
  template <typename T> 
    void operator()(T *p) const {
      std::free(const_cast<std::remove_const_t<T>*>(p));
    }
};

//note you must specify the array qualifier to use it later - e.g.,
//unique_cptr<char *[]> instead of unique_cptr<char*>
template<typename T>
using unique_cptr=std::unique_ptr<T,free_deleter>;
