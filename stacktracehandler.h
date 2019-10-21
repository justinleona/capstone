#pragma once

class StackTraceHandler {
 public:
  StackTraceHandler();
  ~StackTraceHandler();

  static void printTrace();
};
