//! A simple system to toggle logging
#include <iostream>

// The idea is to have code that is only compiled and executed when logging is enabled
//
// This means that when it is disabled, there is no overhead, but when it is enabled,
// I can be as verbose and slow as I like.

#if RUBBISHRSA_VERBOSITY >= 2
#define RUBBISHRSA_LOG_TRACE(...) __VA_ARGS__
#else
#define RUBBISHRSA_LOG_TRACE(...)
#endif


#if RUBBISHRSA_VERBOSITY >= 1
#define RUBBISHRSA_LOG_INFO(...) __VA_ARGS__
#else
#define RUBBISHRSA_LOG_INFO(...)
#endif
