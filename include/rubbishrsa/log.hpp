//! A simple system to toggle logging
#include <iostream>

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
