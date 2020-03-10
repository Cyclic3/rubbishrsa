//! A simple system to toggle logging
#include <iostream>

#ifdef RUBBISHRSA_VERBOSE
#define RUBBISHRSA_LOG(...) __VA_ARGS__
#else
#define RUBBISHRSA_LOG(PARAM...)
#endif
