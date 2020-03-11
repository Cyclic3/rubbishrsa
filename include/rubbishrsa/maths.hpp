#pragma once

//! All the number theory goes in here

// The numeric backend is different between windows and unix:
#include <boost/multiprecision/gmp.hpp>

namespace rubbishrsa {
  // Saves me a lot of typing
  namespace bmp = boost::multiprecision;
  using bigint = bmp::mpz_int;

  // Extended Euclid's algorithm is the name of this algorithm (I think)
  struct egcd_result { bigint gcd; std::pair<bigint, bigint> coefficients; };
  egcd_result egcd(const bigint& a, const bigint& b);

  // This is actually implemented in the numeric library I have used, but that would be cheating
  /// Performs the Miller-Rabin primality check `certainty_log_2` times
  bool is_prime(const bigint& candidate, uint_fast8_t certainty_log_4 = 64);

  /// Generates a prime that is at least 2^(bits - 1) long.
  //
  // Apparently "strong primes" are better, but computing these is much harder, and RSA say they are unnecceary
  //
  // Because RSA (company) can be trusted. Yes.
  bigint generate_prime(uint_fast16_t bits);

  /// Calculate the lowest common multiple of two numbers
  bigint lcm(const bigint& a, const bigint& b);

  // Calculating Carmichael's function for an arbitrary number is complex and pointless
  //
  // Instead, we can just calculate it for our special case
  inline bigint carmichael_semiprime(const bigint& p, const bigint& q) {
    return lcm(p - 1, q - 1);
  }

  // Again, exists in our library, but I don't want to cheat
  /// Computes a^(-1) mod n
  bigint modinv(const bigint& a, const bigint& n);
}
