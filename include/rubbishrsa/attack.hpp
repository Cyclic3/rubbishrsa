//! Sone functions to perform some attacks on RSA

#pragma once

#include "rubbishrsa/keys.hpp"

#include <functional>
#include <ios>
#include <optional>

namespace rubbishrsa::attack {
  /// Derives the result of encrypting the product of the unknown plaintext and the given value (mod n)
  //
  // Takes advantage of the homomorphic property of unpadded RSA
  inline bigint enc_multiply(const public_key& pubkey, const bigint& encrypted_message, const bigint& value) {
    return (pubkey.raw_encrypt(value) * encrypted_message) % pubkey.n;
  }

  /// Forges a signature of the product of the two signed pieces of data (mod n)
  //
  // Again uses the homomorphic property, but since we cannot create arbitrary signatures, we need two real ones
  inline bigint sig_forge_multiply(const public_key& pubkey, const bigint& sig_1, const bigint& sig_2) {
    return (sig_1 * sig_2) % pubkey.n;
  }

  // Returns true if the given char is invisible
  bool is_invisible(char);

  /// Attempt to factorise the key
  private_key crack_key(const public_key& pubkey);

  /// Exploits the lack of semantic security in textbook RSA
  ///
  /// @param get_next_candidate: A function that returns a new candidate, or std::nullopt if the space is exhausted.
  ///                            Be aware that this may be accessed concurrently, and so should be thread safe.
  ///                            It will be passed the thread count and the thread id
  ///
  /// @returns the plaintext that encrypts to encrypted_message or std::nullopt if no matching plaintext was found
  //
  // With textbook RSA, two encryptions of any given plaintexts are the same,
  // and so, given a brute forcible plaintext space, we can work out what the
  // plaintext was
  std::optional<bigint> brute_force_ptext(const public_key& pubkey, const bigint& encrypted_message,
                                          std::function<std::optional<bigint>(unsigned int)> get_next_candidate,
                                          unsigned int thread_count = 0);

  /// A simple wrapper that brute forces with all the plaintexts in a file, with the given delimiter (defaults to a newline)
  ///
  /// @param convert_str_to_num If false, the entries in the file will be treated as a hexadecimal number,
  ///                           as opposed to text to be converted
  std::optional<bigint> brute_force_ptext(const public_key& pubkey, const bigint& encrypted_message,
                                          std::istream& in, char delim = '\n', bool convert_hex_to_num = false);

  /// A simple wrapper that brute forces with all the plaintexts between two numbers (inclusive)
  std::optional<bigint> brute_force_ptext(const public_key& pubkey, const bigint& encrypted_message,
                                          const bigint& min, const bigint& max);

  /// Attempt to brute force the space to find a valid signature.
  ///
  /// This can be used to
  ///
  /// @param check_result: A function that returns true if a valid result was found. Will be run in parallel
  std::optional<bigint> brute_force_sig(const public_key& pubkey, std::function<bool(const bigint&)> check_result);

  std::optional<bigint> brute_force_sig_invis(const public_key& pubkey, bigint msg);
}
