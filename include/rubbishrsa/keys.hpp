#pragma once

#include "rubbishrsa/maths.hpp"

namespace rubbishrsa {
  struct public_key {
    /// The public exponent
    bigint e = 65537; // Recommended numebr due to low hamming weight
    /// The product of the two primes
    bigint n;

    inline bigint raw_encrypt(const bigint& message) {
      // m^e (mod n) is the ciphertext
      //
      // The low hamming weight means fewer additions and multiplications
      // in binary modpow
      return bmp::powm(message, e, n);
    }
    inline bool raw_verify(const bigint& message, const bigint& signature) {
      // Note that this is the same as the encryption state, as $m^{k\lambda(n) + 1} \equiv m \pmod{n}$
      auto expected = bmp::powm(signature, e, n);
      // Only a valid signature would decrypt to the message
      return expected == message;
    }

    /// Write the key to the given stream
    //
    // This is not vritual, and so the private key can have a different impl safely
    void serialise(std::ostream&);
    /// Reads the key from the given stream
    static void deserialise(std::istream&);

    // C++ requires this for inhertiable classes
    virtual ~public_key() = default;
  };

  // Whilst we could derive the public key each time, that takes ages.
  // Instead, we can just inherit all the members of the public key
  struct private_key : public public_key {
    bigint d; /// The decryption modulus

    inline bigint raw_decrypt(const bigint& cyphertext) {
      // Again, $m^{k\lambda(n) + 1} \equiv m \pmod{n}$
      return bmp::powm(cyphertext, d, n);
    }
    inline bigint raw_sign(const bigint& message) {
      // This is, interestingly, exactly the same as decryption
      // as this is encrypting with the private key, so all people
      // with the public key can decrypt, but only one with the
      // private key can encrypt
      return bmp::powm(message, d, n);
    }

    /// Write the key to the given stream
    void serialise(std::ostream&);
    /// Reads the key from the given stream
    static void deserialise(std::istream&);

    static private_key generate(uint_fast16_t bits);
  };
}
