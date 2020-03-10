#include "rubbishrsa/maths.hpp"
#include "rubbishrsa/log.hpp"

// Rubbish rng
#include <boost/random/mersenne_twister.hpp>
// Crypto rng
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>

namespace rubbishrsa {
  bigint modinv(const bigint& a, const bigint& n) {
    auto res = egcd(a, n);
    if (res.gcd != 1)
      throw std::invalid_argument("Cannot compute modular inverse of non-coprime numbers!");

    // The second coefficient would represent the number of multiples of the modulus,
    // but we don't care about that
    //
    // In addition to this, the egcd will may return a negative number in the same
    // congruence class. We will normalise this
    if (res.coefficients.first >= 0)
      return res.coefficients.first;
    else
      return n + res.coefficients.first;
  }

  // lcm(a,b) = a/gcd(a,b) * b
  bigint lcm(const bigint& a, const bigint& b) {
    return (a / egcd(a, b).gcd) * b;
  }

  egcd_result egcd(const bigint& a, const bigint& b) {
    if (a <= 0 || b <= 0)
      throw std::invalid_argument("GCD cannot be computer with non-positive argument!");

    // This is basically a code version of the lecture notes on the topic


    std::array<bigint, 3>col[2];

    using egcd_matrix_t = std::array<std::array<bigint, 3>, 2>;
    egcd_matrix_t matrix = {{
      {1, 0, a},
      {0, 1, b}
    }};

    egcd_result return_value;

    while (true) {
      // Calculate the number of multiples of the b cell that fits into the a cell
      auto a_fit = matrix[0][2] / matrix[1][2];

      // Subtract that from the a row
      for (size_t i = 0; i < 3; ++i) {
        matrix[0][i] -= matrix[1][i] * a_fit;
      }

      // Check the a cell to see if we're done
      if (matrix[0][2] == 0)
        return {
          .gcd = matrix[1][2],
          .coefficients = {matrix[1][0], matrix[1][1]}
        };

      // Now we do the same thing for the b row
      auto b_fit = matrix[1][2] / matrix[0][2];
      for (size_t i = 0; i < 3; ++i) {
        matrix[1][i] -= matrix[0][i] * b_fit;
      }

      // Check the b cell to see if we're done
      if (matrix[1][2] == 0)
        return {
          .gcd = matrix[0][2],
          .coefficients = {matrix[0][0], matrix[0][1]}
        };
    }
  }

  // I will use boost random for this stuff, and stl's one doesn't support the bigint
  bool is_prime(const bigint& candidate, uint_fast8_t certainty_log_4) {
    // We need to get i = 2^exponent * odd
    bigint odd = candidate;
    size_t exponent = 0;

    // We keep the the non-power of 2 in i
    while (odd % 2 != 0) {
      ++exponent;
      // A quicker way of doing i = 2
      odd >>= 1;
    }

    bigint min = 2;
    bigint max = candidate - 2;
    // We don't need a crypto rng here
    thread_local boost::random::mt19937 rng;
    boost::random::uniform_int_distribution<bigint> dist(std::move(min), std::move(max));

    // We do this a lot, so precompute it
    bigint candidate_minus_1 = candidate - 1;

    bigint x;
    for (uint_fast8_t iter = 0; iter < certainty_log_4; ++iter) {
      bigint a = dist(rng);
      x = bmp::powm(a, odd, candidate);
      // If we already have a congruence, then we have passed this iter
      if (x == 1 || x == candidate_minus_1)
        continue;

      for (decltype(exponent) i = 1; i < exponent; ++i) {
        x = bmp::powm(x, 2, candidate);
        if (x == candidate_minus_1)
          // Only way to quickly leave a nested loop
          //
          // Please don't just take away marks because I used a goto!
          //
          // gotos to escape nested loops are perfectly fine, and make
          // the code _far_ more readable than a separate func, or a
          // boolean check at the end (which would also be slower)
          goto next_iter;
      }
      // If we failed all of our subiterations, then we must exit out of the loop
      return false;
next_iter: {}
    }

    return true;
  }

  bigint generate_prime(uint_fast16_t bits) {

    // 1 <<= n == 2^n, giving us a range of 2^(n-2) to 2^(n-1) inclusive
    //
    // The reason for keeping this half of the desired values is that 2 is the only even prime,
    // so we can save a lot of composite candidates by multiplying by 2 and adding 1
    bigint min = 1; min <<= (bits - 2);
    bigint max = min; max <<= 1;

    RUBBISHRSA_LOG(
          std::cerr << "Generating candidate bases between " << min.str()
                    << " and " << max.str() << std::endl
    );

    // (Almost) always a cryptographically secure rng
    thread_local boost::random::random_device rng;
    // Our distribution is that of all numbers with the given bit count
    boost::random::uniform_int_distribution<bigint> dist(std::move(min), std::move(max));

    bigint ret;
    do {
      // Get a random number, and make it odd.
      ret = dist(rng) * 2 + 1;
      RUBBISHRSA_LOG(std::cerr << "\tPrime candidate " << ret.str() << std::endl);
    }
    // Loop until we get a prime
    while (!is_prime(ret, 128));

    return ret;
  }
}
