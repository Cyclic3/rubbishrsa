#include "rubbishrsa/maths.hpp"
#include "rubbishrsa/log.hpp"

// Rubbish rng
#include <boost/random/mersenne_twister.hpp>
// Crypto rng
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>

#include <atomic>
#include <thread>

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

  using egcd_matrix_t = std::array<std::array<bigint, 3>, 2>;

  // Pretty-prints the array
  void egcd_log_matrix(const egcd_matrix_t& state) {
    std::array<std::array<std::string, 3>, 2> string_matrix;
    std::array<size_t, 3> max_len = { 0, 0, 0 };
    // Pass 1: get the maximum length, and generate the strings
    for (size_t row_i = 0; row_i < 2; ++row_i) {
      for (size_t column_i = 0; column_i < 3; ++column_i) {
        auto& res = (string_matrix[row_i][column_i] = state[row_i][column_i].str());
        auto& target = max_len[column_i];
        if (res.size() > target)
          target = res.size();
      }
    }

    std::cerr << "| "
              << std::setw(max_len[0]) << string_matrix[0][0] << "  "
              << std::setw(max_len[1]) << string_matrix[0][1]
              << " | " << std::setw(max_len[2]) << string_matrix[0][2] << " |"
              << std::endl
              << "| "
              << std::setw(max_len[0]) << string_matrix[1][0] << "  "
              << std::setw(max_len[1]) << string_matrix[1][1]
              << " | " << std::setw(max_len[2]) << string_matrix[1][2] << " |"
              << std::endl
              << std::endl;
  }

  egcd_result egcd(const bigint& a, const bigint& b) {
    // This is basically a code version of the lecture notes on the topic

    RUBBISHRSA_LOG_TRACE(std::cerr << "Calculating GCD of " << a.str() << " and " << b.str() << std::endl);

    if (a <= 0 || b <= 0)
      throw std::invalid_argument("GCD cannot be computed with non-positive argument!");

    std::array<bigint, 3>col[2];


    egcd_matrix_t matrix = {{
      {1, 0, a},
      {0, 1, b}
    }};

    RUBBISHRSA_LOG_TRACE(egcd_log_matrix(matrix));

    egcd_result return_value;

    while (true) {
      // Calculate the number of multiples of the b cell that fits into the a cell
      auto a_fit = matrix[0][2] / matrix[1][2];

      // Subtract that from the a row
      for (size_t i = 0; i < 3; ++i) {
        matrix[0][i] -= matrix[1][i] * a_fit;
      }

      RUBBISHRSA_LOG_TRACE(egcd_log_matrix(matrix));

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

      RUBBISHRSA_LOG_TRACE(egcd_log_matrix(matrix));

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
    // This in an implementation of the Miller-Rabin probabilistic primality test
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
    const boost::random::uniform_int_distribution<bigint> dist(std::move(min), std::move(max));

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
    // (1 << n) means 2^n, giving us a range of 2^(n-2) to 2^(n-1) inclusive
    //
    // The reason for keeping this half of the desired values is that 2 is the only even prime,
    // so we can save a lot of composite candidates by multiplying by 2 and adding 1
    bigint min = 1; min <<= (bits - 2);
    bigint max = min; max <<= 1;

    RUBBISHRSA_LOG_TRACE(
          std::cerr << "Generating prime candidate bases between " << min.str()
                    << " and " << max.str() << std::endl
    );

    // Our distribution is that of all numbers with the given bit count
    const boost::random::uniform_int_distribution<bigint> dist(std::move(min), std::move(max));

    // TO speed up prime generation, we run on each core of the cpu until we find a prime
    std::vector<std::thread> pool;
    bigint ret;
    std::atomic<bool> stop = false;
    for (unsigned int i = 0; i < std::thread::hardware_concurrency(); ++i) {
      pool.emplace_back([&, i]() {
        // Removes warnings about i not being used
        (void)i;
        // (Almost) always a cryptographically secure rng
        thread_local boost::random::random_device rng;
        // Moving this outside may create some nebulous speed improvement
        bigint candidate;
        // We stop looping when a single thread has found a result, and marked stop as true
        while (!stop) {
          // Get a random number, and make it odd
          candidate = dist(rng) * 2 + 1;
          // We will only log the candidates of one thread so that we keep the output synchronised
          RUBBISHRSA_LOG_TRACE(if (i == 0) std::cerr << "\tPrime candidate " << candidate.str() << std::endl);
          // Check if we have a prime, and check if we are the first thread to have one
          if (is_prime(candidate, 128) && !stop.exchange(true)) {
            ret = std::move(candidate);
          }
        }
      });
    }

    // Wait for each thread to finish
    for (auto& thread : pool) thread.join();

    RUBBISHRSA_LOG_TRACE(std::cerr << "Chose " << ret << " as prime" << std::endl);

    return ret;
  }

  bigint pollard_rho(const bigint& n) {
    std::vector<std::thread> pool;
    std::atomic<bool> found = false;
    bigint result;

    // Using primes will minimise the chance of collision, which means that threads are less likely to do redundant work
    constexpr static std::array<int, 128> primes{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719};
    auto max_threads = std::min(static_cast<size_t>(std::thread::hardware_concurrency()), primes.size());
    // Do Pollard's rho algorithm with each thread, each with a different polynomial
    for (size_t i = 0; i < max_threads; ++i) {
      pool.emplace_back([&, i]() {
        bigint x = primes[i];
        bigint y = x;
        bigint gcd;

        while (!found) {
          // We are trying to find two elements in the sequence u_n such that u_i is congruent to u_j (mod p), but u_n is not equal to u_i
          //
          // With two such elements, we have (as a result of the remainder property of moduli) gcd(|u_i - u_j|, n) is not 1.
          //
          // This means that there is some common divisor between them, and the result of this gcd is a factor of n
          //
          // We step one position (x) forward by 1, and the other (y) by 2, to increase the size of the tested cycle.
          //
          // For some unknown reason, If we pick u_n = u_n^2 + a (mod n) as our random generator, we will find a result quicker.

          // 1 iter for x
          x = (x*x + 1) % n;
          // 2 iters for y
          y = (y*y + 1) % n;
          y = (y*y + 1) % n;

          // We don't need to worry about both elements being equal (unless it is prime),
          // as we will happen upon a factor cycle far before that (with high probability)
          gcd = egcd(bmp::abs(x - y), n).gcd;
          // If we found something with a non-trivial gcd, that's a factor
          if (gcd != 1 && !found.exchange(true))
            result = gcd;
        }
      });
    }

    for (auto& thread : pool)
      thread.join();

    return result;
  }

  // TODO: implement
//  bigint quadratic_sieve(const bigint& n) {
//    abort();

//    // Not a perfect calcuation, but easy to do
//    bmp::mpf_float log_n = bmp::log(bmp::mpf_float{n});
//    bmp::mpf_float bound = bmp::exp(bmp::mpf_float{1/2} * log_n * bmp::log(log_n));

//    bigint prime_count_approx{bmp::ceil(bmp::mpf_float{n} / log_n)};

//    for (bigint i = 0; i < bound; ++i) {

//    }
//  }

  std::pair<bigint, bigint> factorise_semiprime(const bigint& semiprime) {
    size_t bits = floor_log2(semiprime);

    // Pollard takes a bit too long when bits >= 83 on my system, and I'll knock off a few "Windows points"
    if (bits < 70) {
      auto p = pollard_rho(semiprime);
      auto q = semiprime / p;
      return {p, q};
    }
    // TODO: make this use quadratic sieve
    else {
      auto p = pollard_rho(semiprime);
      auto q = semiprime / p;
      return {p, q};
    }
  }

  bigint ascii2bigint(std::string_view str) {
    bigint data = 0;
    for (auto i : str) {
      // Cast the character to an unsigned integer type, and add it to the end of the number
      data <<= 8;
      data += static_cast<unsigned char>(i);
    }
    return data;
  }

  bigint ascii2bigint(std::istream& in) {
    bigint data = 0;
    // Keep going until the end of the file
    while (!in.eof()) {
      data <<= 8;
      data += in.get();
    }
    return data;
  }

  std::string bigint2ascii(bigint data) {
    std::string str;
    str.reserve(2048);
    // Read the string backwards
    while (data) {
      str.push_back(static_cast<char>(data & 0xFF));
      data >>= 8;
    }
    std::reverse(str.begin(), str.end());
    return str;
  }

  bigint hex2bigint(std::string_view str) {
    // A slow way of doing it, but this is not a bottleneck
    std::string con_str{"0x"};
    con_str += str;
    return bigint{con_str};
  }
}
