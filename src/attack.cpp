#include <rubbishrsa/attack.hpp>
#include <rubbishrsa/log.hpp>

#include <atomic>
#include <mutex>
#include <numeric>
#include <thread>

namespace rubbishrsa::attack {
  std::optional<bigint> brute_force_ptext(const public_key& pubkey, const bigint& encrypted_message,
                                          const std::function<std::optional<bigint>(unsigned int)> get_next_candidate,
                                          unsigned int thread_count) {
    std::vector<std::thread> pool;
    // Whilst this is technically covered by the optional, it would be faster to just access this
    std::atomic<bool> found = false;
    std::optional<bigint> result;

    auto count = thread_count ? thread_count : std::thread::hardware_concurrency();

    for (unsigned int i = 0; i < count; ++i) {
      pool.emplace_back([&, i]() {
        decltype(result) res;
        while (!found && (res = get_next_candidate(i)))
          if (pubkey.raw_encrypt(*res) == encrypted_message && !found.exchange(true))
            result = res;
      });
    }

    for (auto& thread : pool)
      thread.join();

    return result;
  }

  std::optional<bigint> brute_force_ptext(const public_key& pubkey, const bigint& encrypted_message,
                                          std::istream& in, char delim, bool convert_hex_to_num) {
    // Unfortunately, this is inherently sequential, so we have to mutex the whole thing
    std::mutex mutex;
    if (convert_hex_to_num) {
      return brute_force_ptext(pubkey, encrypted_message, [&](auto) -> std::optional<bigint> {
        std::string line;
        bool is_end;
        // Wait our turn
        {
          std::unique_lock lock{mutex};
          is_end = std::getline(in, line, delim).eof();
        }
        return is_end ? std::nullopt : std::optional<bigint>{hex2bigint(line)};
      });
    }
    else {
      return brute_force_ptext(pubkey, encrypted_message, [&](auto) -> std::optional<bigint> {
        std::string line;
        bool is_end;
        // Wait our turn
        {
          std::unique_lock lock{mutex};
          is_end = std::getline(in, line, delim).eof();
        }
        return is_end ? std::nullopt : std::optional<bigint>{ascii2bigint(line)};
      });
    }
  }

  std::optional<bigint> brute_force_ptext(const public_key& pubkey, const bigint& encrypted_message,
                                          const bigint& min, const bigint& max) {
    const auto count = std::thread::hardware_concurrency();
    std::vector<bigint> results(count);
    // Fill the vector with min, min + 1, min + 2, ..., count - 1, count
    std::iota(results.begin(), results.end(), min);
    return brute_force_ptext(pubkey, encrypted_message, [&](unsigned int i) -> std::optional<bigint> {
      auto candidate = results[i];
      results[i] += count;

      RUBBISHRSA_LOG_INFO(auto x = floor_log2(candidate); if (x && x % 8 == 0 && (bigint{1} << (x - 1)) == candidate)
                               std::cerr << "Brute forcing with length " << x/8 << " byte(s)" << std::endl);

      if (candidate > max)
        return std::nullopt;
      else
        return candidate;
    }, count);
  }

//   A bad quadratic sieve implementation
  private_key crack_key(const public_key& pubkey) {
    auto factors = factorise_semiprime(pubkey.n);
    return private_key::from_factors(factors.first, factors.second, pubkey.e);
  }
}
