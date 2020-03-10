#include <rubbishrsa/keys.hpp>

#include <rubbishrsa/log.hpp>

namespace rubbishrsa {
  private_key private_key::generate(uint_fast16_t bits) {
    // Apparently we should differ in lengths by a few dgits
    auto p = generate_prime(bits / 2 + 4);
    auto q = generate_prime(bits / 2 - 4);

    std::cerr << "(p, q) = (" << p.str() << ", " << q.str() << ')' << std::endl

    RUBBISHRSA_LOG(std::cerr << "(p, q) = (" << p.str() << ", " << q.str() << ')' << std::endl);

    // We can now start filling in our result
    private_key ret;
    ret.n = p * q;
    // This is automatically done
    //ret.e = 65537;
    auto lambda_n = carmichael_semiprime(p, q);
    ret.d = modinv(ret.e, lambda_n); // $d \equiv e^{-1} \pmod{\lambda(n)}$


    return ret;
  }
}
