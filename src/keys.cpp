#include <rubbishrsa/keys.hpp>

#include <rubbishrsa/log.hpp>

#include <boost/property_tree/json_parser.hpp>

#include <boost/multiprecision/miller_rabin.hpp>

namespace rubbishrsa {
  private_key private_key::from_factors(const bigint& p, const bigint& q, bigint e) {
    // We can now start filling in our result
    private_key ret;
    ret.n = p * q;
    // This is automatically done
    ret.e = e;

    auto lambda_n = carmichael_semiprime(p, q);
    ret.d = modinv(ret.e, lambda_n); // $d \equiv e^{-1} \pmod{\lambda(n)}$


    return ret;
  }

  private_key private_key::generate(uint_fast16_t bits) {
    // Apparently we should differ in lengths by a few digits
    // this will differ in length by log10(2^8) = ~3 digits
    auto p = generate_prime(bits / 2 + 4);
    auto q = generate_prime(bits / 2 - 3);

    RUBBISHRSA_LOG_INFO(std::cerr << "(p, q) = (" << p.str() << ", " << q.str() << ')' << std::endl);

    // Now we have a good p and q, we can pass it along
    return private_key::from_factors(p, q);
  }

  void public_key::serialise(std::ostream& os) const {
    boost::property_tree::ptree data;
    data.put("e", e);
    data.put("n", n);
    boost::property_tree::write_json(os, data, false);
  }

  void private_key::serialise(std::ostream& os) const {
    boost::property_tree::ptree data;
    data.put("e", e);
    data.put("d", d);
    data.put("n", n);
    boost::property_tree::write_json(os, data, false);
  }

  public_key public_key::deserialise(std::istream& is) {
    boost::property_tree::ptree data;
    boost::property_tree::read_json(is, data);
    public_key ret;

    ret.e = data.get<bigint>("e");
    ret.n = data.get<bigint>("n");

    return ret;
  }

  private_key private_key::deserialise(std::istream& is) {
    boost::property_tree::ptree data;
    boost::property_tree::read_json(is, data);
    private_key ret;

    ret.e = data.get<bigint>("e");
    ret.d = data.get<bigint>("d");
    ret.n = data.get<bigint>("n");

    return ret;
  }
}
