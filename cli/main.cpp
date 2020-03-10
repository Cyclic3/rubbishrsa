#include "rubbishrsa/keys.hpp"
#include "rubbishrsa/log.hpp"


int main() {
  auto key = rubbishrsa::private_key::generate(2048);

  rubbishrsa::bigint msg = 69;

  auto ctext = key.raw_encrypt(msg);
  auto msg_ = key.raw_decrypt(ctext);

  auto res = (msg == msg_);

  return 0;
}
