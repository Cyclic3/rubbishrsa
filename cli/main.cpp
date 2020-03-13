//! This file does nothing but stick everything together in a usable command line executable
//!
//! It's a tiny bit hacky, but all UI stuff is...

#include <rubbishrsa/attack.hpp>
#include <rubbishrsa/keys.hpp>
#include <rubbishrsa/log.hpp>

#include <boost/program_options.hpp>

#include <fstream>
#include <iostream>

// A class that handles where the output goes
class output_handler {
private:
  std::unique_ptr<std::ofstream> maybe_outfile;
  std::ostream* out;

public:
  std::ostream& get() { return *out; }

  output_handler() { out = &std::cout; }
  output_handler(const std::string& path) {
    maybe_outfile = std::make_unique<std::ofstream>(path);
    if (!*maybe_outfile) {
      // Since we are only used in main, we can just do the error handling here
      std::cerr << "ERROR: Could not open private key output file!" << std::endl;
      exit(-1);
    }
    out = maybe_outfile.get();
  }
};

namespace po = boost::program_options;

int main(int argc, char** argv) {
  // Here we will set up our options

  uint_fast16_t keysize;
  std::string outfile_path;
  std::string inkey_path;
  // A common variable used by the different options to represent how to obtain the target data
  std::string target;
  std::string min, max;
  std::string candidates_path;

  po::options_description common_options, gen_options, enc_options, dec_options, crack_options, brute_options;
  {
    common_options.add_options()
        ("help,h", "Prints a help message")
        ("out,o", po::value(&outfile_path)->value_name("path"), "The file in which the result should be placed instead of printed to the terminal");

    gen_options.add_options()
        ("keysize,s", po::value(&keysize)->default_value(2048)->value_name("bits"), "Sets the RSA keysize")
        ("pubkey,p", po::value(&inkey_path)->value_name("path"), "An optional path to place a generated public key");

    enc_options.add_options()
        ("pubkey,p", po::value(&inkey_path)->value_name("path")->required(), "The path to the public key")
        ("hex-message,x", po::value(&target)->value_name("num"), "A hexadeciaml number th at will be used as the RSA message. Must be less than the modulus")
        ("message,m", po::value(&target)->value_name("str"), "A text string which must be shorter than keysize/8 that will be used as the RSA message")
        ("in,i", po::value(&target)->value_name("path"), "The path to the message file, which must be shorter than keysize/8 bytes");

    dec_options.add_options()
        ("privkey,k", po::value(&inkey_path)->value_name("path")->required(), "The path to the private key")
        ("ctext,c", po::value(&target)->value_name("num"), "The cyphertext created by encrypt")
        ("in,i", po::value(&target)->value_name("path"), "The path to the cyphertext file created by encrypt")
        ("hex,x", "Indicates that the output should be in hexadecimal");

    crack_options.add_options()
        ("pubkey,p", po::value(&inkey_path)->value_name("path")->required(), "The path to the public key")
        ("raw,r", "Indicates that the two factors should be returned (in decimal), instead of incorporated into a private key");

    brute_options.add_options()
        ("pubkey,p", po::value(&inkey_path)->value_name("path")->required(), "The path to the public key")
        ("ctext,c", po::value(&target)->value_name("num"), "The cyphertext created by encrypt")
        ("in,i", po::value(&target)->value_name("path"), "The path to the cyphertext file created by encrypt")
        ("list,l", po::value(&candidates_path)->value_name("path"), "A file containing all the candidate plaintexts, with newlines between them")
        ("num,n", "Indicates that the lines in the file are hexadecimal numbers, not text")
        ("min", po::value(&min)->value_name("num")->default_value("0"), "In the context of a range search, gives the lowest candidate value")
        ("max", po::value(&max)->value_name("num"), "In the context of a range search, gives the largest candidate value. If missing, we use the modulus")
        ("hex,x", "Indicates the output should be in hexadecimal, not as text");
  }

  // We use a copy capture so that our hidden options go unnoticed
  auto print_help = [=]() {
    std::cout << "Usage: " << argv[0] << " <mode> <options>" << std::endl
              << std::endl
              << "This program takes in a mode (listed below), and options for that mode."
              << std::endl
              << "Please note that, due to the nature of the encoding used, private keys can be used in the place of public keys, but (obviously) not the other way around"
              << std::endl
              << "Common options: " << std::endl
              << common_options << std::endl
              << "gen: Generates a RSA key" << std::endl
              << gen_options << std::endl
              << "enc: Encrypts some data" << std::endl
              << enc_options << std::endl
              << "dec: Decrypts some data" << std::endl
              << dec_options << std::endl
              << "crack: Factorises public keys" << std::endl
              << crack_options << std::endl
              << "brute: Brute forces plaintexts" << std::endl
              << brute_options << std::endl
              << std::endl;
  };

  // Add in the common_options option to each mode so it doesn't complain
  for (auto* desc : {&gen_options, &enc_options, &dec_options, &crack_options, &brute_options})
    for (auto& i : common_options.options())
      desc->add(i);


  // Actually parse the arguments
  po::variables_map args;
  po::store(po::command_line_parser(argc, argv)
                                .options(common_options)
                                .allow_unregistered()
                                .run(), args);
  po::notify(args);

  if (args.count("help") || argc == 1) {
    print_help();
    return 0;
  }

  output_handler out = args.count("out") ? output_handler{outfile_path} : output_handler{};

  if (std::string_view{argv[1]} == "gen") {
    po::variables_map args2;
    po::store(po::command_line_parser(argc - 1, argv + 1)
                                      .options(gen_options)
                                      .run(), args2);
    po::notify(args2);

    if (keysize < 16) {
      std::cerr << "ERROR: RSA needs a few digits difference in length to be secure, and < 16 bits will ask for a negative number of bits. Sorry" << std::endl;
      return 1;
    }

    auto key = rubbishrsa::private_key::generate(keysize);

    key.serialise(out.get()); // TODO: impl this as json
    if (inkey_path.size()) {
      std::ofstream pubkey_out{inkey_path};
      if (!pubkey_out)
        // Don't crash, this is only a warning, as the public key could be generated later
        std::cerr << "WARNING: Could not open public key output file!" << std::endl;
      else
        static_cast<rubbishrsa::public_key>(key).serialise(pubkey_out);
    }
  }
  else if (std::string_view{argv[1]} == "enc") {
    po::variables_map args2;
    po::store(po::command_line_parser(argc - 1, argv + 1)
                                      .options(enc_options)
                                      .run(), args2);
    po::notify(args2);

    if (args2.count("hex-message") + args2.count("message") + args2.count("in") != 1) {
      std::cerr << "ERROR: Exactly one of --hex-message, --message, --in must be specified!" << std::endl;
      return 1;
    }

    rubbishrsa::public_key key;
    {
      std::ifstream ifs{inkey_path};
      if (!ifs) {
        out.get() << "ERROR: Could not open RSA public key" << std::endl;
        return 1;
      }
      key = rubbishrsa::public_key::deserialise(ifs);
    }

    rubbishrsa::bigint data;

    if (args2.count("hex-message"))
      data = rubbishrsa::hex2bigint(target);
    else if (args2.count("message")) {
      data = rubbishrsa::ascii2bigint(target);
    }
    else /* if (args2.count("in")) */ {
      data = 0;
      std::ifstream in{target};
      // Keep going until the end of the file
      while (!in.eof()) {
        data <<= 8;
        data += in.get();
      }
    }

    RUBBISHRSA_LOG_INFO(std::cerr << "Encrypting " << std::hex << data << std::endl);

    if (data >= key.n) {
      std::cout << "ERROR: Message is too big to be encrypted with a modulus this small!" << std::endl;
      return 1;
    }

    out.get() << std::hex << key.raw_encrypt(data) << std::endl;
  }
  else if (std::string_view{argv[1]} == "dec") {
    po::variables_map args2;
    po::store(po::command_line_parser(argc - 1, argv + 1)
                                      .options(dec_options)
                                      .run(), args2);
    po::notify(args2);

    if (args2.count("ctext") + args2.count("in") != 1) {
      std::cerr << "ERROR: Exactly one of --ctext, --in must be specified!" << std::endl;
      return 1;
    }

    rubbishrsa::private_key key;
    {
      std::ifstream ifs{inkey_path};
      if (!ifs) {
        out.get() << "ERROR: Could not open RSA public key" << std::endl;
        return 1;
      }
      key = rubbishrsa::private_key::deserialise(ifs);
    }

    rubbishrsa::bigint data;

    if (args2.count("ctext"))
      data = rubbishrsa::hex2bigint(target);
    else /* if (args2.count("in")) */ {
      std::ifstream in{target};

      std::string num;
      std::getline(in, num);
      data = rubbishrsa::hex2bigint(num);
    }

    RUBBISHRSA_LOG_INFO(std::cerr << "Decrypting " << std::hex << data << std::endl);

    if (data >= key.n) {
      std::cout << "ERROR: Cyphertext too large! Maybe you used the wrong key?" << std::endl;
      return 1;
    }

    auto result = key.raw_decrypt(data);

    if (args2.count("hex-message"))
      out.get() << std::hex << result << std::endl;
    else
      out.get() << rubbishrsa::bigint2ascii(result) << std::endl;
  }
  else if (std::string_view{argv[1]} == "crack") {
    po::variables_map args2;
    po::store(po::command_line_parser(argc - 1, argv + 1)
                                      .options(crack_options)
                                      .run(), args2);
    po::notify(args2);

    rubbishrsa::public_key key;
    {
      std::ifstream ifs{inkey_path};

      if (!ifs) {
        out.get() << "ERROR: Could not open RSA public key" << std::endl;
        return 1;
      }
      key = rubbishrsa::public_key::deserialise(ifs);
    }

    if (args2.count("raw")) {
      auto fact = rubbishrsa::factorise_semiprime(key.n);
      out.get() << fact.first << std::endl << fact.second << std::endl;
    }
    else {
      auto k = rubbishrsa::attack::crack_key(key);
      k.serialise(out.get());
    }
  }
  else if (std::string_view{argv[1]} == "brute") {
    po::variables_map args2;
    po::store(po::command_line_parser(argc - 1, argv + 1)
                                      .options(brute_options)
                                      .run(), args2);
    po::notify(args2);

    if (args2.count("ctext") + args2.count("in") != 1) {
      std::cerr << "ERROR: Exactly one of --ctext, --in must be specified!" << std::endl;
      return 1;
    }
    // For various API reasons, we cannot check if a defaulted argument was given
    if ((args2.count("max")) && (args2.count("list") || args2.count("num"))) {
      std::cerr << "ERROR: Invalid option combination!" << std::endl;
      return 1;
    }

    rubbishrsa::public_key key;
    {
      std::ifstream ifs{inkey_path};
      if (!ifs) {
        out.get() << "ERROR: Could not open RSA public key" << std::endl;
        return 1;
      }
      key = rubbishrsa::public_key::deserialise(ifs);
    }

    rubbishrsa::bigint cyphertext;

    if (args2.count("ctext"))
      cyphertext = rubbishrsa::hex2bigint(target);
    else /* if (args2.count("in")) */ {
      std::ifstream in{target};

      std::string num;
      std::getline(in, num);
      cyphertext = rubbishrsa::hex2bigint(num);
    }

    std::optional<rubbishrsa::bigint> result;

    // Are we in range mode?
    if (args2.count("list")) {
      std::ifstream ifs{candidates_path};
      if (!ifs) {
        std::cerr << "ERROR: Could not open candidates file!" << std::endl;
        return 1;
      }
      // XXX: may not work on Windows due to CRLF bs
      result = rubbishrsa::attack::brute_force_ptext(key, cyphertext, ifs, '\n', args2.count("num"));
    }
    else
      result = rubbishrsa::attack::brute_force_ptext(key, cyphertext, rubbishrsa::hex2bigint(min),
                                                     args2.count("max") ? rubbishrsa::hex2bigint(max) : key.n);

    if (result) {
      if (args.count("hex"))
        out.get() << std::hex << *result << std::endl;
      else
        out.get() << rubbishrsa::bigint2ascii(*result) << std::endl;
    }
    else {
      std::cerr << "ERROR: Could not crack the cyphertext!" << std::endl;
      return 1;
    }
  }
  else {
    std::cerr << "ERROR: Unknown mode '" << argv[1] << '\'' << std::endl << std::endl;
    print_help();
  }

  return 0;
}
