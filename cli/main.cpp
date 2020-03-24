//! This file does nothing but stick everything together in a usable command line executable
//!
//! It's a tiny bit hacky, but all UI stuff is...

#include <rubbishrsa/attack.hpp>
#include <rubbishrsa/keys.hpp>
#include <rubbishrsa/log.hpp>

#include <boost/program_options.hpp>

#include <fstream>
#include <iostream>

namespace po = boost::program_options;

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

rubbishrsa::bigint read_hex_input(const std::string& not_file_indicator, const po::variables_map& args2) {
  rubbishrsa::bigint data;

  if (args2.count(not_file_indicator)) {
    data = rubbishrsa::hex2bigint(args2.at(not_file_indicator).as<std::string>());
  }
  else {
    std::ifstream in{args2.at("in").as<std::string>()};
    if (!in) {
      std::cerr << "ERROR: Cannot open input file!" << std::endl;
      exit(1);
    }
    in >> std::hex >> data;
  }

  return data;
}

rubbishrsa::bigint read_message(const po::variables_map& args2) {
  rubbishrsa::bigint data;

  if (args2.count("message")){
    if (args2.count("hex"))
      data = rubbishrsa::hex2bigint(args2.at("message").as<std::string>());
    else
      data = rubbishrsa::ascii2bigint(args2.at("message").as<std::string>());
  }
  else {
    std::ifstream in{args2.at("in").as<std::string>()};
    if (!in) {
      std::cerr << "ERROR: Cannot open input file!" << std::endl;
      exit(1);
    }
    if (args2.count("hex"))
      in >> std::hex >> data;
    else
      data = rubbishrsa::ascii2bigint(in);
  }

  return data;
}

rubbishrsa::public_key read_pubkey(const po::variables_map& args2) {
  std::ifstream ifs{args2.at("pubkey").as<std::string>()};
  if (!ifs) {
    std::cerr << "ERROR: Could not open RSA public key" << std::endl;
    exit(1);
  }
  return rubbishrsa::public_key::deserialise(ifs);
}

rubbishrsa::private_key read_privkey(const po::variables_map& args2) {
  std::ifstream ifs{args2.at("privkey").as<std::string>()};
  if (!ifs) {
    std::cerr << "ERROR: Could not open RSA private key" << std::endl;
    exit(1);
  }
  return rubbishrsa::private_key::deserialise(ifs);
}

int main(int argc, char** argv) {
  // Here we will set up our options
  uint_fast16_t keysize;
  std::string outfile_path;
  std::string inkey_path;
  // A common variable used by the different options to represent how to obtain the target data
  std::string target;
  std::string min, max;
  std::string candidates_path;

  po::options_description common_options, gen_options, enc_options, dec_options, crack_options, brute_options, sign_options, verify_options, forge_options;
  {
    common_options.add_options()
        ("help,h", "Prints a help message")
        ("out,o", po::value(&outfile_path)->value_name("path"), "The file in which the result should be placed instead of printed to the terminal");

    gen_options.add_options()
        ("keysize,s", po::value(&keysize)->default_value(2048)->value_name("bits"), "Sets the RSA keysize")
        ("pubkey,p", po::value(&inkey_path)->value_name("path"), "An optional path to place a generated public key");

    enc_options.add_options()
        ("hex,x", po::value(&target)->value_name("num"), "Indicates that the message is in hexadecimal, not text")
        ("pubkey,p", po::value(&inkey_path)->value_name("path")->required(), "The path to the public key")
        ("message,m", po::value(&target)->value_name("str"), "A text (or hexadecimal) string that will be used as the RSA message")
        ("in,i", po::value(&target)->value_name("path"), "The path to the message file");

    dec_options.add_options()
        ("hex,x", "Indicates that the output should be in hexadecimal")
        ("privkey,k", po::value(&inkey_path)->value_name("path")->required(), "The path to the private key")
        ("ctext,c", po::value(&target)->value_name("num"), "The cyphertext created by encrypt")
        ("in,i", po::value(&target)->value_name("path"), "The path to the cyphertext file created by encrypt");

    sign_options.add_options()
        ("hex,x", "Indicates that the message is in hexadecimal, not text")
        ("privkey,k", po::value(&inkey_path)->value_name("path")->required(), "The path to the private key")
        ("message,m", po::value(&target)->value_name("str"), "A text (or hexadecimal) string that will be used as the RSA message")
        ("in,i", po::value(&target)->value_name("path"), "The path to the message file");

    verify_options.add_options()
        ("hex,x", "Indicates that the output should be in hexadecimal. Without this options, invisible characters can be added to the end of the string to fake signatures")
        ("pubkey,p", po::value(&inkey_path)->value_name("path")->required(), "The path to the public key")
        ("sig,s", po::value(&target)->value_name("num"), "The cyphertext created by encrypt")
        ("in,i", po::value(&target)->value_name("path"), "The path to the cyphertext file created by encrypt");

    crack_options.add_options()
        ("hex,x", "Indicates that the two factors should be returned (in decimal), instead of incorporated into a private key")
        ("pubkey,p", po::value(&inkey_path)->value_name("path")->required(), "The path to the public key");

    brute_options.add_options()
        ("hex,x", "Indicates the output should be in hexadecimal, not as text")
        ("pubkey,p", po::value(&inkey_path)->value_name("path")->required(), "The path to the public key")
        ("ctext,c", po::value(&target)->value_name("num"), "The cyphertext created by encrypt")
        ("in,i", po::value(&target)->value_name("path"), "The path to the cyphertext file created by encrypt")
        ("list,l", po::value(&candidates_path)->value_name("path"), "A file containing all the candidate plaintexts, with newlines between them")
        ("num,n", "Indicates that the lines in the file are hexadecimal numbers, not text")
        ("min", po::value(&min)->value_name("num")->default_value("0"), "In the context of a range search, gives the lowest candidate value")
        ("max", po::value(&max)->value_name("num"), "In the context of a range search, gives the largest candidate value. If missing, we use the modulus");

    forge_options.add_options()
        ("hex,x",  "Indicates that the message is in hexadecimal, not text")
        ("pubkey,p", po::value(&inkey_path)->value_name("path")->required(), "The path to the public key")
        ("invisible,u", "Indicates that invisible characters are allowed")
        ("message,m", po::value(&target)->value_name("str"), "A text (or hexadecimal) string that will be used as the RSA message")
        ("in,i", po::value(&target)->value_name("path"), "The path to the message file");
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
              << "sign: Signs some data" << std::endl
              << enc_options << std::endl
              << "verify: Verifies as signature" << std::endl
              << dec_options << std::endl
              << "crack: Factorises public keys" << std::endl
              << crack_options << std::endl
              << "brute: Brute forces plaintexts" << std::endl
              << brute_options << std::endl
              << "forge: Forges signatures for small moduli" << std::endl
              << forge_options << std::endl
              << std::endl;
  };

  // Add in the common_options option to each mode so it doesn't complain
  for (auto* desc : {&gen_options, &enc_options, &dec_options, &crack_options, &brute_options, &sign_options, &verify_options})
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

  std::string_view mode{argv[1]};

  if (mode == "gen") {
    po::variables_map args2;
    po::store(po::command_line_parser(argc - 1, argv + 1)
                                      .options(gen_options)
                                      .run(), args2);
    po::notify(args2);

    if (keysize < 16) {
      std::cerr << "ERROR: RSA needs a few digits difference in length to be secure, and < 16 bits may ask for a negative number of bits. Sorry" << std::endl;
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
  else if (mode == "enc") {
    po::variables_map args2;
    po::store(po::command_line_parser(argc - 1, argv + 1)
                                      .options(enc_options)
                                      .run(), args2);
    po::notify(args2);

    if (args2.count("hex-message") + args2.count("message") + args2.count("in") != 1) {
      std::cerr << "ERROR: Exactly one of --hex-message, --message, --in must be specified!" << std::endl;
      return 1;
    }

    rubbishrsa::public_key key = read_pubkey(args2);
    rubbishrsa::bigint data = read_message(args2);

    RUBBISHRSA_LOG_INFO(std::cerr << "Encrypting " << std::hex << data << std::endl);

    if (data >= key.n) {
      std::cout << "ERROR: Message is too big to be encrypted with a modulus this small!" << std::endl;
      return 1;
    }

    out.get() << std::hex << key.raw_encrypt(data) << std::endl;
  }
  else if (mode == "dec") {
    po::variables_map args2;
    po::store(po::command_line_parser(argc - 1, argv + 1)
                                      .options(dec_options)
                                      .run(), args2);
    po::notify(args2);

    if (args2.count("ctext") + args2.count("in") != 1) {
      std::cerr << "ERROR: Exactly one of --ctext, --in must be specified!" << std::endl;
      return 1;
    }

    rubbishrsa::private_key key = read_privkey(args2);
    rubbishrsa::bigint data = read_hex_input("ctext", args2);

    RUBBISHRSA_LOG_INFO(std::cerr << "Decrypting " << std::hex << data << std::endl);

    if (data >= key.n) {
      std::cout << "ERROR: Cyphertext too large! Maybe you used the wrong key?" << std::endl;
      return 1;
    }

    auto result = key.raw_decrypt(data);

    if (args2.count("hex"))
      out.get() << std::hex << result << std::endl;
    else
      out.get() << rubbishrsa::bigint2ascii(result) << std::endl;
  }
  else if (mode == "sign") {
    po::variables_map args2;
    po::store(po::command_line_parser(argc - 1, argv + 1)
                                      .options(sign_options)
                                      .run(), args2);
    po::notify(args2);

    rubbishrsa::private_key key = read_privkey(args2);
    rubbishrsa::bigint data = read_message(args2);

    RUBBISHRSA_LOG_INFO(std::cerr << "Signing " << std::hex << data << std::endl);

    if (data >= key.n) {
      std::cout << "ERROR: Message is too big to be signed with a modulus this small!" << std::endl;
      return 1;
    }

    auto result = key.raw_sign(data);

    out.get() << std::hex << result << std::endl;
  }
  else if (mode == "verify") {
    po::variables_map args2;
    po::store(po::command_line_parser(argc - 1, argv + 1)
                                      .options(verify_options)
                                      .run(), args2);
    po::notify(args2);

    rubbishrsa::public_key key = read_pubkey(args2);
    rubbishrsa::bigint data = read_hex_input("sig", args2);

    if (data >= key.n) {
      std::cout << "ERROR: Signature too large! Maybe you used the wrong key?" << std::endl;
      return 1;
    }

    rubbishrsa::bigint result = key.raw_verify(data);

    if (args2.count("hex"))
      out.get() << std::hex << result << std::endl;
    else
      out.get() << rubbishrsa::bigint2ascii(result) << std::endl;
  }
  else if (mode == "crack") {
    po::variables_map args2;
    po::store(po::command_line_parser(argc - 1, argv + 1)
                                      .options(crack_options)
                                      .run(), args2);
    po::notify(args2);

    rubbishrsa::public_key key = read_pubkey(args2);

    if (args2.count("hex")) {
      auto fact = rubbishrsa::factorise_semiprime(key.n);
      out.get() << std::hex << fact.first << std::endl << std::hex << fact.second << std::endl;
    }
    else {
      auto k = rubbishrsa::attack::crack_key(key);
      k.serialise(out.get());
    }
  }
  else if (mode == "brute") {
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

    rubbishrsa::public_key key = read_pubkey(args2);

    rubbishrsa::bigint data = read_hex_input("ctext", args2);

    std::optional<rubbishrsa::bigint> result;

    // Are we in range mode?
    if (args2.count("list")) {
      std::ifstream ifs{candidates_path};
      if (!ifs) {
        std::cerr << "ERROR: Could not open candidates file!" << std::endl;
        return 1;
      }
      // XXX: may not work on Windows due to CRLF bs
      result = rubbishrsa::attack::brute_force_ptext(key, data, ifs, '\n', args2.count("num"));
    }
    else
      result = rubbishrsa::attack::brute_force_ptext(key, data, rubbishrsa::hex2bigint(min),
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
  else if (mode == "forge") {
    po::variables_map args2;
    po::store(po::command_line_parser(argc - 1, argv + 1)
                                      .options(forge_options)
                                      .run(), args2);
    po::notify(args2);

    rubbishrsa::public_key key = read_pubkey(args2);

    rubbishrsa::bigint data = read_message(args2);

    if (data >= key.n) {
      std::cout << "ERROR: Message is too big to be signed with a modulus this small!" << std::endl;
      return 1;
    }

    std::optional<rubbishrsa::bigint> result;

    if (args2.count("invisible"))
      result = rubbishrsa::attack::brute_force_sig_invis(key, data);
    else
      result = rubbishrsa::attack::brute_force_sig(key, [&](const auto& i) {return i == data;});

    if (!result)
      std::cerr << "ERROR: Could not find a conforming signature!" << std::endl;

    out.get() << std::hex << *result << std::endl;
  }
  else {
    std::cerr << "ERROR: Unknown mode '" << argv[1] << '\'' << std::endl << std::endl;
    print_help();
  }

  return 0;
}
