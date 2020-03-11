//! This file does nothing but stick everything together in a usable command line executable
//!
//! It's a tiny bit hacky, but all UI stuff is...

#include "rubbishrsa/keys.hpp"
#include "rubbishrsa/log.hpp"

#include <boost/program_options.hpp>

#include <fstream>
#include <iostream>

namespace po = boost::program_options;

int main(int argc, char** argv) {
  // Here we will set up our options

  uint_fast16_t keysize;
  std::string outfile_path;
  std::string pubkey_path;
  // A common variable used by the different options to represent how to obtain the target data
  std::string target;

  po::options_description common_options, gen_options, enc_options, dec_options;
  {
    common_options.add_options()
        ("help,h", "Prints a help message");

    gen_options.add_options()
        ("keysize,s", po::value(&keysize)->default_value(2048)->value_name("bits"), "Sets the RSA keysize")
        ("out,o", po::value(&outfile_path)->value_name("path"), "The file in which the output should be placed instead of printed to the terminal")
        ("pubkey,p", po::value(&pubkey_path)->value_name("path"), "An optional path to place a generated public key");

    enc_options.add_options()
        ("pubkey,p", po::value(&pubkey_path)->value_name("path")->required(), "The path to the public key (private key files can be used as well)")
        ("hex-message,x", po::value(&target)->value_name("num"), "A hexadeciaml number th at will be used as the RSA message. Must be less than the modulus")
        ("message,m", po::value(&target)->value_name("str"), "A text string which must be shorter than keysize/8 that will be used as the RSA message")
        ("in,i", po::value(&target)->value_name("path"), "The path to the message file, which must be shorter than keysize/8 bytes")
        ("out,o", po::value(&outfile_path)->value_name("path"), "The file in which the output should be placed instead of printed to the terminal");

    dec_options.add_options()
        ("privkey,k", po::value(&pubkey_path)->value_name("path")->required(), "The path to the private key")
        ("ctext,c", po::value(&target)->value_name("num"), "The cyphertext created by encrypt")
        ("in,i", po::value(&target)->value_name("path"), "The path to the cyphertext file created by encrypt")
        ("out,o", po::value(&outfile_path)->value_name("path"), "The file in which the plaintext should be placed instead of printed to the terminal")
        ("hex,x", po::value(&outfile_path)->value_name("path"), "Indicates that the output should be in hexadecimal");
  }

  auto print_help = [&]() {
    std::cout << "Usage: " << argv[0] << " <mode> <options>" << std::endl
              << std::endl
              << "Common options: " << std::endl
              << common_options << std::endl
              << "gen: Generates a RSA key" << std::endl
              << gen_options << std::endl
              << "enc: Encrypts some data" << std::endl
              << enc_options << std::endl
              << "dec: Decrypts some data" << std::endl
              << dec_options << std::endl
              << std::endl;
  };


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
  else if (std::string_view{argv[1]} == "gen") {
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

    // This little bit of code allows us to write the code independently of whether we are writing to the terminal or a file
    std::unique_ptr<std::ofstream> maybe_outfile;
    std::ostream* out;

    if (args2.count("out") || args2.count("o")) {
      maybe_outfile = std::make_unique<std::ofstream>(outfile_path);
      if (!*maybe_outfile) {
        std::cerr << "ERROR: Could not open private key output file!" << std::endl;
        return 1;
      }
      out = maybe_outfile.get();
    }
    else
      out = &std::cout;

    key.serialise(*out); // TODO: impl this as json
    if (pubkey_path.size()) {
      std::ofstream pubkey_out{pubkey_path};
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
      std::ifstream ifs{pubkey_path};
      if (!ifs)
        throw std::invalid_argument("Could not open RSA pubkey");
      key = rubbishrsa::public_key::deserialise(ifs);
    }

    rubbishrsa::bigint data;

    if (args2.count("hex-message"))
      data = rubbishrsa::bigint("0x" + target);
    else if (args2.count("message")) {
      data = 0;
      for (auto i : target) {
        // Cast the character to an unsigned integer type, and add it to the end of the number
        data <<= 8;
        data += static_cast<unsigned char>(i);
      }
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

    // This little bit of code allows us to write the code independently of whether we are writing to the terminal or a file
    std::unique_ptr<std::ofstream> maybe_outfile;
    std::ostream* out;

    if (args2.count("out")) {
      maybe_outfile = std::make_unique<std::ofstream>(outfile_path);
      if (!*maybe_outfile) {
        std::cerr << "ERROR: Could not open private key output file!" << std::endl;
        return 1;
      }
      out = maybe_outfile.get();
    }
    else
      out = &std::cout;

    *out << key.raw_encrypt(data).str() << std::endl;
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
      std::ifstream ifs{pubkey_path};
      if (!ifs)
        throw std::invalid_argument("Could not open RSA pubkey");
      key = rubbishrsa::private_key::deserialise(ifs);
    }

    rubbishrsa::bigint data;

    if (args2.count("ctext")) {
      data = rubbishrsa::bigint{target};
    }
    else /* if (args2.count("in")) */ {
      data = 0;
      std::ifstream in{target};

      std::string num;
      std::getline(in, num);
      data = rubbishrsa::bigint{num};
    }

    RUBBISHRSA_LOG_INFO(std::cerr << "Decrypting " << std::hex << data << std::endl);

    if (data >= key.n) {
      std::cout << "ERROR: Cyphertext too large! Maybe you used the wrong key?" << std::endl;
      return 1;
    }

    // This little bit of code allows us to write the code independently of whether we are writing to the terminal or a file
    std::unique_ptr<std::ofstream> maybe_outfile;
    std::ostream* out;

    if (args2.count("out")) {
      maybe_outfile = std::make_unique<std::ofstream>(outfile_path);
      if (!*maybe_outfile) {
        std::cerr << "ERROR: Could not open private key output file!" << std::endl;
        return 1;
      }
      out = maybe_outfile.get();
    }
    else
      out = &std::cout;

    auto result = key.raw_decrypt(data);

    if (args2.count("x")) {
      *out << std::hex << result << std::endl;
    }
    else {
      std::string message;
      // Read the string backwards
      while (result) {
        message.push_back(static_cast<char>(result & 0xFF));
        result >>= 8;
      }
      std::reverse(message.begin(), message.end());
      *out << message << std::endl;
    }


  }
  else {
    std::cerr << "Unknown mode '" << argv[1] << '\'' << std::endl << std::endl;
    print_help();
  }

  return 0;
}
