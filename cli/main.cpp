//! This file does nothing but stick everything together in a usable command line executable

#include "rubbishrsa/keys.hpp"
#include "rubbishrsa/log.hpp"

#include <boost/program_options.hpp>

#include <fstream>

namespace po = boost::program_options;

int main(int argc, char** argv) {
  // Here we will set up our options

  uint_fast16_t keysize;
  std::string outfile_path;
  std::string pubkey_path;

  po::options_description common_options, gen_options;
  {
    common_options.add_options()
        ("help", "Prints a help message");

    gen_options.add_options()
        ("keysize", po::value(&keysize)->default_value(2048)->value_name("bits"), "Sets the RSA keysize")
        ("out,o", po::value(&outfile_path)->value_name("path"), "The file in which the output should be placed instead of printed to the terminal")
        ("pubkey", po::value(&pubkey_path)->value_name("path"), "An optional path to place a generated public key");
  }




  // Actually parse the arguments
  po::variables_map args;
  po::store(po::command_line_parser(argc, argv)
                                .options(common_options)
                                .allow_unregistered()
                                .run(), args);

  if (args.count("help") || argc <= 2) {
    std::cout << "Usage: " << argv[0] << " <mode> <options>" << std::endl
              << std::endl
              << "Common options: " << std::endl
              << common_options << std::endl
              << "gen: generates a RSA key" << std::endl
              << gen_options << std::endl
              << std::endl;
    // We're done
    return 0;
  }

  if (std::string_view{argv[1]} == "gen") {
    auto key = rubbishrsa::private_key::generate(keysize);

    std::unique_ptr<std::ofstream> maybe_outfile;
    std::ostream* out;

    if (outfile_path.size() == 0) {
      out = &std::cout;
    }
    else {
      maybe_outfile = std::make_unique<std::ofstream>(outfile_path);
      if (!*maybe_outfile) {
        std::cerr << "Could not open outfile" << std::endl;
        return 1;
      }
    }

    key.serialise(*out); // TODO: impl this as json
    out->flush();
  }

  return 0;
}
