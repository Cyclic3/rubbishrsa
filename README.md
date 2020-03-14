# RubbishRSA
_Why the hell has it done that™_

## Setup
### Windows
1. Download the program [here](https://github.com/Cyclic3/rubbishrsa/releases/download/latest/rubbishrsa-win64.zip).
1. Open the path that you downloaded the zip file to, right click it, and click extract
1. Go into the newly created rubbishrsa-win64 folder, and double click on the run.cmd script
1. A box will now appear in which you can type commands into. 

### Linux
1. Make sure all the dependencies are installed (for Debian-based systems, this can be done with `sudo apt-get install libboost-system1.67.0 libboost-random1.67.0 libboost-program-options1.67.0 libgmp10`
1. Download the program [here](https://github.com/Cyclic3/rubbishrsa/releases/download/latest/rubbishrsa-cli)
1. Run it with the terminal of your choice

## Usage and examples
**_NOTE_**: if you want to encrypt/decrypt raw hexadecimal values, then use the `-x` flag.

### Generating a key
`rubbishrsa-cli gen -o private_key -p public_key -s 2048`

This will generate a key of `2048` bits, and put the private key in a file called `private_key` and the public key in a file called `public_key`.
### Encrypting a message
`rubbishrsa-cli enc -p public_key -m "hello" -o ctext`

This will create a file called `ctext`, which will contain the message `hello` encrypted with the key found in the file `public_key`.

### Decrypting a message
`rubbishrsa-cli dec -k private_key -i ctext`
This will print the result of decrypting the cyphertext found in `ctext` with the private key found in the file `private_key`.

