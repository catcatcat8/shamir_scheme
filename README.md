# Shamir's Secret Sharing Scheme

## Project description
A program that divides any ECDSA private key into N parts according to Shamir's secret sharing algorithm and restores it upon presentation of any T parts.

## Configuration
The program receives as input a single command-line argument indicating the mode of the program:
> ./program split - private key splitting mode

> ./program recover - private key recovering mode

## Build
Install OpenSSL library with the command `sudo apt-get install libssl-dev`.

Install Boost Multiprecision library with the command `sudo apt-get install libboost-all-dev`.

To build a project write in the command-line: 
> g++ -o shamir shamir.cpp -lssl -lcrypto

## Run

### Private key splitting mode
To run the project in private key splitting mode write in the command-line:
> ./shamir split

After that, enter from the keyboard two parameters separated by a space: N T

### Private key recovering mode
To run the project in private key recovering mode write in the command-line:
> ./shamir recover

After that, enter from the keyboard T shares of private key via enter.

The program reads your shares of private key until you enter an empty string.

For example:
> 3 049C3A0FC21923A91E656294018C7473C31E885A6ABF86F02BC2C67D04779F01BF

> 4 0748FFBFB3294CA3D2281293AB72A2C5B94BF631CC20C2EEC25AD225AD0A0C9162

> 5 0AA63EBC6A1E7A41F9A84D18BA9D553DC21B0A8EDBD03EEF860F10ACB583AD339F


## An example of building, running, working the program

![](shamir_example.png "Example")

## Used non-system libraries
OpenSSL (https://www.openssl.org/)

Boost Multiprecision library (https://www.boost.org/)

## License
MIT License (https://opensource.org/licenses/MIT)
