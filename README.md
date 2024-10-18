# Media For Tamper-Averse Humans (MFTAH)
Encrypt and decrypt encapsulated AES-256 boot or transfer payloads with NO DEPENDENCIES.

This is a file format which encrypts/decrypts data payloads for generic use. It's not really anything novel, and its primary use is as a bootloader protocol from MBR/UEFI since it has no dependencies (not even the Standard Library).

In the future (version 2), this format will be extended to accommodate different algorithms for password hashing, HMACs, and symmetric cryptography. I may also venture into compression algorithms, which would add interesting behaviors and complexity to the format.


## Crypto Backing
MFTAH provides `CIA`: _Confidentiality_ of data (encryption), _Integrity_ of the encapsulated payload (through HMACs), and _Availability_ of the data because it is easily transmissible and securely storable.

Interestingly, it allows safe parallelization of AES-256's _CBC_ (Cipher Block Chaining) mode without reusing initialization vector values, which is kind of new and cool (and probably useless).


## Using It
Compile with `make all; sudo make install` to install the MFTAH headers and generate the libraries.

You can either use the `libmftah` as a static library (".a" file) or as a Dynamic Shared Object (`/usr/local/lib/libmftah.so`).

There is a [Linux command-line tool](https://github.com/NotsoanoNimus/MFTAH-CLI) that incorporates the static library in its build process. Building this can allow you to en/decapsulate payloads without any dependencies.

I suppose it is possible to use this under Windows, but I haven't really explored that yet and I'm not sure I will.
