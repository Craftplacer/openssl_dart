import 'dart:io' show File;

import 'package:openssl_dart/openssl_dart.dart';

void main() {
  RSA? rsa;
  BIO? bio;
  try {
    // generate key
    rsa = RSA()..generateKey(2048, rsaF4);

    // initialize BIO
    bio = BIO(BIOMethod.sMem);

    // write public key to disk
    rsa.writePublicKey(bio);
    File('public.pem').writeAsBytesSync(bio.read(bio.numberWritten));
  } finally {
    bio?.dispose();
    rsa?.dispose();
  }
}
