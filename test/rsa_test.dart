import 'dart:typed_data' show Uint8List;

import 'package:openssl_dart/openssl_dart.dart';
import 'package:openssl_dart/src/err.dart';
import 'package:test/test.dart';

const bits = 4096;
const rsaStartLine = "-----BEGIN RSA PUBLIC KEY-----";
const rsaEndLine = "-----END RSA PUBLIC KEY-----";

void main() {
  group("Write and Read Public Key", () {
    late Uint8List writtenPublicKey;

    test('PEM_write_bio_RSAPublicKey', () {
      RSA? rsa;
      BIO? bio;
      try {
        rsa = RSA()..generateKey(bits, rsaF4);
        // write public key to bio
        bio = BIO(BIOMethod.sMem);
        rsa.writePublicKey(bio);

        writtenPublicKey = bio.read(bio.numberWritten);

        // Check for start line
        final header = writtenPublicKey.sublist(0, rsaStartLine.length);
        expect(
          header,
          orderedEquals(rsaStartLine.codeUnits),
          reason: "RSA start line is not present",
        );

        // Check for end line
        final footer = writtenPublicKey.sublist(
          writtenPublicKey.length - rsaEndLine.length - 1,
          writtenPublicKey.length - 1,
        );
        expect(
          footer,
          orderedEquals(rsaEndLine.codeUnits),
          reason: "RSA end line is not present",
        );
      } finally {
        rsa?.dispose();
        bio?.dispose();
      }
    });

    test('PEM_read_bio_RSAPublicKey', () {
      RSA? rsa;
      BIO? readBio, writeBio;
      try {
        readBio = BIO.memory(writtenPublicKey);
        rsa = readBioRsaPublicKey(readBio);

        writeBio = BIO(BIOMethod.sMem);
        rsa.writePublicKey(writeBio);

        final readPublicKey = writeBio.read(writeBio.numberWritten);

        expect(readPublicKey, orderedEquals(readPublicKey));
      } finally {
        rsa?.dispose();
        readBio?.dispose();
        writeBio?.dispose();
      }
    });
  });

  group("Signing and Verifying", () {
    late RSA rsa;
    const type = 674;
    Uint8List? signature;
    final message = Uint8List.fromList(
      "Who would've thought that programming a wrapper in Dart for a C++ library would be so hard?"
          .codeUnits,
    );

    setUpAll(() => rsa = RSA()..generateKey(bits, rsaF4));

    test('RSA_sign', () {
      signature = rsa.sign(type, message);
    });

    test('RSA_verify', () {
      final s = signature ?? rsa.sign(type, message);

      if (!rsa.verify(type, message, s)) {
        throw OpenSSLException();
      }
    });

    tearDownAll(() => rsa.dispose());
  });
}
