import 'dart:math';
import 'dart:typed_data';

import 'package:openssl_dart/src/evp.dart';
import 'package:openssl_dart/src/rsa.dart';
import 'package:test/test.dart';

final message = Uint8List.fromList("Hello World!".codeUnits);

void main() {
  // The following test code is based upon https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
  group("HMAC", () {
    RSA? rsa;
    PKey? pKey;
    late Uint8List hmac;

    setUpAll(() {
      rsa = RSA()..generateKey(2048, rsaF4);
      pKey = PKey()..assignRSA(rsa!);
    });

    test("Calcuating", () {
      DigestContext? context;
      try {
        context = DigestContext();
        context.digestSignInit(DigestAlgorithm.sha256, pKey!);
        context.digestUpdate(message);
        hmac = context.digestSignFinal();
      } finally {
        context?.dispose();
      }
    });

    test("Verifying against the same key", () {
      DigestContext? context;
      try {
        context = DigestContext();
        context.digestSignInit(DigestAlgorithm.sha256, pKey!);
        context.digestUpdate(message);
        final buffer = context.digestSignFinal();
        expect(buffer.length, equals(hmac.length));
      } finally {
        context?.dispose();
      }
    });

    // TODO(Craftplacer): add test with different key, checking against original HMAC

    tearDownAll(() {
      rsa?.dispose();
      pKey?.dispose();
    });
  });

  group("Asymmetric Key", () {
    RSA? rsa;
    PKey? pKey;
    late Uint8List sig;

    setUpAll(() {
      rsa = RSA()..generateKey(2048, rsaF4);
      pKey = PKey()..assignRSA(rsa!);
    });

    test("Signing", () {
      DigestContext? context;

      try {
        context = DigestContext();
        context.digestSignInit(DigestAlgorithm.sha256, pKey!);
        context.digestUpdate(message);
        sig = context.digestSignFinal();
      } finally {
        context?.dispose();
      }
    });

    test("Verifying against valid signature", () {
      DigestContext? context;

      try {
        context = DigestContext();
        context.digestVerifyInit(DigestAlgorithm.sha256, pKey!);
        context.digestUpdate(message);
        context.digestVerifyFinal(sig).throwException();
      } finally {
        context?.dispose();
      }
    });

    test("Verifying against empty signature", () {
      DigestContext? context;

      try {
        context = DigestContext();
        context.digestVerifyInit(DigestAlgorithm.sha256, pKey!);
        context.digestUpdate(message);
        final result = context.digestVerifyFinal(Uint8List(0));
        expect(result.isSuccessful, isFalse);
      } finally {
        context?.dispose();
      }
    });

    test("Verifying against random signature", () {
      DigestContext? context;

      try {
        context = DigestContext();
        context.digestVerifyInit(DigestAlgorithm.sha256, pKey!);
        context.digestUpdate(message);
        final random = Random.secure();
        final randomSignature = Uint8List.fromList(
          List.generate(
            sig.length,
            (_) => random.nextInt(255),
          ),
        );
        final result = context.digestVerifyFinal(randomSignature);
        expect(result.isSuccessful, isFalse);
      } finally {
        context?.dispose();
      }
    });

    tearDownAll(() {
      rsa?.dispose();
      pKey?.dispose();
    });
  });
}
