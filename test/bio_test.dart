import 'dart:math';
import 'dart:typed_data';

import 'package:openssl_dart/openssl_dart.dart';
import 'package:test/test.dart';

void main() {
  test('check against BIO_new_mem_buf', () {
    BIO? bio;

    try {
      const length = 256;
      final random = Random();
      final testData = Uint8List.fromList(
        List.generate(length, (_) => random.nextInt(255)),
      );
      bio = BIO.memory(testData);
      final data = bio.read(length);
      expect(data, orderedEquals(testData));
    } finally {
      bio?.dispose();
    }
  });
  test('check with write and read', () {
    BIO? bio;

    try {
      const length = 256;
      final random = Random();
      final testData = Uint8List.fromList(
        List.generate(length, (_) => random.nextInt(255)),
      );
      bio = BIO(BIOMethod.sMem);
      bio.write(testData);
      final actualData = bio.read(length);
      expect(actualData, orderedEquals(testData));
    } finally {
      bio?.dispose();
    }
  });
}
