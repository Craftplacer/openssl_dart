import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:meta/meta.dart';

import 'bindings.g.dart' show rsa_st;
import 'bio.dart' show BIO;
import 'bn.dart';
import 'err.dart';
import 'lib.dart';
import 'pem.dart' as pem;
import 'utils.dart';

typedef RSAHandle = Pointer<rsa_st>;

/// RSA_F4
const rsaF4 = 65537;

class RSA {
  RSAHandle? _handle;

  @internal
  RSAHandle get handle => _handle!;

  int get size => nativeLibrary.RSA_size(_handle!);
  int get bits => nativeLibrary.RSA_bits(_handle!);
  int get securityBits => nativeLibrary.RSA_security_bits(_handle!);

  RSA() {
    final handle = nativeLibrary.RSA_new();
    if (handle == nullptr) throw OpenSSLException();
    _handle = handle;
  }

  @internal
  RSA.fromHandle(RSAHandle this._handle);

  void dispose() {
    nativeLibrary.RSA_free(_handle!);
    _handle = null;
  }

  void generateKey(int bits, int exponent) {
    BigNum? exponentBn;

    try {
      exponentBn = exponent.toBigNum();
      nativeLibrary.RSA_generate_key_ex(
        _handle!,
        bits,
        exponentBn.handle,
        nullptr,
      ).throwIfNotOne();
    } finally {
      exponentBn?.dispose();
    }
  }

  void writePrivateKey(BIO bio) => pem.writeBioRsaPrivateKey(bio, this);
  void writePublicKey(BIO bio) => pem.writeBioRsaPublicKey(bio, this);

  Uint8List sign(int type, Uint8List message) {
    Pointer<UnsignedChar>? hM;
    Pointer<UnsignedChar>? hSigret;
    Pointer<UnsignedInt>? hSiglen;

    try {
      final mLength = message.length;
      hM = message.allocate<UnsignedChar>();

      final siglen = size;
      hSigret = malloc.call<UnsignedChar>(siglen);
      hSiglen = malloc.call<UnsignedInt>()..value = siglen;

      nativeLibrary.RSA_sign(
        type,
        hM,
        mLength,
        hSigret,
        hSiglen,
        _handle!,
      ).throwIfNotOne();

      return hSigret.toUint8List(siglen);
    } finally {
      if (hM != null) malloc.free(hM);
      if (hSigret != null) malloc.free(hSigret);
      if (hSiglen != null) malloc.free(hSiglen);
    }
  }

  bool verify(int type, Uint8List message, Uint8List siganture) {
    Pointer<UnsignedChar>? hM;
    Pointer<UnsignedChar>? hSigbuf;

    try {
      final mLength = message.length;
      hM = message.allocate<UnsignedChar>();

      final siglen = siganture.length;
      hSigbuf = siganture.allocate<UnsignedChar>();

      final result = nativeLibrary.RSA_verify(
        type,
        hM,
        mLength,
        hSigbuf,
        siglen,
        _handle!,
      );

      return result == 1;
    } finally {
      if (hSigbuf != null) malloc.free(hSigbuf);
      if (hM != null) malloc.free(hM);
    }
  }
}
