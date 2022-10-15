import 'dart:ffi';

import 'bio.dart';
import 'err.dart';
import 'lib.dart';
import 'rsa.dart';

RSA readBioRsaPrivateKey(BIO bp) {
  final result = nativeLibrary.PEM_read_bio_RSAPrivateKey(
    bp.handle,
    nullptr,
    nullptr,
    nullptr,
  );

  if (result == nullptr) throw OpenSSLException();

  return RSA.fromHandle(result);
}

RSA readBioRsaPublicKey(BIO bp) {
  final result = nativeLibrary.PEM_read_bio_RSAPublicKey(
    bp.handle,
    nullptr,
    nullptr,
    nullptr,
  );

  if (result == nullptr) throw OpenSSLException();

  return RSA.fromHandle(result);
}

void writeBioRsaPublicKey(BIO bio, RSA rsa) {
  nativeLibrary.PEM_write_bio_RSAPublicKey(
    bio.handle,
    rsa.handle,
  ).throwIfNotOne();
}

void writeBioRsaPrivateKey(BIO bio, RSA rsa) {
  nativeLibrary.PEM_write_bio_RSAPrivateKey(
    bio.handle,
    rsa.handle,
    nullptr,
    nullptr,
    0,
    nullptr,
    nullptr,
  ).throwIfNotOne();
}
