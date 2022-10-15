import 'dart:ffi';

import 'package:meta/meta.dart';

import 'bindings.g.dart';
import 'err.dart';
import 'lib.dart';

typedef BigNumHandle = Pointer<bignum_st>;

class BigNum {
  BigNumHandle? _handle;

  @internal
  BigNumHandle get handle => _handle!;

  BigNum() {
    var handle = nativeLibrary.BN_new();
    if (handle == nullptr) throw OpenSSLException();
    _handle = handle;
  }

  void setWord(int word) {
    nativeLibrary.BN_set_word(_handle!, word).throwIfNotOne();
  }

  BigNum.secure() {
    var handle = nativeLibrary.BN_secure_new();
    if (handle == nullptr) throw OpenSSLException();
    _handle = handle;
  }

  void dispose() {
    nativeLibrary.BN_free(_handle!);
    _handle = null;
  }
}

extension BigNumIntExtensions on int {
  BigNum toBigNum() => BigNum()..setWord(this);
}
