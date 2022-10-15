import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

extension Uint8ListExtensions on Uint8List {
  Pointer<T> allocate<T extends NativeType>() {
    final length = this.length;
    final pointer = malloc.call<Uint8>(length);
    pointer.asTypedList(length).setAll(0, this);
    return pointer.cast<T>();
  }
}

extension PointerExtensions on Pointer {
  Uint8List toUint8List(int length) {
    final Pointer<Uint8> pointer = this is Pointer<Uint8> //
        ? this as Pointer<Uint8>
        : cast<Uint8>();

    final view = pointer.asTypedList(length);
    return Uint8List.fromList(view);
  }
}
