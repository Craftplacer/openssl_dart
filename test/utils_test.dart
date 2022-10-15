import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:openssl_dart/src/utils.dart';
import 'package:test/test.dart';

void main() {
  test("Uint8List.allocate()", () {
    final list = Uint8List.fromList(List.generate(50, (i) => i));
    final pointer = list.allocate<Uint8>();
    addTearDown(() => malloc.free(pointer));

    final list2 = pointer.asTypedList(list.length);
    expect(list2, orderedEquals(list));
  });
}
