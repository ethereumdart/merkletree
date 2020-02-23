import 'dart:typed_data';

import 'package:buffer/buffer.dart';

class MerkleTreeUtils {
  static bool isHexStr(String v) {
    return RegExp('^(0x)?[0-9A-Fa-f]*\$').hasMatch(v);
  }

  static Uint8List bufferReverse(Uint8List src) {
    var buffer = Uint8List(src.length);

    for (var i = 0, j = src.length - 1; i <= j; ++i, --j) {
      buffer[i] = src[j];
      buffer[j] = src[i];
    }

    return buffer;
  }

  static Uint8List bufferConcat(List<Uint8List> buffers) {
    var bytesBuffer = BytesBuffer(copy: true);
    buffers.forEach((buffer) => bytesBuffer.add(buffer));
    return bytesBuffer.toBytes();
  }

  static int bufferCompare(Uint8List a, Uint8List b) {
    for (var i = 0; i < a.length && i < b.length; i++) {
      if (a[i] < b[i]) return -1;
      if (a[i] > b[i]) return 1;
    }
    return 0;
  }
}
