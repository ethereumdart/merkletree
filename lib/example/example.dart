import 'dart:typed_data';

import 'package:merkletree/merkletree.dart';
import 'package:pointycastle/pointycastle.dart';

void main() {
  Uint8List sha256(Uint8List data) {
    var sha256 = Digest('SHA-256');
    return sha256.process(data);
  }

  Uint8List sha3(Uint8List data) {
    var sha3 = Digest('SHA-3/256');
    return sha3.process(data);
  }

  var leaves = ['a', 'b', 'c'].map((x) => Uint8List.fromList(x.codeUnits)).map((x) => sha3(x)).toList();
  var tree = MerkleTree(leaves: leaves, hashAlgo: sha256);
}