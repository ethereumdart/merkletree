# Merkle Tree Dart Example

Here is a working Dart example of the Merkle Tree Dart implementation

## Construct a Merkle Tree.
All nodes and leaves are stored as *Uint8List*.
Lonely leaf nodes are promoted to the next level up without being hashed again.

*leaves* is a list of hashed leaves. Each leaf must be a *Uint8List*.
*hashAlgo* is a *HashAlgo* function used for hashing leaves and nodes defined.
*isBitcoinTree* decides whether to construct the MerkleTree using the [Bitcoin Merkle Tree implementation](http://www.righto.com/2014/02/bitcoin-mining-hard-way-algorithms.html).
Enable it when you need to replicate Bitcoin constructed Merkle Trees. In Bitcoin Merkle Trees, single nodes are combined with themselves, and each output hash is hashed again.

```dart
import 'dart:typed_data';

import 'package:merkletree/merkletree.dart';
import 'package:pointycastle/pointycastle.dart';

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
```