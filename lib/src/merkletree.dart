import 'dart:typed_data';

import 'package:merkletree/src/utils.dart';
import 'package:meta/meta.dart';

typedef Uint8List HashAlgo(Uint8List input);

/// Class representing a Merkle Tree
class MerkleTree {
  final HashAlgo hashAlgo;
  final List<Uint8List> leaves;
  List<List<Uint8List>> _layers;
  final bool isBitcoinTree;

  /// Constructs a Merkle Tree.
  /// All nodes and leaves are stored as [Uint8List].
  /// Lonely leaf nodes are promoted to the next level up without being hashed again.
  ///
  /// [leaves] is a list of hashed leaves. Each leaf must be a [Uint8List].
  /// [hashAlgo] is a [HashAlgo] function used for hashing leaves and nodes defined.
  /// [isBitcoinTree] decides whether to construct the MerkleTree using the [Bitcoin Merkle Tree implementation](http://www.righto.com/2014/02/bitcoin-mining-hard-way-algorithms.html).
  ///   Enable it when you need to replicate Bitcoin constructed Merkle Trees. In Bitcoin Merkle Trees, single nodes are combined with themselves, and each output hash is hashed again.
  ///
  /// ```dart
  /// import 'dart:typed_data';
  ///
  /// import "package:convert/convert.dart";
  /// import 'package:merkletree/merkletree.dart';
  /// import "package:pointycastle/pointycastle.dart";
  ///
  /// Uint8List sha3(Uint8List data) {
  ///   Digest sha3 = new Digest("SHA-3/256");
  ///   return sha3.process(data);
  /// }
  ///
  /// List<Uint8List> leaves = ['a', 'b', 'c'].map((x) => Uint8List.fromList(x.codeUnits)).map((x) => sha3(x)).toList();
  /// var tree = new MerkleTree(leaves: leaves, hashAlgo: sha256);
  /// ```
  MerkleTree(
      {@required this.leaves,
      @required this.hashAlgo,
      this.isBitcoinTree = false}) {
    this._layers = [this.leaves];
    this._createHashes(this.leaves);
  }

  _createHashes(List<Uint8List> nodes) {
    while (nodes.length > 1) {
      int layerIndex = this._layers.length;

      this._layers.add([]);

      for (int i = 0; i < nodes.length - 1; i += 2) {
        Uint8List left = nodes[i];
        Uint8List right = nodes[i + 1];
        Uint8List data;

        if (this.isBitcoinTree) {
          data = MerkleTreeUtils.bufferConcat([
            MerkleTreeUtils.bufferReverse(left),
            MerkleTreeUtils.bufferReverse(right)
          ]);
        } else {
          data = MerkleTreeUtils.bufferConcat([left, right]);
        }

        var hash = this.hashAlgo(data);

        // double hash if bitcoin tree
        if (this.isBitcoinTree) {
          hash = MerkleTreeUtils.bufferReverse(this.hashAlgo(hash));
        }

        this._layers[layerIndex].add(hash);
      }

      // is odd number of nodes
      if (nodes.length % 2 == 1) {
        var data = nodes[nodes.length - 1];
        var hash = data;

        // is bitcoin tree
        if (this.isBitcoinTree) {
          // Bitcoin method of duplicating the odd ending nodes
          data = MerkleTreeUtils.bufferConcat([
            MerkleTreeUtils.bufferReverse(data),
            MerkleTreeUtils.bufferReverse(data)
          ]);
          hash = this.hashAlgo(data);
          hash = MerkleTreeUtils.bufferReverse(this.hashAlgo(hash));
        }

        this._layers[layerIndex].add(hash);
      }

      nodes = this._layers[layerIndex];
    }
  }

  /// Returns array of all layers of Merkle Tree, including leaves and root.
  List<List<Uint8List>> get layers {
    return this._layers;
  }

  /// Returns the Merkle root hash as a Buffer.
  Uint8List get root {
    if (this._layers.length == 0) {
      return Uint8List(0);
    }

    if (this._layers[this._layers.length - 1].length == 0) {
      return Uint8List(0);
    }

    return this._layers[this._layers.length - 1][0] ?? Uint8List(0);
  }

  /// Returns the proof for a target leaf.
  /// [leaf] is the target leaf for this proof.
  /// [index] is the target leaf index in leaves array. Use only if there are leaves containing duplicate data in order to distinguish it.
  ///
  /// ```dart
  /// var proof = tree.getProof(leaf: leaves[2]);
  /// ```
  ///
  /// ```dart
  /// var leaves = ['a', 'b', 'a'].map((x) => Uint8List.fromList(x.codeUnits)).map((x) => sha3(x)).toList();
  /// var tree = MerkleTree(leaves: leaves, hashAlgo: sha3);
  /// var proof = tree.getProof(leaf: leaves[2], index: 2);
  /// ```
  List<MerkleProof> getProof({@required Uint8List leaf, int index = -1}) {
    List<MerkleProof> proof = [];

    if (index == -1) {
      for (int i = 0; i < this.leaves.length; i++) {
        if (MerkleTreeUtils.bufferCompare(leaf, this.leaves[i]) == 0) {
          index = i;
        }
      }
    }

    if (index <= -1) {
      return [];
    }

    if (this.isBitcoinTree && index == (this.leaves.length - 1)) {
      // Proof Generation for Bitcoin Trees

      for (int i = 0; i < this._layers.length - 1; i++) {
        var layer = this._layers[i];
        var isRightNode = index % 2 == 1;
        var pairIndex = (isRightNode ? index - 1 : index);

        if (pairIndex < layer.length) {
          proof.add(MerkleProof(
              position: isRightNode
                  ? MerkleProofPosition.left
                  : MerkleProofPosition.right,
              data: layer[pairIndex]));
        }

        // set index to parent index
        index = (index / 2).floor();
      }

      return proof;
    } else {
      // Proof Generation for Non-Bitcoin Trees

      for (int i = 0; i < this._layers.length; i++) {
        var layer = this._layers[i];
        var isRightNode = index % 2 == 1;
        var pairIndex = (isRightNode ? index - 1 : index + 1);

        if (pairIndex < layer.length) {
          proof.add(MerkleProof(
              position: isRightNode
                  ? MerkleProofPosition.left
                  : MerkleProofPosition.right,
              data: layer[pairIndex]));
        }

        // set index to parent index
        index = (index / 2).floor();
      }

      return proof;
    }
  }

  /// Returns true if the proof path (array of hashes) can connect the target node to the Merkle root.
  /// [proof] is a list of [MerkleProof] objects that should connect target node to Merkle root.
  /// [targetNode] is the target node buffer.
  /// [root] is the Merkle root Buffer.
  ///
  /// ```dart
  /// var root = tree.getRoot();
  /// var proof = tree.getProof(leaf: leaves[2]);
  /// var verified = tree.verify(proof: proof, targetNode: leaves[2], root: root);
  /// ```
  bool verify(
      {@required List<MerkleProof> proof,
      @required Uint8List targetNode,
      @required Uint8List root}) {
    var hash = targetNode;

    if (proof.length == 0 || targetNode.length == 0 || root.length == 0) {
      return false;
    }

    for (int i = 0; i < proof.length; i++) {
      var node = proof[i];
      var isLeftNode = (node.position == MerkleProofPosition.left);
      List<Uint8List> buffers = [];

      if (this.isBitcoinTree) {
        buffers.add(MerkleTreeUtils.bufferReverse(hash));

        if (isLeftNode) {
          buffers.insert(0, MerkleTreeUtils.bufferReverse(node.data));
        } else {
          buffers.add(MerkleTreeUtils.bufferReverse(node.data));
        }

        hash = this.hashAlgo(MerkleTreeUtils.bufferConcat(buffers));
        hash = MerkleTreeUtils.bufferReverse(this.hashAlgo(hash));
      } else {
        buffers.add(hash);

        if (isLeftNode) {
          buffers.insert(0, node.data);
        } else {
          buffers.add(node.data);
        }

        hash = this.hashAlgo(MerkleTreeUtils.bufferConcat(buffers));
      }
    }

    return MerkleTreeUtils.bufferCompare(hash, root) == 0;
  }
}

class MerkleProof {
  MerkleProofPosition position;
  Uint8List data;
  MerkleProof({@required this.position, @required this.data});
}

enum MerkleProofPosition { left, right }
