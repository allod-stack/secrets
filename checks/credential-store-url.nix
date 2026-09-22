{ lib, pkgs, credentialStoreUrl, isCredentialStoreUrlSource, isCredentialStoreUrlTemplate }:
  let
    vectors = credentialStoreUrl.vectors;
    verdict = vector: isCredentialStoreUrlSource vector.credential;
    word = accept: if accept then "accept" else "reject";
    disagreeing = builtins.filter (vector: vector.accept != verdict vector) vectors;
    disagreeingText = lib.concatMapStringsSep "; "
      (vector: "${vector.name}: the table says ${word vector.accept}, the predicate says ${word (verdict vector)}")
      disagreeing;
    accepted = builtins.filter (vector: vector.accept) vectors;
    rejected = builtins.filter (vector: !vector.accept) vectors;

    # The composition law: on a vector whose credential carries no
    # `format`, the two predicates must give the same answer, because
    # the only clause between them is the `format` guard.  A vector that
    # does carry `format` is left out: its answer is exactly what a
    # consumer with its own format policy is free to decide, and this
    # flake's policy is already pinned by the assertion above.
    formatFree = builtins.filter
      (vector: !(builtins.isAttrs vector.credential && vector.credential ? format))
      vectors;
    templateVerdict = vector: isCredentialStoreUrlTemplate vector.credential;
    lawBreaking = builtins.filter
      (vector: vector.accept != templateVerdict vector)
      formatFree;
    lawBreakingText = lib.concatMapStringsSep "; "
      (vector: "${vector.name}: the table says ${word vector.accept}, the template predicate says ${word (templateVerdict vector)}")
      lawBreaking;
  in
  # A table with only accept vectors, or only reject ones, would agree
  # with a predicate that answers the same thing every time.
  assert lib.assertMsg (accepted != [])
    "credential-store-url: the vector table holds no accept vector";
  assert lib.assertMsg (rejected != [])
    "credential-store-url: the vector table holds no reject vector";
  assert lib.assertMsg (disagreeing == [])
    "credential-store-url: vectors the predicate disagrees with: ${disagreeingText}";
  assert lib.assertMsg (lawBreaking == [])
    "credential-store-url: format-free vectors the template predicate disagrees with: ${lawBreakingText}";
  pkgs.runCommand "credential-store-url-check" {} ''
    echo "credential-store-url predicate agreed with ${toString (builtins.length accepted)} accept and ${toString (builtins.length rejected)} reject vectors, ${toString (builtins.length formatFree)} of them also pinning the template predicate"
    touch $out
  ''
