{ lib, credentialStoreUrl }:
rec {
  # A blank line is one holding only spaces and tabs, not `[[:space:]]`:
  # modules/netrc.nix in allod/archetypes drops lines with `awk 'NF { print }'`,
  # and awk's default field splitting separates on space, tab and newline
  # alone, so a line holding only a carriage return survives there.  A wider
  # class here would accept a template whose deployed file fails activation.
  #
  # The grammar and the `format` policy are separate predicates so a consumer
  # that has its own rule for `format` composes the grammar half instead of
  # respelling it.
  isCredentialStoreUrlTemplate = credential:
    let
      value =
        if builtins.isAttrs credential && builtins.isAttrs (credential.value or null)
        then credential.value
        else null;
      template = if value == null then null else value.template or null;
      nonBlankLines =
        if builtins.isString template then
          builtins.filter
            (line: builtins.match credentialStoreUrl.blank_line line == null)
            (lib.splitString "\n" template)
        else [];
    in
      builtins.isString template &&
      (value.encode or null) == null &&
      builtins.length (lib.splitString "{secret}" template) == 2 &&
      builtins.length nonBlankLines == 1 &&
      builtins.match credentialStoreUrl.line (builtins.head nonBlankLines) != null;
  
  # This registry's own policy: a credential carrying `format` is an unknown
  # shape, and this fails it closed rather than guess what it renders to.
  isCredentialStoreUrlSource = credential:
    builtins.isAttrs credential &&
    !(credential ? format) &&
    isCredentialStoreUrlTemplate credential;
  
  # Named once so a sabotage fixture can require this clause by its text
  # instead of settling for "some diagnostic".
  credentialStoreUrlSourceClause = "is not a credential-store URL source";
}
