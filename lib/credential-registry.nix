# Registry-shape validation for a rotation-registry-style credential
# registry: `credentialRegistryDiagnostics` names every problem with a
# registry, empty when there is none; `validateCredentialRegistry` asserts
# that and returns the registry unchanged. Moved out of flake.nix by
# allod/secrets#37.
{ lib, credentialEncodings }:
rec {
  credentialRegistryDiagnostics = registry:
    let
      isBlankString = value: builtins.match "[[:space:]]*" value != null;
      isOneLineCommand = value:
        builtins.isString value &&
        !(isBlankString value) &&
        !(lib.hasInfix "\n" value) &&
        !(lib.hasInfix "\r" value);
      hasExactlyOneSecret = template:
        builtins.isString template &&
        builtins.length (lib.splitString "{secret}" template) == 2;
      valueDiagnostics = value:
        if !builtins.isAttrs value then [ "value must be an attribute set" ]
        else
          let
            fields = builtins.attrNames value;
            allowedFields = [ "encode" "template" ];
            extraFields = builtins.filter (field: !(builtins.elem field allowedFields)) fields;
            missingTemplate = !(builtins.hasAttr "template" value);
            badTemplate = !missingTemplate && !(hasExactlyOneSecret value.template);
            badEncode = builtins.hasAttr "encode" value &&
              (!(builtins.isString value.encode) || !(builtins.elem value.encode credentialEncodings));
          in
            lib.optional (extraFields != []) "value has fields outside template and optional encode" ++
            lib.optional missingTemplate "value is missing template" ++
            lib.optional badTemplate "value.template must contain exactly one {secret}" ++
            lib.optional badEncode "value.encode is not an exported encoding";
      isNewShapeCredential = credential:
        builtins.isAttrs credential && !(builtins.hasAttr "format" credential);
      credentialEncoding = credential:
        if builtins.isAttrs credential &&
           builtins.hasAttr "value" credential &&
           builtins.isAttrs credential.value &&
           builtins.hasAttr "encode" credential.value &&
           builtins.isString credential.value.encode
        then credential.value.encode
        else null;
      credentialDiagnostics = credential:
        if !builtins.isAttrs credential then [ "credential must be an attribute set" ]
        else
          let
            hasValue = builtins.hasAttr "value" credential;
            # A credential's own "credential" name field is itself
            # unvalidated at this point, so a malformed registry entry
            # (missing name, or a non-string name) must not make the format
            # refusal's own message throw: toString aborts evaluation on an
            # attrset or null instead of producing a diagnostic.
            credentialName =
              if builtins.hasAttr "credential" credential && builtins.isString credential.credential
              then credential.credential
              else "?";
            targets = if builtins.hasAttr "targets" credential && builtins.isList credential.targets
              then credential.targets
              else [];
            missingTargets = !(builtins.hasAttr "targets" credential) || !builtins.isList credential.targets;
            emptyTargets = !missingTargets && targets == [];
            targetVerifies = map (target:
              if builtins.isAttrs target && builtins.hasAttr "verify" target
              then target.verify
              else null
            ) targets;
            # Classify each target's verify so a credential with several bad
            # targets can surface more than one kind of problem without one
            # masking another: missing, present but not a string, or a string
            # that fails the one-line-command shape.
            verifyIssueKinds = lib.unique (builtins.filter (kind: kind != null) (map (verify:
              if verify == null then "missing"
              else if !(builtins.isString verify) then "non-string"
              else if !(isOneLineCommand verify) then "bad-format"
              else null
            ) targetVerifies));
          in
            lib.optional missingTargets "credential targets must be a list" ++
            lib.optional emptyTargets "credential must declare at least one target" ++
            lib.optional (builtins.hasAttr "format" credential)
              "credential '${credentialName}' carries 'format', which the registry no longer accepts; declare a value template instead" ++
            lib.optional (builtins.elem "non-string" verifyIssueKinds)
              "target verify must be a string command" ++
            lib.optional
              (builtins.elem "missing" verifyIssueKinds || builtins.elem "bad-format" verifyIssueKinds)
              "new targets require a non-empty one-line verify command" ++
            (if hasValue then valueDiagnostics credential.value else []);
      groupDiagnostics = group:
        if !builtins.isAttrs group ||
           !(builtins.hasAttr "credentials" group) ||
           !builtins.isList group.credentials
        then [ "group credentials must be a list" ]
        else
          let
            # A credential carrying format is refused on its own account, so
            # it is filtered out here too: any stray value.encode it also
            # carries never forces or breaks its group's compatibility check.
            encodings = map credentialEncoding
              (builtins.filter isNewShapeCredential group.credentials);
          in
            lib.optional (group.credentials == []) "group must declare at least one credential" ++
            lib.concatMap credentialDiagnostics group.credentials ++
            lib.optional (builtins.length (lib.unique encodings) > 1)
              "credentials in a group must use one compatible encoding";
    in
      if !builtins.isAttrs registry then [ "registry must be an attribute set" ]
      else lib.concatMap (name: groupDiagnostics registry.${name}) (builtins.attrNames registry);
  validateCredentialRegistry = registry:
    let diagnostics = credentialRegistryDiagnostics registry;
    in assert lib.assertMsg (diagnostics == [])
      "credential-registry: ${lib.concatStringsSep "; " diagnostics}";
      registry;
}
