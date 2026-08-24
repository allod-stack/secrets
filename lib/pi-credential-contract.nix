{ lib }:
{
  registry,
  machines,
  devVMs,
  machineHostKeys,
  nexusName,
  nexusPublicKeys ? null,
  ciphertextRoot,
  ciphertextExists ? builtins.pathExists,
  declaredRecipients ? null,
}:
let
  schema = import ./pi-credential-schema.nix { inherit registry; };
  inherit (schema)
    allProviders
    credentialIds
    duplicateProviders
    providersFor
    safeRegistry
    targetsFor
    tokensFor
    unique
    validId
    ;
  duplicates = values:
    builtins.filter
      (value: builtins.length (builtins.filter (other: other == value) values) > 1)
      (unique values);
  allTargets = unique (builtins.concatLists (map targetsFor credentialIds));
  unknownTargets = builtins.filter
    (target: !(builtins.isString target) || !(builtins.hasAttr target machines))
    allTargets;
  knownTargets = builtins.filter
    (target: builtins.isString target && builtins.hasAttr target machines)
    allTargets;
  unsupportedTargets = builtins.filter
    (target:
      let machine = machines.${target};
      in !(builtins.isAttrs machine)
         || !(machine ? type)
         || machine.type != "dev"
         || !(machine ? runtime)
         || machine.runtime != "libvirt"
         || !(builtins.hasAttr target devVMs))
    knownTargets;

  # Each named token owns one ciphertext under the credential's directory.
  relativeCiphertextPath = id: token: "secrets/pi-credentials/${id}/${token}.age";
  ciphertextPath = id: token: ciphertextRoot + "/pi-credentials/${id}/${token}.age";
  # Only well-formed names can derive a path; malformed ones are already a
  # schema error and must not turn path derivation into an interpolation crash.
  tokenPairs = builtins.concatLists (map
    (id: map
      (token: { credential = id; inherit token; })
      (builtins.filter schema.validTokenName (tokensFor id)))
    credentialIds);
  missingCiphertexts = builtins.filter
    (pair: !(ciphertextExists (ciphertextPath pair.credential pair.token)))
    tokenPairs;

  # External callers that omit nexusPublicKeys use their historical hypervisor
  # record as the compatibility source. New callers keep hypervisor identity
  # out of the VM registry, so every remaining record is an independent source.
  effectiveMachineHostKeys =
    if nexusPublicKeys == null
    then builtins.removeAttrs machineHostKeys [ nexusName ]
    else machineHostKeys;
  referencedMachineNames = builtins.attrNames effectiveMachineHostKeys;
  missingMachineKeys = builtins.filter
    (name: !(builtins.hasAttr name effectiveMachineHostKeys))
    knownTargets;
  presentMachineNames = builtins.filter
    (name: builtins.hasAttr name effectiveMachineHostKeys)
    referencedMachineNames;
  badMachineKeys = builtins.filter
    (name:
      let keys = effectiveMachineHostKeys.${name};
      in !(builtins.isAttrs keys)
         || !(keys ? active)
         || !(builtins.isString keys.active)
         || keys.active == ""
         || !(keys ? staged)
         || !(keys.staged == null
              || (builtins.isString keys.staged && keys.staged != "")))
    presentMachineNames;
  legacyNexusRecordPresent = builtins.hasAttr nexusName machineHostKeys;
  legacyNexusRecordValid = legacyNexusRecordPresent
    && (let keys = machineHostKeys.${nexusName};
        in builtins.isAttrs keys
           && keys ? active
           && builtins.isString keys.active
           && keys.active != ""
           && keys ? staged
           && (keys.staged == null
               || (builtins.isString keys.staged && keys.staged != "")));
  resolvedNexusPublicKeys =
    if nexusPublicKeys != null
    then nexusPublicKeys
    else if legacyNexusRecordValid
    then let keys = machineHostKeys.${nexusName};
         in [ keys.active ] ++ (if keys.staged == null then [] else [ keys.staged ])
    else [];
  nexusPublicKeysHaveShape = builtins.isList resolvedNexusPublicKeys
    && resolvedNexusPublicKeys != []
    && builtins.all (key: builtins.isString key && key != "") resolvedNexusPublicKeys;
  safeNexusPublicKeys =
    if nexusPublicKeysHaveShape then resolvedNexusPublicKeys else [];
  validNexusPublicKeys = nexusPublicKeysHaveShape
    && builtins.length safeNexusPublicKeys
       == builtins.length (unique safeNexusPublicKeys);
  allRecipientKeys = safeNexusPublicKeys ++ builtins.concatLists (map
    (name:
      let keys = effectiveMachineHostKeys.${name};
      in if builtins.elem name badMachineKeys
         then []
         else [ keys.active ] ++ (if keys.staged == null then [] else [ keys.staged ]))
    presentMachineNames);
  duplicateRecipientKeys = duplicates allRecipientKeys;

  schemaErrors = schema.errors;

  referenceErrors =
    lib.optional (duplicateProviders != []) "providers referenced by multiple credentials: ${lib.concatStringsSep ", " duplicateProviders}"
    ++ lib.optional (unknownTargets != []) "unknown targets: ${lib.concatStringsSep ", " unknownTargets}"
    ++ lib.optional (unsupportedTargets != []) "targets must be libvirt dev VMs with identities: ${lib.concatStringsSep ", " unsupportedTargets}"
    ++ lib.optional (missingCiphertexts != []) "missing ciphertexts: ${lib.concatMapStringsSep ", " (pair: relativeCiphertextPath pair.credential pair.token) missingCiphertexts}";

  derivedRecipients =
    if schemaErrors == []
       && unknownTargets == []
       && missingMachineKeys == []
       && badMachineKeys == []
       && validNexusPublicKeys
       && duplicateRecipientKeys == []
    then import ./pi-credential-recipients.nix {
      inherit registry;
      machineHostKeys = effectiveMachineHostKeys;
      nexusPublicKeys = resolvedNexusPublicKeys;
    }
    else {};

  declaredPiRecipients =
    if declaredRecipients == null || !(builtins.isAttrs declaredRecipients)
    then null
    else lib.filterAttrs
      (path: _: lib.hasPrefix "secrets/pi-credentials/" path)
      declaredRecipients;

  recipientErrors =
    lib.optional (missingMachineKeys != []) "recipient machines missing host keys: ${lib.concatStringsSep ", " missingMachineKeys}"
    ++ lib.optional (badMachineKeys != []) "recipient host-key records are invalid: ${lib.concatStringsSep ", " badMachineKeys}"
    ++ lib.optional (!validNexusPublicKeys) "hypervisor recipient keys must be a non-empty unique list of non-empty strings"
    ++ lib.optional (duplicateRecipientKeys != []) "recipient host keys are duplicated: ${lib.concatStringsSep ", " duplicateRecipientKeys}"
    ++ lib.optional (declaredRecipients != null && !(builtins.isAttrs declaredRecipients)) "declared recipient map must be an object"
    ++ lib.optional (declaredPiRecipients != null && declaredPiRecipients != derivedRecipients) "declared Pi recipients drift from the credential registry";

  diagnostics = {
    schema = schemaErrors;
    references = referenceErrors;
    recipients = recipientErrors;
  };

  providerCredentialsRaw = builtins.listToAttrs (builtins.concatLists (map
    (credential: map
      (provider: { name = provider; value = credential; })
      (providersFor credential))
    credentialIds));

  credentialInventoryRaw = builtins.mapAttrs
    (credential: _: {
      name = credential;
      kind = "service";
      owner = "pi";
      public_key = null;
      consumers = map
        (token: {
          type = "agenix";
          repo = "secrets";
          secret = relativeCiphertextPath credential token;
        })
        (tokensFor credential);
      rotation_state = "active";
    })
    safeRegistry;

  projectionFor = target:
    let
      targetCredentials = lib.filterAttrs
        (_: entry: builtins.elem target entry.targets)
        safeRegistry;
      targetProviderCredentials = lib.filterAttrs
        (_: credential: builtins.hasAttr credential targetCredentials)
        providerCredentialsRaw;
    in {
      # Names and paths only: no endpoint metadata and no bearer value ever
      # reaches a per-VM projection.
      credentials = builtins.mapAttrs
        (credential: entry: {
          providers = entry.providers;
          tokens = builtins.listToAttrs (map
            (token: {
              name = token;
              value.file = ciphertextPath credential token;
            })
            entry.tokens);
          defaultToken = entry.defaultToken;
        })
        targetCredentials;
      providers = targetProviderCredentials;
    };

  projectionsRaw = builtins.mapAttrs (target: _: projectionFor target) devVMs;

  checkedRegistry =
    assert lib.assertMsg (schemaErrors == [])
      "pi-credential-registry: ${lib.concatStringsSep "; " schemaErrors}";
    assert lib.assertMsg (referenceErrors == [])
      "pi-credential-registry: ${lib.concatStringsSep "; " referenceErrors}";
    assert lib.assertMsg (recipientErrors == [])
      "pi-credential-registry: ${lib.concatStringsSep "; " recipientErrors}";
    safeRegistry;

  validateProviderReferences = knownProviderIds:
    let
      knownIdsValid = builtins.isList knownProviderIds
        && builtins.all validId knownProviderIds
        && builtins.length knownProviderIds == builtins.length (unique knownProviderIds);
      unknownProviders =
        if knownIdsValid
        then builtins.filter (provider: !(builtins.elem provider knownProviderIds)) allProviders
        else [];
    in
    assert builtins.seq checkedRegistry true;
    assert lib.assertMsg knownIdsValid
      "pi-credential-registry: known provider IDs must be a unique ID list";
    assert lib.assertMsg (unknownProviders == [])
      "pi-credential-registry: unknown providers: ${lib.concatStringsSep ", " unknownProviders}";
    providerCredentialsRaw;
in
{
  inherit diagnostics validateProviderReferences;
  registry = checkedRegistry;
  ciphertextPaths = builtins.mapAttrs
    (credential: _: builtins.listToAttrs (map
      (token: { name = token; value = ciphertextPath credential token; })
      (tokensFor credential)))
    checkedRegistry;
  credentialInventory = builtins.seq checkedRegistry credentialInventoryRaw;
  providerCredentials = builtins.seq checkedRegistry providerCredentialsRaw;
  projections = builtins.seq checkedRegistry projectionsRaw;
  recipients = builtins.seq checkedRegistry derivedRecipients;
}
