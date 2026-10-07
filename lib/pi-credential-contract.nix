{ lib }:
{
  registry,
  machines,
  devVMs,
  machineHostKeys,
  nexusName ? null,
  hypervisorPublicKeys ? null,
  ciphertextRoot,
  ciphertextExists ? builtins.pathExists,
  declaredRecipients ? null,
}:
let
  schema = import ./pi-credential-schema.nix { inherit registry; };
  inherit (schema)
    allProviders
    credentialIds
    duplicateProviderTargets
    providersFor
    safeRegistry
    targetNameOf
    targetNamesFor
    targetTokenOf
    targetsFor
    tokensFor
    unique
    validId
    ;
  duplicates = values:
    builtins.filter
      (value: builtins.length (builtins.filter (other: other == value) values) > 1)
      (unique values);
  allTargetNames = unique (builtins.concatLists (map targetNamesFor credentialIds));
  unknownTargets = builtins.filter
    (target: !(builtins.isString target) || !(builtins.hasAttr target machines))
    allTargetNames;
  knownTargets = builtins.filter
    (target: builtins.isString target && builtins.hasAttr target machines)
    allTargetNames;
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

  # External callers that omit hypervisorPublicKeys use their historical
  # hypervisor record as the compatibility source. Only that path requires
  # nexusName. New callers keep hypervisor identity out of the VM registry, so
  # every remaining record is an independent source.
  usesCompatibilityFallback = hypervisorPublicKeys == null;
  validCompatibilityNexusName = builtins.isString nexusName && nexusName != "";
  effectiveMachineHostKeys =
    if usesCompatibilityFallback && validCompatibilityNexusName
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
  legacyNexusRecordPresent = validCompatibilityNexusName
    && builtins.hasAttr nexusName machineHostKeys;
  legacyNexusRecordValid = legacyNexusRecordPresent
    && (let keys = machineHostKeys.${nexusName};
        in builtins.isAttrs keys
           && keys ? active
           && builtins.isString keys.active
           && keys.active != ""
           && keys ? staged
           && (keys.staged == null
               || (builtins.isString keys.staged && keys.staged != "")));
  resolvedHypervisorPublicKeys =
    if hypervisorPublicKeys != null
    then hypervisorPublicKeys
    else if legacyNexusRecordValid
    then let keys = machineHostKeys.${nexusName};
         in [ keys.active ] ++ (if keys.staged == null then [] else [ keys.staged ])
    else [];
  hypervisorPublicKeysHaveShape = builtins.isList resolvedHypervisorPublicKeys
    && resolvedHypervisorPublicKeys != []
    && builtins.all (key: builtins.isString key && key != "") resolvedHypervisorPublicKeys;
  safeHypervisorPublicKeys =
    if hypervisorPublicKeysHaveShape then resolvedHypervisorPublicKeys else [];
  validHypervisorPublicKeys = hypervisorPublicKeysHaveShape
    && builtins.length safeHypervisorPublicKeys
       == builtins.length (unique safeHypervisorPublicKeys);
  allRecipientKeys = safeHypervisorPublicKeys ++ builtins.concatLists (map
    (name:
      let keys = effectiveMachineHostKeys.${name};
      in if builtins.elem name badMachineKeys
         then []
         else [ keys.active ] ++ (if keys.staged == null then [] else [ keys.staged ]))
    presentMachineNames);
  duplicateRecipientKeys = duplicates allRecipientKeys;

  schemaErrors = schema.errors;

  referenceErrors =
    lib.optional (duplicateProviderTargets != []) "providers referenced by multiple credentials for the same target: ${lib.concatStringsSep ", " duplicateProviderTargets}"
    ++ lib.optional (unknownTargets != []) "unknown targets: ${lib.concatStringsSep ", " unknownTargets}"
    ++ lib.optional (unsupportedTargets != []) "targets must be libvirt dev VMs with identities: ${lib.concatStringsSep ", " unsupportedTargets}"
    ++ lib.optional (missingCiphertexts != []) "missing ciphertexts: ${lib.concatMapStringsSep ", " (pair: relativeCiphertextPath pair.credential pair.token) missingCiphertexts}";

  derivedRecipients =
    if schemaErrors == []
       && unknownTargets == []
       && missingMachineKeys == []
       && badMachineKeys == []
       && validHypervisorPublicKeys
       && duplicateRecipientKeys == []
    then import ./pi-credential-recipients.nix {
      inherit registry;
      machineHostKeys = effectiveMachineHostKeys;
      hypervisorPublicKeys = resolvedHypervisorPublicKeys;
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
    ++ lib.optional (usesCompatibilityFallback && !validCompatibilityNexusName) "nexusName is required when hypervisorPublicKeys is omitted"
    ++ lib.optional ((!usesCompatibilityFallback || validCompatibilityNexusName) && !validHypervisorPublicKeys) "hypervisor recipient keys must be a non-empty unique list of non-empty strings"
    ++ lib.optional (duplicateRecipientKeys != []) "recipient host keys are duplicated: ${lib.concatStringsSep ", " duplicateRecipientKeys}"
    ++ lib.optional (declaredRecipients != null && !(builtins.isAttrs declaredRecipients)) "declared recipient map must be an object"
    ++ lib.optional (declaredPiRecipients != null && declaredPiRecipients != derivedRecipients) "declared Pi recipients drift from the credential registry";

  diagnostics = {
    schema = schemaErrors;
    references = referenceErrors;
    recipients = recipientErrors;
  };

  # A flat provider -> credential map, for callers that need the common
  # case of one credential per provider. A provider legitimately split
  # across credentials for disjoint targets has no single answer here;
  # `providerCredentialsChecked` throws for that case and sends per-target
  # callers to `projections` instead.
  providerCredentialsRaw = builtins.listToAttrs (builtins.concatLists (map
    (credential: map
      (provider: { name = provider; value = credential; })
      (providersFor credential))
    credentialIds));
  providersInMultipleCredentials = duplicates allProviders;
  providerCredentialsChecked =
    if providersInMultipleCredentials != []
    then throw "pi-credential-contract: provider claimed by more than one credential, use `projections` for per-target consumers: ${lib.concatStringsSep ", " providersInMultipleCredentials}"
    else providerCredentialsRaw;

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

  # A target resolves its token through its own entry's override, if the
  # credential named one for it, else through the credential's default
  # (today's meaning, unchanged). An overridden target's projection is
  # narrowed to that one token: it is never a recipient of the credential's
  # other ciphertexts, so listing them would promise access it doesn't have.
  # Symmetrically, a shared (plain-string) target's projection drops any
  # token claimed by another target's override, since that ciphertext's
  # recipients narrowed to the override alone.
  tokenOverrideFor = target: entry:
    let
      matches = builtins.filter
        (e: !(builtins.isString e) && targetNameOf e == target)
        entry.targets;
    in if matches == [] then null else targetTokenOf (builtins.head matches);
  claimedTokensOf = entry:
    unique (builtins.concatMap
      (e: if builtins.isString e then [] else [ (targetTokenOf e) ])
      entry.targets);

  projectionFor = target:
    let
      targetCredentials = lib.filterAttrs
        (_: entry: builtins.elem target (map targetNameOf entry.targets))
        safeRegistry;
      targetProviderCredentials = builtins.listToAttrs (builtins.concatLists (map
        (credential: map
          (provider: { name = provider; value = credential; })
          (providersFor credential))
        (builtins.attrNames targetCredentials)));
    in {
      # Names and paths only: no endpoint metadata and no bearer value ever
      # reaches a per-VM projection.
      credentials = builtins.mapAttrs
        (credential: entry:
          let override = tokenOverrideFor target entry;
          in {
            providers = entry.providers;
            tokens =
              if override == null
              then builtins.listToAttrs (map
                (token: {
                  name = token;
                  value.file = ciphertextPath credential token;
                })
                (builtins.filter
                  (token: !(builtins.elem token (claimedTokensOf entry)))
                  entry.tokens))
              else builtins.listToAttrs [
                {
                  name = override;
                  value.file = ciphertextPath credential override;
                }
              ];
            defaultToken = if override == null then entry.defaultToken else override;
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
  providerCredentials = builtins.seq checkedRegistry providerCredentialsChecked;
  projections = builtins.seq checkedRegistry projectionsRaw;
  recipients = builtins.seq checkedRegistry derivedRecipients;
}
