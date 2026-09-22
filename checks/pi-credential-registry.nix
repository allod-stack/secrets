{ lib, pkgs, mkPiCredentialContract, piCredentialContract, secretsNix }:
  let
    fixtureRegistry = {
      shared = {
        targets = [ "dev-a" "dev-b" ];
        providers = [ "alpha" "beta" ];
        tokens = [ "primary" "secondary" ];
        defaultToken = "primary";
      };
      solo = {
        targets = [ "dev-b" ];
        providers = [ "gamma" ];
        tokens = [ "only" ];
        defaultToken = null;
      };
    };
    fixtureMachines = {
      dev-a = { type = "dev"; runtime = "libvirt"; };
      dev-b = { type = "dev"; runtime = "libvirt"; };
      privacy-a = { type = "privacy"; runtime = "libvirt"; };
      forge-host = { type = "hypervisor"; };
    };
    fixtureDevVMs = {
      dev-a = {};
      dev-b = {};
    };
    fixtureKeys = {
      dev-a = { active = "dev-a-active"; staged = null; };
      dev-b = { active = "dev-b-active"; staged = "dev-b-staged"; };
      privacy-a = { active = "privacy-a-active"; staged = null; };
    };
    fixtureHypervisorPublicKeys = [ "forge-host-active" "forge-host-staged" ];
    fixtureArgs = {
      registry = fixtureRegistry;
      machines = fixtureMachines;
      devVMs = fixtureDevVMs;
      machineHostKeys = fixtureKeys;
      hypervisorPublicKeys = fixtureHypervisorPublicKeys;
      ciphertextRoot = "/synthetic-secrets";
      ciphertextExists = _: true;
    };
    fixtureWithoutDeclared = mkPiCredentialContract fixtureArgs;
    fixture = mkPiCredentialContract (fixtureArgs // {
      declaredRecipients = fixtureWithoutDeclared.recipients;
    });
    rejects = args:
      !(builtins.tryEval
        (builtins.deepSeq (mkPiCredentialContract args) true)).success;
    rejectsProviderReferences = known:
      !(builtins.tryEval
        (builtins.deepSeq (fixture.validateProviderReferences known) true)).success;
    rejectsStandaloneRecipientsWith = registry: keys: hypervisorKeys:
      !(builtins.tryEval (builtins.deepSeq
        (import ../lib/pi-credential-recipients.nix {
          inherit registry;
          machineHostKeys = keys;
          hypervisorPublicKeys = hypervisorKeys;
        })
        true)).success;
    rejectsStandaloneRecipients = registry:
      rejectsStandaloneRecipientsWith
        registry fixtureKeys fixtureHypervisorPublicKeys;

    withShared = overrides: fixtureArgs // {
      registry = fixtureRegistry // {
        shared = fixtureRegistry.shared // overrides;
      };
    };

    schemaSabotage = withShared { unexpected = true; };
    standaloneSchemaSabotage = {
      "../escape" = {
        targets = [ "dev-a" ];
        providers = [];
        tokens = [];
        defaultToken = "absent";
        unexpected = true;
      };
    };
    duplicateProviderSabotage = fixtureArgs // {
      registry = fixtureRegistry // {
        second = {
          targets = [ "dev-a" ];
          providers = [ "alpha" ];
          tokens = [ "primary" ];
          defaultToken = "primary";
        };
      };
    };
    unsupportedTargetSabotage = withShared { targets = [ "privacy-a" ]; };
    unknownTargetSabotage = withShared { targets = [ "missing-dev" ]; };
    # A record still carrying the retired rotation strategy is now an
    # unknown field, not a tolerated leftover.
    rotationStrategySabotage = withShared { rotationStrategy = "overlap"; };
    missingTokenFieldSabotage = fixtureArgs // {
      registry = fixtureRegistry // {
        shared = builtins.removeAttrs fixtureRegistry.shared [ "tokens" ];
      };
    };
    emptyTokensSabotage = withShared {
      tokens = [];
      defaultToken = null;
    };
    duplicateTokenSabotage = withShared {
      tokens = [ "primary" "primary" ];
    };
    invalidTokenNameSabotage = withShared {
      tokens = [ "primary" "9-leading-digit" ];
    };
    reservedTokenNameSabotage = withShared {
      tokens = [ "primary" "none" ];
    };
    unlistedDefaultSabotage = withShared { defaultToken = "absent"; };
    nonStringDefaultSabotage = withShared { defaultToken = true; };
    missingCiphertextSabotage = fixtureArgs // {
      ciphertextExists = _: false;
    };
    missingOneCiphertextSabotage = fixtureArgs // {
      ciphertextExists = path:
        path != "/synthetic-secrets/pi-credentials/shared/secondary.age";
    };
    recipientSabotage = fixtureArgs // {
      declaredRecipients = fixtureWithoutDeclared.recipients // {
        "secrets/pi-credentials/shared/secondary.age".publicKeys = [
          "forge-host-active"
          "dev-a-active"
          "dev-b-active"
          "dev-b-staged"
        ];
      };
    };
    invalidHypervisorRecipientSabotage = fixtureArgs // {
      hypervisorPublicKeys = [];
    };
    malformedHypervisorRecipientSabotage = fixtureArgs // {
      hypervisorPublicKeys = "not-a-list";
    };
    malformedHypervisorRecipientDiagnostics =
      (mkPiCredentialContract malformedHypervisorRecipientSabotage).diagnostics.recipients;
    duplicateHypervisorRecipientSabotage = fixtureArgs // {
      hypervisorPublicKeys = [ "forge-host-active" "forge-host-active" ];
    };
    duplicateRecipientKeySabotage = fixtureArgs // {
      machineHostKeys = fixtureKeys // {
        dev-a = fixtureKeys.dev-a // { active = "forge-host-active"; };
      };
    };
    untargetedDuplicateRecipientKeySabotage = fixtureArgs // {
      machineHostKeys = fixtureKeys // {
        privacy-a = fixtureKeys.privacy-a // { active = "forge-host-active"; };
      };
    };
    missingCompatibilityNexusNameArgs =
      builtins.removeAttrs fixtureArgs [ "hypervisorPublicKeys" ];
    missingCompatibilityNexusNameDiagnostics =
      (mkPiCredentialContract missingCompatibilityNexusNameArgs).diagnostics.recipients;
    compatibilityArgs = builtins.removeAttrs fixtureArgs [ "hypervisorPublicKeys" ] // {
      nexusName = "forge-host";
      machineHostKeys = fixtureKeys // {
        forge-host = {
          active = "forge-host-active";
          staged = "forge-host-staged";
        };
      };
    };
    compatibilityFixture = mkPiCredentialContract compatibilityArgs;

    actualPiSecrets = lib.filterAttrs
      (path: _: lib.hasPrefix "secrets/pi-credentials/" path)
      secretsNix;

    # Every token of a credential shares that credential's recipient set.
    sharedRecipients = [
      "forge-host-active"
      "forge-host-staged"
      "dev-a-active"
      "dev-b-active"
      "dev-b-staged"
    ];
    soloRecipients = [
      "forge-host-active"
      "forge-host-staged"
      "dev-b-active"
      "dev-b-staged"
    ];
    sharedProjection = {
      providers = [ "alpha" "beta" ];
      tokens = {
        primary.file = "/synthetic-secrets/pi-credentials/shared/primary.age";
        secondary.file = "/synthetic-secrets/pi-credentials/shared/secondary.age";
      };
      defaultToken = "primary";
    };
  in
  assert lib.assertMsg (piCredentialContract.registry == {})
    "pi-credential-registry: public registry must stay empty";
  assert lib.assertMsg (piCredentialContract.credentialInventory == {})
    "pi-credential-registry: empty registry generated credential inventory";
  assert lib.assertMsg (piCredentialContract.recipients == {})
    "pi-credential-registry: empty registry generated recipients";
  assert lib.assertMsg (piCredentialContract.providerCredentials == {})
    "pi-credential-registry: empty registry generated provider references";
  assert lib.assertMsg (actualPiSecrets == {})
    "pi-credential-registry: empty registry generated secrets.nix entries";
  assert lib.assertMsg (fixture.providerCredentials == {
    alpha = "shared";
    beta = "shared";
    gamma = "solo";
  }) "pi-credential-registry: provider-to-credential projection drifted";
  assert lib.assertMsg (fixture.recipients == {
    "secrets/pi-credentials/shared/primary.age".publicKeys = sharedRecipients;
    "secrets/pi-credentials/shared/secondary.age".publicKeys = sharedRecipients;
    "secrets/pi-credentials/solo/only.age".publicKeys = soloRecipients;
  }) "pi-credential-registry: recipient derivation drifted";
  assert lib.assertMsg (compatibilityFixture.recipients == fixture.recipients)
    "pi-credential-registry: legacy constructor fallback drifted";
  assert lib.assertMsg (fixture.ciphertextPaths == {
    shared = {
      primary = "/synthetic-secrets/pi-credentials/shared/primary.age";
      secondary = "/synthetic-secrets/pi-credentials/shared/secondary.age";
    };
    solo.only = "/synthetic-secrets/pi-credentials/solo/only.age";
  }) "pi-credential-registry: per-token ciphertext paths drifted";
  assert lib.assertMsg (fixture.credentialInventory.shared.consumers == [
    {
      type = "agenix";
      repo = "secrets";
      secret = "secrets/pi-credentials/shared/primary.age";
    }
    {
      type = "agenix";
      repo = "secrets";
      secret = "secrets/pi-credentials/shared/secondary.age";
    }
  ]) "pi-credential-registry: inventory consumers are not one per ciphertext";
  assert lib.assertMsg (fixture.projections.dev-a.providers == {
    alpha = "shared";
    beta = "shared";
  }) "pi-credential-registry: per-VM provider projection drifted";
  assert lib.assertMsg (fixture.projections.dev-a.credentials == {
    shared = sharedProjection;
  }) "pi-credential-registry: per-VM credential projection drifted";
  assert lib.assertMsg (fixture.projections.dev-b.credentials == {
    shared = sharedProjection;
    solo = {
      providers = [ "gamma" ];
      tokens.only.file = "/synthetic-secrets/pi-credentials/solo/only.age";
      defaultToken = null;
    };
  }) "pi-credential-registry: default-null credential projection drifted";
  assert lib.assertMsg (
    builtins.attrNames fixture.registry.shared
    == [ "defaultToken" "providers" "targets" "tokens" ]
  ) "pi-credential-registry: validated record fields drifted from the contract";
  assert lib.assertMsg (
    builtins.attrNames fixture.projections.dev-a.credentials.shared
    == [ "defaultToken" "providers" "tokens" ]
  ) "pi-credential-registry: projected credential fields drifted from the contract";
  assert lib.assertMsg (
    fixture.validateProviderReferences [ "alpha" "beta" "gamma" ]
    == fixture.providerCredentials
  ) "pi-credential-registry: provider reference validator returned the wrong projection";
  assert lib.assertMsg (rejects schemaSabotage)
    "pi-credential-registry: schema sabotage was accepted";
  assert lib.assertMsg (rejectsStandaloneRecipients standaloneSchemaSabotage)
    "pi-credential-registry: standalone recipient schema sabotage was accepted";
  assert lib.assertMsg (rejects duplicateProviderSabotage)
    "pi-credential-registry: duplicate-provider sabotage was accepted";
  assert lib.assertMsg (rejects unsupportedTargetSabotage)
    "pi-credential-registry: unsupported-target sabotage was accepted";
  assert lib.assertMsg (rejects unknownTargetSabotage)
    "pi-credential-registry: unknown-target sabotage was accepted";
  assert lib.assertMsg (rejects rotationStrategySabotage)
    "pi-credential-registry: retired rotationStrategy field was accepted";
  assert lib.assertMsg (rejects missingTokenFieldSabotage)
    "pi-credential-registry: missing-tokens sabotage was accepted";
  assert lib.assertMsg (rejects emptyTokensSabotage)
    "pi-credential-registry: empty-tokens sabotage was accepted";
  assert lib.assertMsg (rejects duplicateTokenSabotage)
    "pi-credential-registry: duplicate-token sabotage was accepted";
  assert lib.assertMsg (rejects invalidTokenNameSabotage)
    "pi-credential-registry: invalid-token-name sabotage was accepted";
  assert lib.assertMsg (rejects reservedTokenNameSabotage)
    "pi-credential-registry: reserved-token-name sabotage was accepted";
  assert lib.assertMsg (rejects unlistedDefaultSabotage)
    "pi-credential-registry: unlisted-default sabotage was accepted";
  assert lib.assertMsg (rejects nonStringDefaultSabotage)
    "pi-credential-registry: non-string-default sabotage was accepted";
  assert lib.assertMsg (rejects missingCiphertextSabotage)
    "pi-credential-registry: missing-ciphertext sabotage was accepted";
  assert lib.assertMsg (rejects missingOneCiphertextSabotage)
    "pi-credential-registry: missing single-token ciphertext sabotage was accepted";
  assert lib.assertMsg (rejects recipientSabotage)
    "pi-credential-registry: recipient drift sabotage was accepted";
  assert lib.assertMsg (rejects invalidHypervisorRecipientSabotage)
    "pi-credential-registry: empty hypervisor recipient list was accepted";
  assert lib.assertMsg (rejects malformedHypervisorRecipientSabotage)
    "pi-credential-registry: malformed hypervisor recipient list was accepted";
  assert lib.assertMsg (malformedHypervisorRecipientDiagnostics == [
    "hypervisor recipient keys must be a non-empty unique list of non-empty strings"
  ]) "pi-credential-registry: malformed hypervisor recipient diagnostic drifted";
  assert lib.assertMsg (rejects duplicateHypervisorRecipientSabotage)
    "pi-credential-registry: duplicate hypervisor recipient was accepted";
  assert lib.assertMsg (rejects missingCompatibilityNexusNameArgs)
    "pi-credential-registry: compatibility fallback accepted a missing nexusName";
  assert lib.assertMsg (missingCompatibilityNexusNameDiagnostics == [
    "nexusName is required when hypervisorPublicKeys is omitted"
  ]) "pi-credential-registry: compatibility nexusName diagnostic drifted";
  assert lib.assertMsg (rejects duplicateRecipientKeySabotage)
    "pi-credential-registry: duplicate-recipient-key sabotage was accepted";
  assert lib.assertMsg (rejects untargetedDuplicateRecipientKeySabotage)
    "pi-credential-registry: untargeted duplicate-recipient-key sabotage was accepted";
  assert lib.assertMsg (rejectsStandaloneRecipientsWith
    fixtureRegistry
    untargetedDuplicateRecipientKeySabotage.machineHostKeys
    fixtureHypervisorPublicKeys)
    "pi-credential-registry: standalone untargeted duplicate-recipient-key sabotage was accepted";
  assert lib.assertMsg (rejectsProviderReferences [ "alpha" "beta" ])
    "pi-credential-registry: unknown provider sabotage was accepted";
  pkgs.runCommand "pi-credential-registry-check" {} ''
    echo "Pi credential registry validation and sabotage passed"
    touch "$out"
  ''
