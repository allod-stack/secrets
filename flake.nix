{
  description = "Allod public identity template — synthetic values for agent-isolated VMs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    inventory = {
      url = "git+https://forge.anarch.diy/allod/inventory.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, inventory, ... }:
  let
    lib = nixpkgs.lib;
    identity = import ./identity.nix;

    machineHostKeys = builtins.fromJSON (builtins.readFile ./machine-host-keys.json);
    piCredentialsJson = builtins.fromJSON (builtins.readFile ./pi-credentials.json);
    secretsNix = import ./secrets.nix;
    mkPiCredentialContract = import ./lib/pi-credential-contract.nix { inherit lib; };
    piCredentialContract = mkPiCredentialContract {
      registry = piCredentialsJson;
      machines = inventory.lib.machines;
      devVMs = identity.devVMs;
      inherit machineHostKeys;
      nexusName = identity.hostname;
      ciphertextRoot = ./secrets;
      declaredRecipients = secretsNix;
    };
    baseCredentials = import ./credentials.nix;
    piCredentialInventoryCollisions = lib.intersectLists
      (builtins.attrNames baseCredentials)
      (builtins.attrNames piCredentialContract.credentialInventory);
    credentials =
      assert lib.assertMsg (piCredentialInventoryCollisions == [])
        "pi-credential-registry: derived inventory collides with existing credentials: ${lib.concatStringsSep ", " piCredentialInventoryCollisions}";
      baseCredentials // piCredentialContract.credentialInventory;
    vmHostKeyDir = ./secrets/vm-host-keys;
    vmHostKeySecretFiles =
      lib.mapAttrs'
        (file: _: {
          name = lib.removeSuffix "-ssh.age" file;
          value = vmHostKeyDir + "/${file}";
        })
        (lib.filterAttrs
          (file: type: type == "regular" && lib.hasSuffix "-ssh.age" file)
          (builtins.readDir vmHostKeyDir));

    devIdentities = builtins.mapAttrs (name: vm:
      let
        # A dev machine that does not push does not need Forge credentials.
        # Opting out keeps a throwaway machine from requiring credential
        # material that only a human can mint, which would otherwise gate its
        # very existence. One flag nulls both files: the per-machine Forge
        # HTTPS token and the shared agent PR token. The agent token must
        # follow the flag because a non-pushing machine is not a recipient of
        # the shared ciphertext — handing it the file would deploy a secret
        # the machine cannot decrypt, failing at first activation. Keeping the
        # two paired is this template's job: the dev builder treats each file
        # as independently optional and does not check them against each other.
        forgeAccess = vm.forgeAccess or true;
      in {
      inherit (identity) username forgeHost forgePort;
      inherit (vm) sshKeyName;
      forgeUser = identity.forgeUser;
      gpgSigningKey = identity.gpgSigningKey;
      forgeTokenFile =
        if forgeAccess
        then ./secrets + "/forgejo-https-token-${name}.age"
        else null;
      agentTokenFile =
        if forgeAccess
        then ./secrets + "/agent-pr-token.age"
        else null;
      gpgPublicKeyFile = null;
      piCredentials = piCredentialContract.projections.${name}.credentials;
      piProviders = piCredentialContract.projections.${name}.providers;
    }) identity.devVMs;

    privacyIdentities = builtins.mapAttrs (_: vm: {
      inherit (vm) username;
    }) identity.privacyVMs;

    nexusIdentity = {
      inherit (identity) username hostname forgeHost forgePort;
      sshPublicKey = identity.hostPublicKey;
      sshPublicKeys = identity.hostPublicKeys;
      forgeTokenFile = null;
    };

    vmUsernames =
      builtins.mapAttrs (_: id: id.username) (devIdentities // privacyIdentities) //
      { ${nexusIdentity.hostname} = nexusIdentity.username; };
  in {
    lib.devIdentities = devIdentities;
    lib.privacyIdentities = privacyIdentities;
    lib.nexusIdentity = nexusIdentity;
    lib.vmUsernames = vmUsernames;
    lib.credentials = credentials;
    lib.identity = identity;
    lib.forgeSshKeys = builtins.fromJSON (builtins.readFile ./forge-ssh-keys.json);
    lib.forgejoTokenGroups = builtins.fromJSON (builtins.readFile ./forgejo-token-groups.json);
    lib.machineHostKeys = machineHostKeys;
    lib.vmHostKeySecretFiles = vmHostKeySecretFiles;
    lib.githubCredentialTargets = {};
    lib.piCredentials = piCredentialContract.registry;
    lib.piCredentialCiphertextPaths = piCredentialContract.ciphertextPaths;
    lib.piProviderCredentials = piCredentialContract.providerCredentials;
    lib.piCredentialInventory = piCredentialContract.credentialInventory;
    lib.piCredentialRecipients = piCredentialContract.recipients;
    lib.piCredentialProjections = piCredentialContract.projections;
    lib.validatePiProviderReferences = piCredentialContract.validateProviderReferences;
    lib.mkPiCredentialContract = mkPiCredentialContract;
    lib.consumedInventorySource = inventory;

    checks = lib.genAttrs inventory.lib.supportedPlatforms (checkSystem:
      let
        pkgs = nixpkgs.legacyPackages.${checkSystem};
      in {
        external-ssh-trust-targets =
          let
            targets = identity.externalSshTrustTargets or {};
            targetNames = builtins.attrNames targets;
            validRecoveries = [ "old-key" "provider-console" "provider-support" ];
            fieldOrNull = target: field:
              if builtins.isAttrs target && builtins.hasAttr field target
              then target.${field}
              else null;
            badShape = builtins.filter (name:
              let target = targets.${name};
              in !(builtins.isAttrs target) ||
                 !(builtins.isString (fieldOrNull target "sshHost")) ||
                 !(builtins.isString (fieldOrNull target "authorizedKeysPath")) ||
                 !(builtins.isString (fieldOrNull target "recovery"))
            ) targetNames;
            wellShapedNames = builtins.filter (name: !(builtins.elem name badShape)) targetNames;
            unresolvedSshHosts = builtins.filter (name:
              !(builtins.hasAttr targets.${name}.sshHost identity.sshHosts)
            ) wellShapedNames;
            badRecovery = builtins.filter (name:
              !(builtins.elem targets.${name}.recovery validRecoveries)
            ) wellShapedNames;
          in
          assert lib.assertMsg (badShape == [])
            "external-ssh-trust-targets: invalid schema: ${lib.concatStringsSep ", " badShape}";
          assert lib.assertMsg (unresolvedSshHosts == [])
            "external-ssh-trust-targets: sshHost alias not found in identity.sshHosts: ${lib.concatStringsSep ", " unresolvedSshHosts}";
          assert lib.assertMsg (badRecovery == [])
            "external-ssh-trust-targets: unknown recovery value: ${lib.concatStringsSep ", " badRecovery}";
          pkgs.runCommand "external-ssh-trust-targets-check" {} ''
            echo "external SSH trust target validation passed"
            touch $out
          '';

        pi-credential-registry =
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
              nexus = { type = "hypervisor"; };
            };
            fixtureDevVMs = {
              dev-a = {};
              dev-b = {};
            };
            fixtureKeys = {
              nexus = { active = "nexus-active"; staged = "nexus-staged"; };
              dev-a = { active = "dev-a-active"; staged = null; };
              dev-b = { active = "dev-b-active"; staged = "dev-b-staged"; };
              privacy-a = { active = "privacy-a-active"; staged = null; };
            };
            fixtureArgs = {
              registry = fixtureRegistry;
              machines = fixtureMachines;
              devVMs = fixtureDevVMs;
              machineHostKeys = fixtureKeys;
              nexusName = "nexus";
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
            rejectsStandaloneRecipients = registry:
              !(builtins.tryEval (builtins.deepSeq
                (import ./lib/pi-credential-recipients.nix {
                  inherit registry;
                  machineHostKeys = fixtureKeys;
                  nexusName = "nexus";
                })
                true)).success;

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
                  "nexus-active"
                  "dev-a-active"
                  "dev-b-active"
                  "dev-b-staged"
                ];
              };
            };
            duplicateRecipientKeySabotage = fixtureArgs // {
              machineHostKeys = fixtureKeys // {
                dev-a = fixtureKeys.dev-a // { active = "nexus-active"; };
              };
            };

            actualPiSecrets = lib.filterAttrs
              (path: _: lib.hasPrefix "secrets/pi-credentials/" path)
              secretsNix;

            # Every token of a credential shares that credential's recipient set.
            sharedRecipients = [
              "nexus-active"
              "nexus-staged"
              "dev-a-active"
              "dev-b-active"
              "dev-b-staged"
            ];
            soloRecipients = [
              "nexus-active"
              "nexus-staged"
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
          assert lib.assertMsg (rejects duplicateRecipientKeySabotage)
            "pi-credential-registry: duplicate-recipient-key sabotage was accepted";
          assert lib.assertMsg (rejectsProviderReferences [ "alpha" "beta" ])
            "pi-credential-registry: unknown provider sabotage was accepted";
          pkgs.runCommand "pi-credential-registry-check" {} ''
            echo "Pi credential registry validation and sabotage passed"
            touch "$out"
          '';

        credential-inventory =
          let
            entries = builtins.attrValues credentials;
            entryNames = builtins.attrNames credentials;

          mhkNames = builtins.attrNames machineHostKeys;
          mhkBadShape = builtins.filter (vm:
            let d = machineHostKeys.${vm};
            in !(builtins.isString d.active) ||
               !(d.staged == null || builtins.isString d.staged)
          ) mhkNames;
          mhkAllKeys = builtins.concatLists (map (vm:
            let d = machineHostKeys.${vm};
            in [ d.active ] ++ (if d.staged != null then [ d.staged ] else [])
          ) mhkNames);
          mhkHasDuplicateKeys = builtins.length mhkAllKeys != builtins.length (lib.unique mhkAllKeys);
          validKinds = [ "user" "machine-host" "forge-git" "agent" "service" ];
          validStates = [ "active" "staged" "retiring" "retired" ];

          invalidSchema = builtins.filter (e:
            !(builtins.elem e.kind validKinds) ||
            !(builtins.elem e.rotation_state validStates) ||
            !(builtins.isString e.name) ||
            !(builtins.isString e.owner) ||
            !(builtins.isList e.consumers)
          ) entries;

          aliasMismatches = builtins.filter (a: credentials.${a}.name != a) entryNames;

          nonNullKeys = map (e: e.public_key) (builtins.filter (e: e.public_key != null) entries);
          hasDuplicateKeys = builtins.length nonNullKeys != builtins.length (lib.unique nonNullKeys);

          allRecipientKeys = lib.unique (lib.flatten (
            map (s: s.publicKeys) (builtins.attrValues secretsNix)
          ));
          activeKeys = map (e: e.public_key) (
            builtins.filter (e:
              e.public_key != null && builtins.elem e.rotation_state [ "active" "staged" ]
            ) entries
          );
          unresolvedRecipients = builtins.filter (k: !(builtins.elem k activeKeys)) allRecipientKeys;

          coveredPaths = lib.flatten (map (e:
            map (c: c.secret) (
              builtins.filter (c:
                (c.type == "agenix" && c.repo == "secrets") || c.type == "forge-key-secret"
              ) e.consumers
            )
          ) entries);
          tokenPaths = builtins.attrNames secretsNix;
          uncoveredSecrets = builtins.filter (p: !(builtins.elem p coveredPaths)) tokenPaths;

          activeForgeGit = builtins.filter (e:
            e.kind == "forge-git" && builtins.elem e.rotation_state [ "active" "staged" ]
          ) entries;
          forgeGitNullKey = builtins.filter (e: e.public_key == null) activeForgeGit;
          forgeGitBadConsumers = builtins.filter (e:
            let
              nFk = builtins.length (builtins.filter (c: c.type == "forge-key-secret") e.consumers);
              nFs = builtins.length (builtins.filter (c: c.type == "forgejo-ssh") e.consumers);
            in nFk != 1 || nFs != 1
          ) activeForgeGit;

          secretsRepoFiles = lib.flatten (map (e:
            map (c: { inherit (e) name; inherit (c) secret; }) (
              builtins.filter (c:
                (c.type == "agenix" && c.repo == "secrets") || c.type == "forge-key-secret"
              ) e.consumers
            )
          ) entries);

          forgejoSshRefs = lib.flatten (map (e:
            map (c: { inherit (e) name; forgeKey = c.key; publicKey = e.public_key; }) (
              builtins.filter (c: c.type == "forgejo-ssh") e.consumers
            )
          ) entries);
        in
        assert lib.assertMsg (mhkBadShape == [])
          "credential-inventory: machine-host-keys.json bad shape: ${lib.concatStringsSep ", " mhkBadShape}";
        assert lib.assertMsg (!mhkHasDuplicateKeys)
          "credential-inventory: machine-host-keys.json has duplicate keys";
        assert lib.assertMsg (invalidSchema == [])
          "credential-inventory: invalid schema: ${lib.concatMapStringsSep ", " (e: e.name) invalidSchema}";
        assert lib.assertMsg (aliasMismatches == [])
          "credential-inventory: alias/name mismatch: ${lib.concatStringsSep ", " aliasMismatches}";
        assert lib.assertMsg (!hasDuplicateKeys)
          "credential-inventory: duplicate non-null public keys";
        assert lib.assertMsg (unresolvedRecipients == [])
          "credential-inventory: unresolved recipient keys in secrets.nix";
        assert lib.assertMsg (uncoveredSecrets == [])
          "credential-inventory: secrets missing consumer records: ${lib.concatStringsSep ", " uncoveredSecrets}";
        assert lib.assertMsg (forgeGitNullKey == [])
          "credential-inventory: forge-git entries need public_key: ${lib.concatMapStringsSep ", " (e: e.name) forgeGitNullKey}";
        assert lib.assertMsg (forgeGitBadConsumers == [])
          "credential-inventory: forge-git needs one forge-key-secret + one forgejo-ssh consumer: ${lib.concatMapStringsSep ", " (e: e.name) forgeGitBadConsumers}";
        pkgs.runCommand "credential-inventory-check" {} ''
          ${lib.concatMapStringsSep "\n" (c: ''
            test -f ${self}/${c.secret} \
              || { echo "ERROR: missing ${c.secret} for ${c.name}"; exit 1; }
          '') secretsRepoFiles}

          ${lib.concatMapStringsSep "\n" (r: ''
            test -f ${self}/keys/${r.forgeKey}.pub \
              || { echo "ERROR: missing keys/${r.forgeKey}.pub for ${r.name}"; exit 1; }
          '') forgejoSshRefs}

          ${lib.concatMapStringsSep "\n" (r:
            if r.publicKey != null then ''
              expected=${builtins.toFile "${r.forgeKey}-expected" r.publicKey}
              actual=$(tr -d '\n' < ${self}/keys/${r.forgeKey}.pub)
              exp=$(cat "$expected")
              [ "$actual" = "$exp" ] \
                || { echo "ERROR: key mismatch: inventory vs keys/${r.forgeKey}.pub for ${r.name}"; exit 1; }
            '' else ""
          ) forgejoSshRefs}

          echo "credential inventory validation passed"
          touch $out
        '';
    });
  };
}
