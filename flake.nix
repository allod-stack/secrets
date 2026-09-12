{
  description = "Allod public identity template — synthetic values for agent-isolated VMs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
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
      hypervisorPublicKeys = identity.hostPublicKeys;
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
    credentialEncodings = [ "rclone-obscure" ];
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
      # A deployment sets each of these to a Nix path, e.g. `./secrets + "/<name>.age"`
      # (a path, not a string; the same spelling the dev-VM token fields above use).
      userForgejoTokenFile = null;
      siteHostingConfigFile = null;
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
    lib.credentialEncodings = credentialEncodings;
    lib.identity = identity;
    lib.forgeSshKeys = builtins.fromJSON (builtins.readFile ./forge-ssh-keys.json);
    lib.forgejoTokenGroups = validateCredentialRegistry (builtins.fromJSON (builtins.readFile ./forgejo-token-groups.json));
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

        credential-registry =
          let
            current = builtins.fromJSON (builtins.readFile ./forgejo-token-groups.json);

            newPlainCredential = {
              credential = "new-plain-token";
              secret_path = "secrets/new-plain-token.age";
              targets = [{
                system = "fixture-host";
                verify = "test -n \"$TOKEN\"";
              }];
            };
            encodedCredential = {
              credential = "new-encoded-password";
              secret_path = "secrets/new-encoded-password.age";
              value = {
                template = "[shared]\ntype = ftp\npass = {secret}\n";
                encode = "rclone-obscure";
              };
              targets = [{
                system = "fixture-host";
                verify = "rclone lsd shared:";
              }];
            };

            positive = {
              # One group of plain verify-command credentials, one using an
              # encoded value template.
              tokens.credentials = [ newPlainCredential ];
              encoded.credentials = [ encodedCredential ];
            };
            withGroup = name: credentials:
              positive // { ${name} = positive.${name} // { inherit credentials; }; };

            # Each fixture must produce exactly the one diagnostic it names, so no
            # fixture can pass by tripping a neighbouring rule.
            sabotages = [
              {
                name = "registry-shape";
                registry = [ positive.tokens ];
                diagnostic = "registry must be an attribute set";
              }
              {
                name = "group-schema";
                registry = positive // { malformed = { credentials = {}; }; };
                diagnostic = "group credentials must be a list";
              }
              {
                name = "empty-group";
                registry = withGroup "tokens" [];
                diagnostic = "group must declare at least one credential";
              }
              {
                name = "credential-shape";
                registry = withGroup "tokens" [ "not-a-credential" ];
                diagnostic = "credential must be an attribute set";
              }
              {
                name = "target-list";
                registry = withGroup "tokens" [
                  newPlainCredential
                  (newPlainCredential // { targets = {}; })
                ];
                diagnostic = "credential targets must be a list";
              }
              {
                name = "empty-targets";
                registry = withGroup "tokens" [
                  newPlainCredential
                  (newPlainCredential // { targets = []; })
                ];
                diagnostic = "credential must declare at least one target";
              }
              {
                name = "format-field";
                registry = withGroup "tokens" [
                  newPlainCredential
                  (newPlainCredential // {
                    credential = "legacy-shaped-token";
                    format = "raw";
                  })
                ];
                diagnostic = "credential 'legacy-shaped-token' carries 'format', which the registry no longer accepts; declare a value template instead";
              }
              {
                # A malformed registry entry can carry format with a
                # non-string (or missing) name; the refusal must still
                # produce its one diagnostic, with a placeholder name,
                # rather than aborting evaluation.
                name = "format-field-non-string-name";
                registry = withGroup "tokens" [
                  newPlainCredential
                  (newPlainCredential // {
                    credential = {};
                    format = "raw";
                  })
                ];
                diagnostic = "credential '?' carries 'format', which the registry no longer accepts; declare a value template instead";
              }
              {
                name = "non-string-verify";
                registry = withGroup "tokens" [
                  newPlainCredential
                  (newPlainCredential // {
                    targets = [{ system = "fixture-host"; verify = { type = "fixture-verify"; }; }];
                  })
                ];
                diagnostic = "target verify must be a string command";
              }
              {
                name = "missing-verify";
                registry = withGroup "tokens" [
                  newPlainCredential
                  (newPlainCredential // { targets = [{ system = "fixture-host"; }]; })
                ];
                diagnostic = "new targets require a non-empty one-line verify command";
              }
              {
                name = "blank-verify";
                registry = withGroup "tokens" [
                  newPlainCredential
                  (newPlainCredential // {
                    targets = [{ system = "fixture-host"; verify = "   "; }];
                  })
                ];
                diagnostic = "new targets require a non-empty one-line verify command";
              }
              {
                name = "multi-line-verify";
                registry = withGroup "tokens" [
                  newPlainCredential
                  (newPlainCredential // {
                    targets = [{ system = "fixture-host"; verify = "echo one\necho two"; }];
                  })
                ];
                diagnostic = "new targets require a non-empty one-line verify command";
              }
              {
                name = "value-shape";
                registry = withGroup "tokens" [
                  newPlainCredential
                  (newPlainCredential // { value = "https://user:{secret}@host"; })
                ];
                diagnostic = "value must be an attribute set";
              }
              {
                name = "missing-template";
                registry = withGroup "tokens" [
                  newPlainCredential
                  (newPlainCredential // { value = {}; })
                ];
                diagnostic = "value is missing template";
              }
              {
                name = "value-fields";
                registry = withGroup "tokens" [
                  newPlainCredential
                  (newPlainCredential // {
                    value = { template = "{secret}"; unexpected = true; };
                  })
                ];
                diagnostic = "value has fields outside template and optional encode";
              }
              {
                name = "missing-placeholder";
                registry = withGroup "tokens" [
                  newPlainCredential
                  (newPlainCredential // { value = { template = "missing placeholder"; }; })
                ];
                diagnostic = "value.template must contain exactly one {secret}";
              }
              {
                name = "repeated-placeholder";
                registry = withGroup "tokens" [
                  newPlainCredential
                  (newPlainCredential // { value = { template = "{secret}:{secret}"; }; })
                ];
                diagnostic = "value.template must contain exactly one {secret}";
              }
              {
                name = "unexported-encoder";
                registry = withGroup "encoded" [
                  (encodedCredential // {
                    value = encodedCredential.value // { encode = "not-exported"; };
                  })
                ];
                diagnostic = "value.encode is not an exported encoding";
              }
              {
                name = "incompatible-encoding";
                registry = withGroup "tokens" [ newPlainCredential encodedCredential ];
                diagnostic = "credentials in a group must use one compatible encoding";
              }
            ];

            diagnosticsText = registry:
              "[${lib.concatStringsSep "; " (credentialRegistryDiagnostics registry)}]";
            tripsOnlyItsOwnRule = sabotage:
              credentialRegistryDiagnostics sabotage.registry == [ sabotage.diagnostic ] &&
              !(builtins.tryEval
                (builtins.deepSeq (validateCredentialRegistry sabotage.registry) true)).success;
            vacuousSabotages = builtins.filter (sabotage: !(tripsOnlyItsOwnRule sabotage)) sabotages;
            vacuousText = lib.concatMapStringsSep "; "
              (sabotage: "${sabotage.name} wanted [${sabotage.diagnostic}] got ${diagnosticsText sabotage.registry}")
              vacuousSabotages;
          in
          assert lib.assertMsg (credentialRegistryDiagnostics current == [])
            "credential-registry: public registry failed validation: ${diagnosticsText current}";
          assert lib.assertMsg (credentialRegistryDiagnostics positive == [])
            "credential-registry: positive value-template fixtures failed validation: ${diagnosticsText positive}";
          assert lib.assertMsg (vacuousSabotages == [])
            "credential-registry: sabotage fixtures accepted or tripping the wrong rule: ${vacuousText}";
          pkgs.runCommand "credential-registry-check" {} ''
            echo "credential registry validation and ${toString (builtins.length sabotages)} sabotage fixtures passed"
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
                (import ./lib/pi-credential-recipients.nix {
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
          '';

        credential-inventory =
          let
            # The check's rules as a function of their inputs, so the same
            # rules run once over the repository's data and once over the
            # sabotage fixtures below: the fixture witnesses production logic,
            # not a copy of it. Every field is a list of violations, empty
            # when the rule holds. fileExists answers for a repository-relative
            # path; the real run asks the flake source, the fixtures answer
            # from a table.
            inventoryDiagnostics = { credentials, secretsNix, machineHostKeys, fileExists }:
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
                # 'pending' is an entry an agent declared before the host produced
                # its ciphertext: legal on a reviewable branch, so the non-secret
                # half of a credential can land green ahead of the secret half.
                validStates = [ "pending" "active" "staged" "retiring" "retired" ];

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
                  map (c: { inherit (e) name rotation_state; inherit (c) secret; }) (
                    builtins.filter (c:
                      (c.type == "agenix" && c.repo == "secrets") || c.type == "forge-key-secret"
                    ) e.consumers
                  )
                ) entries);

                # A pending entry's file must be absent: present means the state
                # was never flipped to active, and the check refuses rather than
                # let a stale 'pending' ride into a rebuild. Every other state
                # needs the file.
                pendingWithFile = builtins.filter (c:
                  c.rotation_state == "pending" && fileExists c.secret
                ) secretsRepoFiles;
                missingFiles = builtins.filter (c:
                  c.rotation_state != "pending" && !(fileExists c.secret)
                ) secretsRepoFiles;

                forgejoSshRefs = lib.flatten (map (e:
                  map (c: { inherit (e) name; forgeKey = c.key; publicKey = e.public_key; }) (
                    builtins.filter (c: c.type == "forgejo-ssh") e.consumers
                  )
                ) entries);
              in {
                inherit mhkBadShape mhkHasDuplicateKeys invalidSchema aliasMismatches
                  hasDuplicateKeys unresolvedRecipients uncoveredSecrets
                  forgeGitNullKey forgeGitBadConsumers pendingWithFile missingFiles
                  forgejoSshRefs;
              };

            real = inventoryDiagnostics {
              inherit credentials secretsNix machineHostKeys;
              fileExists = path: builtins.pathExists (self + "/${path}");
            };

            # Sabotage fixtures for the file-presence rules, which the
            # template's own data never exercises (it has no pending entry).
            # One pending and one active entry; the healthy table has exactly
            # the active file, the sabotaged table has exactly the pending one,
            # so each rule is seen to pass and to fail.
            fixtureEntry = name: state: {
              inherit name;
              kind = "agent";
              owner = "fixture";
              public_key = null;
              consumers = [
                { type = "agenix"; repo = "secrets"; secret = "secrets/${name}.age"; }
              ];
              rotation_state = state;
            };
            fixtureDiagnostics = fileExists: inventoryDiagnostics {
              credentials = {
                fixture-pending = fixtureEntry "fixture-pending" "pending";
                fixture-active = fixtureEntry "fixture-active" "active";
              };
              secretsNix = {
                "secrets/fixture-pending.age".publicKeys = [];
                "secrets/fixture-active.age".publicKeys = [];
              };
              machineHostKeys = {};
              inherit fileExists;
            };
            fixtureHealthy = fixtureDiagnostics (path: path == "secrets/fixture-active.age");
            fixtureSabotaged = fixtureDiagnostics (path: path == "secrets/fixture-pending.age");
            names = map (c: c.name);
          in
          assert lib.assertMsg (fixtureHealthy.pendingWithFile == [] && fixtureHealthy.missingFiles == [])
            "credential-inventory: fixture with the right files present was refused";
          assert lib.assertMsg (names fixtureSabotaged.pendingWithFile == [ "fixture-pending" ])
            "credential-inventory: sabotage accepted: a pending entry with a ciphertext present";
          assert lib.assertMsg (names fixtureSabotaged.missingFiles == [ "fixture-active" ])
            "credential-inventory: sabotage accepted: an active entry with no ciphertext";
          assert lib.assertMsg (real.mhkBadShape == [])
            "credential-inventory: machine-host-keys.json bad shape: ${lib.concatStringsSep ", " real.mhkBadShape}";
          assert lib.assertMsg (!real.mhkHasDuplicateKeys)
            "credential-inventory: machine-host-keys.json has duplicate keys";
          assert lib.assertMsg (real.invalidSchema == [])
            "credential-inventory: invalid schema: ${lib.concatMapStringsSep ", " (e: e.name) real.invalidSchema}";
          assert lib.assertMsg (real.aliasMismatches == [])
            "credential-inventory: alias/name mismatch: ${lib.concatStringsSep ", " real.aliasMismatches}";
          assert lib.assertMsg (!real.hasDuplicateKeys)
            "credential-inventory: duplicate non-null public keys";
          assert lib.assertMsg (real.unresolvedRecipients == [])
            "credential-inventory: unresolved recipient keys in secrets.nix";
          assert lib.assertMsg (real.uncoveredSecrets == [])
            "credential-inventory: secrets missing consumer records: ${lib.concatStringsSep ", " real.uncoveredSecrets}";
          assert lib.assertMsg (real.forgeGitNullKey == [])
            "credential-inventory: forge-git entries need public_key: ${lib.concatMapStringsSep ", " (e: e.name) real.forgeGitNullKey}";
          assert lib.assertMsg (real.forgeGitBadConsumers == [])
            "credential-inventory: forge-git needs one forge-key-secret + one forgejo-ssh consumer: ${lib.concatMapStringsSep ", " (e: e.name) real.forgeGitBadConsumers}";
          assert lib.assertMsg (real.pendingWithFile == [])
            "credential-inventory: ${lib.concatMapStringsSep "; " (c:
              "${c.secret} exists but ${c.name} is pending; land it with 'allod secret create ${c.name}' or set rotation_state to active"
            ) real.pendingWithFile}";
          assert lib.assertMsg (real.missingFiles == [])
            "credential-inventory: ${lib.concatMapStringsSep "; " (c: "missing ${c.secret} for ${c.name}") real.missingFiles}";
          pkgs.runCommand "credential-inventory-check" {} ''
            ${lib.concatMapStringsSep "\n" (r: ''
              test -f ${self}/keys/${r.forgeKey}.pub \
                || { echo "ERROR: missing keys/${r.forgeKey}.pub for ${r.name}"; exit 1; }
            '') real.forgejoSshRefs}

            ${lib.concatMapStringsSep "\n" (r:
              if r.publicKey != null then ''
                expected=${builtins.toFile "${r.forgeKey}-expected" r.publicKey}
                actual=$(tr -d '\n' < ${self}/keys/${r.forgeKey}.pub)
                exp=$(cat "$expected")
                [ "$actual" = "$exp" ] \
                  || { echo "ERROR: key mismatch: inventory vs keys/${r.forgeKey}.pub for ${r.name}"; exit 1; }
              '' else ""
            ) real.forgejoSshRefs}

            echo "credential inventory validation passed"
            touch $out
          '';
    });
  };
}
