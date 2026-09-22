{ lib, pkgs, self, credentials, secretsNix, machineHostKeys }:
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
  ''
