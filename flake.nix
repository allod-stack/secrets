{
  description = "Allod public identity template — synthetic values for agent-isolated VMs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    inventory = {
      url = "git+ssh://git@forge.anarch.diy:2222/Allod/inventory.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, inventory, ... }:
  let
    lib = nixpkgs.lib;
    identity = import ./identity.nix;

    credentials = import ./credentials.nix;
    secretsNix = import ./secrets.nix;

    devIdentities = builtins.mapAttrs (name: vm: {
      inherit (identity) username forgeHost forgePort;
      inherit (vm) sshKeyName;
      forgeUser = identity.forgeUser;
      gpgSigningKey = identity.gpgSigningKey;
      forgeTokenFile = ./secrets + "/forgejo-https-token-${name}.age";
      agentTokenFile = ./secrets + "/agent-pr-token.age";
      gpgPublicKeyFile = null;
    }) identity.devVMs;

    privacyIdentities = builtins.mapAttrs (_: vm: {
      inherit (vm) username;
    }) identity.privacyVMs;

    nexusIdentity = {
      inherit (identity) username hostname forgeHost forgePort;
      sshPublicKey = identity.hostPublicKey;
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

    homeModules.preferences = import ./modules/preferences.nix;

    checks = lib.genAttrs inventory.lib.supportedPlatforms (checkSystem: {
      credential-inventory =
      let
        pkgs = nixpkgs.legacyPackages.${checkSystem};
        entries = builtins.attrValues credentials;
        entryNames = builtins.attrNames credentials;

        machineHostKeys = builtins.fromJSON (builtins.readFile ./machine-host-keys.json);
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
            builtins.filter (c: c.type == "agenix" && c.repo == "secrets") e.consumers
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
