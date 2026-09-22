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
    devSshHosts = import ./lib/dev-ssh-hosts.nix { inherit lib; };
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
    inherit (import ./lib/credential-registry.nix { inherit lib credentialEncodings; })
      credentialRegistryDiagnostics validateCredentialRegistry;
    # The credential-store URL grammar and its accept/reject vectors are data,
    # not prose: this is the one table allod/archetypes, allod/nexus, and
    # allod/tools are meant to read instead of each carrying a spelling that
    # only a comment keeps in step.  Each cutover lands in its own repo, so
    # nothing here fails when a copy that has not switched yet drifts.
    credentialStoreUrl = builtins.fromJSON (builtins.readFile ./credential-store-url.json);

    inherit (import ./lib/credential-store-url.nix { inherit lib credentialStoreUrl; })
      isCredentialStoreUrlTemplate isCredentialStoreUrlSource credentialStoreUrlSourceClause;

    inherit (import ./lib/local-auth-refresh.nix {
        inherit lib isCredentialStoreUrlSource credentialStoreUrlSourceClause;
      })
      localAuthRefreshContract localAuthRefreshDeployedPath localAuthRefreshDeclaration
      localAuthRefreshEntries localAuthRefreshDiagnostics localAuthRefreshSourcesFor
      mkLocalAuthRefreshSources;

    rotationRegistry = validateCredentialRegistry (builtins.fromJSON (builtins.readFile ./rotation-registry.json));
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
      sshHosts = devSshHosts.project { inherit identity; machineName = name; inherit vm; };
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
    lib.rotationRegistry = rotationRegistry;
    lib.credentialStoreUrl = credentialStoreUrl;
    lib.isCredentialStoreUrlTemplate = isCredentialStoreUrlTemplate;
    lib.isCredentialStoreUrlSource = isCredentialStoreUrlSource;
    lib.localAuthRefreshDiagnostics = localAuthRefreshDiagnostics;
    lib.mkLocalAuthRefreshSources = mkLocalAuthRefreshSources;
    lib.localAuthRefreshSources = mkLocalAuthRefreshSources rotationRegistry;
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
    lib.projectDevSshHosts = devSshHosts.project;
    lib.consumedInventorySource = inventory;

    checks = lib.genAttrs inventory.lib.supportedPlatforms (checkSystem:
      let
        pkgs = nixpkgs.legacyPackages.${checkSystem};
      in
      import ./checks {
        inherit lib pkgs self identity devSshHosts devIdentities credentials
          secretsNix machineHostKeys credentialRegistryDiagnostics
          validateCredentialRegistry credentialStoreUrl
          isCredentialStoreUrlTemplate isCredentialStoreUrlSource
          credentialStoreUrlSourceClause localAuthRefreshDiagnostics
          mkLocalAuthRefreshSources rotationRegistry mkPiCredentialContract
          piCredentialContract;
      });
  };
}
