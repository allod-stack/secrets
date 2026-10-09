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

    # Absent means a fork's identity predates this field: default to https on
    # the forge host, since clone transport (sshHost) and API transport
    # (forgeUrl) diverge only when an identity sets this explicitly.
    mkForgeUrl = identity: identity.forgeUrl or "https://${identity.forgeHost}";

    devIdentities = builtins.mapAttrs (name: vm: {
      inherit (identity) username forgeHost forgePort;
      forgeUrl = mkForgeUrl identity;
      inherit (vm) sshKeyName;
      forgeUser = identity.forgeUser;
      gpgSigningKey = identity.gpgSigningKey;
      # An opted-out VM is not a recipient of the shared agent-token ciphertext.
      agentTokenFile =
        if vm.forgeAccess or true
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

    # A service VM has no operator account; it logs in as root.
    serviceIdentities = builtins.mapAttrs (_: _: { username = "root"; }) identity.serviceVMs;

    nexusIdentity = {
      inherit (identity) username hostname forgeHost forgePort;
      forgeUrl = mkForgeUrl identity;
      sshPublicKey = identity.hostPublicKey;
      sshPublicKeys = identity.hostPublicKeys;
      # A deployment sets each of these to a Nix path, e.g. `./secrets + "/<name>.age"`
      # (a path, not a string; the same spelling the dev-VM token fields above use).
      userForgejoTokenFile = null;
      siteHostingConfigFile = null;
      # Leave empty: only an additional hypervisor's entry may set this.
      operatorPublicKeys = [ ];
    };

    hypervisorIdentities = { ${nexusIdentity.hostname} = nexusIdentity; };

    # Do not drop this assert: a silently overwritten collision hands a
    # login to the wrong principal.
    mkVmUsernames = { guestUsernames, hypervisorIdentities }:
      let
        hypervisorUsernames = builtins.mapAttrs (_: id: id.username) hypervisorIdentities;
        collisions = lib.intersectLists
          (builtins.attrNames guestUsernames)
          (builtins.attrNames hypervisorUsernames);
      in
      assert lib.assertMsg (collisions == [])
        "vmUsernames: hypervisor identity collides with a guest machine name: ${lib.concatStringsSep ", " collisions}";
      guestUsernames // hypervisorUsernames;

    vmUsernames = mkVmUsernames {
      guestUsernames = builtins.mapAttrs (_: id: id.username)
        (devIdentities // privacyIdentities // serviceIdentities);
      inherit hypervisorIdentities;
    };
  in {
    lib.devIdentities = devIdentities;
    lib.privacyIdentities = privacyIdentities;
    lib.serviceIdentities = serviceIdentities;
    lib.nexusIdentity = nexusIdentity;
    lib.hypervisorIdentities = hypervisorIdentities;
    lib.vmUsernames = vmUsernames;
    lib.credentials = credentials;
    lib.credentialEncodings = credentialEncodings;
    lib.identity = identity;
    lib.forgeSshKeys = builtins.fromJSON (builtins.readFile ./forge-ssh-keys.json);
    lib.rotationRegistry = rotationRegistry;
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
          validateCredentialRegistry mkPiCredentialContract
          piCredentialContract hypervisorIdentities nexusIdentity
          mkVmUsernames mkForgeUrl;
        machines = inventory.lib.machines;
      });
  };
}
