let
  machineHostKeys = builtins.fromJSON (builtins.readFile ./machine-host-keys.json);
  forgeSshKeys = builtins.fromJSON (builtins.readFile ./forge-ssh-keys.json);
  identity = import ./identity.nix;
  piCredentials = builtins.fromJSON (builtins.readFile ./pi-credentials.json);
  rotationRegistry = builtins.fromJSON (builtins.readFile ./rotation-registry.json);

  vmKeys = vm:
    let d = machineHostKeys.${vm};
    in [ d.active ] ++ (if d.staged != null then [ d.staged ] else []);
  hostKey = identity.hostPublicKey;
  piCredentialRecipients = import ./lib/pi-credential-recipients.nix {
    registry = piCredentials;
    inherit machineHostKeys;
    hypervisorPublicKeys = identity.hostPublicKeys;
  };
  # Declared credentials' recipients; 'allod secret declare' writes no line here.
  registryRecipients = (import ./lib/registry-recipients.nix {
    registry = rotationRegistry;
    inherit machineHostKeys;
    hypervisorPublicKeys = identity.hostPublicKeys;
    primaryHostname = identity.hostname;
  }).recipients;

  # Unlisted when no VM has forge access, so agenix never asks for it.
  forgeAccessVMs = import ./lib/forge-access-vms.nix { inherit identity; };
  agentTokenRecipients = if forgeAccessVMs == [ ] then { } else {
    "secrets/agent-pr-token.age".publicKeys =
      [ hostKey ] ++ builtins.concatMap vmKeys forgeAccessVMs;
  };

  forgeKeyRecipients = builtins.listToAttrs (map (name: {
    name = forgeSshKeys.${name}.secret;
    value.publicKeys = [ hostKey ] ++ vmKeys forgeSshKeys.${name}.owner;
  }) (builtins.attrNames forgeSshKeys));

  # Host keys, the hypervisor's own included, are readable by the hypervisor alone.
  vmHostKeyRecipients = builtins.listToAttrs (map (vm: {
    name = "secrets/vm-host-keys/${vm}-ssh.age";
    value.publicKeys = [ hostKey ];
  }) ([ identity.hostname ] ++ builtins.attrNames machineHostKeys));
in
agentTokenRecipients // forgeKeyRecipients // vmHostKeyRecipients // piCredentialRecipients // registryRecipients
