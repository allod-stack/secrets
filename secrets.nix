let
  machineHostKeys = builtins.fromJSON (builtins.readFile ./machine-host-keys.json);
  identity = import ./identity.nix;
  piCredentials = builtins.fromJSON (builtins.readFile ./pi-credentials.json);

  vmKeys = vm:
    let d = machineHostKeys.${vm};
    in [ d.active ] ++ (if d.staged != null then [ d.staged ] else []);
  hostKey = identity.hostPublicKey;
  piCredentialRecipients = import ./lib/pi-credential-recipients.nix {
    registry = piCredentials;
    inherit machineHostKeys;
    nexusPublicKeys = identity.hostPublicKeys;
  };
in {
  "secrets/forgejo-https-token-allod-dev.age".publicKeys = [ hostKey ] ++ vmKeys "allod-dev";
  "secrets/agent-pr-token.age".publicKeys = [ hostKey ] ++ vmKeys "allod-dev";
  "secrets/allod-dev-forge-key.age".publicKeys = [ hostKey ] ++ vmKeys "allod-dev";
  "secrets/vm-host-keys/nexus-ssh.age".publicKeys = [ hostKey ];
  "secrets/vm-host-keys/allod-dev-ssh.age".publicKeys = [ hostKey ];
  "secrets/vm-host-keys/privacy-1-ssh.age".publicKeys = [ hostKey ];
} // piCredentialRecipients
