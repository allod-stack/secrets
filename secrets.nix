let
  machineHostKeys = builtins.fromJSON (builtins.readFile ./machine-host-keys.json);
  hostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJvgPQ/XEO5jFd5Q5lfp1tMnCeK3RbRP0k0U05fBR0iu nexus";

  vmKeys = vm:
    let d = machineHostKeys.${vm};
    in [ d.active ] ++ (if d.staged != null then [ d.staged ] else []);
in {
  "secrets/forgejo-https-token-allod-dev.age".publicKeys = [ hostKey ] ++ vmKeys "allod-dev";
  "secrets/agent-pr-token.age".publicKeys = [ hostKey ] ++ vmKeys "allod-dev";
  "secrets/allod-dev-forge-key.age".publicKeys = [ hostKey ] ++ vmKeys "allod-dev";
  "secrets/vm-host-keys/nexus-ssh.age".publicKeys = [ hostKey ];
  "secrets/vm-host-keys/allod-dev-ssh.age".publicKeys = [ hostKey ];
  "secrets/vm-host-keys/privacy-1-ssh.age".publicKeys = [ hostKey ];
}
