let
  machineHostKeys = builtins.fromJSON (builtins.readFile ./machine-host-keys.json);
  hostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKrf3aZ6bTnSYT+GpotLCyaRw8irbkwY1DdUgrLcewFj host";

  vmKeys = vm:
    let d = machineHostKeys.${vm};
    in [ d.active ] ++ (if d.staged != null then [ d.staged ] else []);
in {
  "secrets/forgejo-https-token-dev-1.age".publicKeys  = [ hostKey ] ++ vmKeys "dev-1";
  "secrets/agent-pr-token.age".publicKeys             = [ hostKey ] ++ vmKeys "dev-1";
}
