let
  machineHostKeys = builtins.fromJSON (builtins.readFile ./machine-host-keys.json);
  vmNames = builtins.attrNames machineHostKeys;

  mkActiveEntry = vm: {
    name           = "${vm}-host";
    kind           = "machine-host";
    owner          = vm;
    public_key     = machineHostKeys.${vm}.active;
    consumers      = [
      { type = "agenix"; repo = "profiles"; secret = "secrets/${vm}-ssh.age"; }
    ];
    rotation_state = "active";
  };

  mkStagedEntry = vm: {
    name           = "${vm}-host-staged";
    kind           = "machine-host";
    owner          = vm;
    public_key     = machineHostKeys.${vm}.staged;
    consumers      = [
      { type = "agenix"; repo = "profiles"; secret = "secrets/${vm}-ssh.age"; }
    ];
    rotation_state = "staged";
  };

  activeEntries = builtins.listToAttrs (map (vm: {
    name  = "${vm}-host";
    value = mkActiveEntry vm;
  }) vmNames);

  stagedEntries = builtins.listToAttrs (builtins.concatLists (map (vm:
    if machineHostKeys.${vm}.staged != null then [{
      name  = "${vm}-host-staged";
      value = mkStagedEntry vm;
    }] else []
  ) vmNames));
in
activeEntries // stagedEntries // {
  dev_1 = {
    name           = "dev_1";
    kind           = "forge-git";
    owner          = "dev-1";
    public_key     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILQEW5UsP3/cDNzpI4j28k8vKU87pC0jO/9m6Igy1lUT dev_1";
    consumers      = [
      { type = "forge-key-secret"; repo = "secrets"; secret = "secrets/dev-1-forge-key.age"; }
      { type = "forgejo-ssh"; account = "allod-agent"; key = "dev_1"; }
    ];
    rotation_state = "active";
  };

  agent-pr-token = {
    name           = "agent-pr-token";
    kind           = "agent";
    owner          = "allod-agent";
    public_key     = null;
    consumers      = [
      { type = "agenix"; repo = "secrets"; secret = "secrets/agent-pr-token.age"; }
    ];
    rotation_state = "active";
  };

  forgejo-https-token-dev-1 = {
    name           = "forgejo-https-token-dev-1";
    kind           = "agent";
    owner          = "allod-agent";
    public_key     = null;
    consumers      = [
      { type = "agenix"; repo = "secrets"; secret = "secrets/forgejo-https-token-dev-1.age"; }
    ];
    rotation_state = "active";
  };
}
