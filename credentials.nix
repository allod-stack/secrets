let
  identity = import ./identity.nix;
  machineHostKeys = builtins.fromJSON (builtins.readFile ./machine-host-keys.json);
  forgeSshKeys = builtins.fromJSON (builtins.readFile ./forge-ssh-keys.json);
  vmNames = builtins.attrNames machineHostKeys;
  forgeKeyNames = builtins.attrNames forgeSshKeys;

  mkActiveEntry = vm: {
    name           = "${vm}-host";
    kind           = "machine-host";
    owner          = vm;
    public_key     = machineHostKeys.${vm}.active;
    consumers      = [
      { type = "agenix"; repo = "secrets"; secret = "secrets/vm-host-keys/${vm}-ssh.age"; }
    ];
    rotation_state = "active";
  };

  mkStagedEntry = vm: {
    name           = "${vm}-host-staged";
    kind           = "machine-host";
    owner          = vm;
    public_key     = machineHostKeys.${vm}.staged;
    consumers      = [
      { type = "agenix"; repo = "secrets"; secret = "secrets/vm-host-keys/${vm}-ssh.age"; }
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

  hostEntries = builtins.listToAttrs (builtins.genList
    (index:
      let
        isActive = index == 0;
        suffix = if isActive then "" else if index == 1 then "-staged" else "-staged-${toString index}";
      in {
        name = "${identity.hostname}-host${suffix}";
        value = {
          name = "${identity.hostname}-host${suffix}";
          kind = "machine-host";
          owner = identity.hostname;
          public_key = builtins.elemAt identity.hostPublicKeys index;
          consumers = [{
            type = "agenix";
            repo = "secrets";
            secret = "secrets/vm-host-keys/${identity.hostname}-ssh.age";
          }];
          rotation_state = if isActive then "active" else "staged";
        };
      })
    (builtins.length identity.hostPublicKeys));

  mkForgeGitEntry = forgeKey:
    let
      data = forgeSshKeys.${forgeKey};
      hasStaged = data.staged != null;
    in {
      name           = forgeKey;
      kind           = "forge-git";
      owner          = data.owner;
      public_key     = if hasStaged then data.staged else data.active;
      consumers      = [
        { type = "forge-key-secret"; repo = "secrets"; secret = data.secret; }
        { type = "forgejo-ssh"; account = data.account; key = forgeKey; }
      ];
      rotation_state = if hasStaged then "staged" else "active";
    };

  forgeGitEntries = builtins.listToAttrs (map (forgeKey: {
    name = forgeKey;
    value = mkForgeGitEntry forgeKey;
  }) forgeKeyNames);
in
hostEntries // activeEntries // stagedEntries // forgeGitEntries // {
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

  forgejo-https-token-allod-dev = {
    name           = "forgejo-https-token-allod-dev";
    kind           = "agent";
    owner          = "allod-agent";
    public_key     = null;
    consumers      = [
      { type = "agenix"; repo = "secrets"; secret = "secrets/forgejo-https-token-allod-dev.age"; }
    ];
    rotation_state = "active";
  };
}
