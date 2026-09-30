{ lib, pkgs, identity, secretsNix, machineHostKeys, machines }:
  let
    # Contract: a secret naming a guest's key must also name a key of the
    # hypervisor that runs that guest; a guest registered in
    # machine-host-keys.json must have its own vm-host-keys rule, and that
    # rule obeys the same recipient contract.
    # Trap: the primary is never registered in machine-host-keys.json.
    hypervisorRecipientDiagnostics = { machines, secretsRules, primaryKeys, primaryName, machineHostKeys }:
      let
        vmKeys = name:
          if machineHostKeys ? ${name}
          then
            let d = machineHostKeys.${name};
            in [ d.active ] ++ (if (d.staged or null) != null then [ d.staged ] else [])
          else [];

        guestNames = builtins.attrNames
          (lib.filterAttrs (_: m: (m.type or null) != "hypervisor") machines);

        hypervisorKeysFor = g:
          let host = machines.${g}.host or null;
          in
            if host == null || host == primaryName then primaryKeys
            else if machineHostKeys ? ${host} then vmKeys host
            else throw "hypervisor-recipient-coverage: guest ${g}'s host ${host} has no registered keys in machine-host-keys.json";

        secretsList = lib.mapAttrsToList
          (path: s: { inherit path; publicKeys = s.publicKeys; })
          secretsRules;

        hasAny = keys: candidates: lib.any (k: builtins.elem k candidates) keys;

        recipientGaps = lib.concatMap (g:
          let
            guestKeys = vmKeys g;
            hvKeys = hypervisorKeysFor g;
          in
          builtins.seq hvKeys (
            lib.concatMap (s:
              if guestKeys != [] && hasAny guestKeys s.publicKeys
                 && !(hasAny hvKeys s.publicKeys)
              then [ { secret = s.path; guest = g; } ]
              else []
            ) secretsList
          )
        ) guestNames;

        hostKeyGaps = lib.concatMap (g:
          if !(machineHostKeys ? ${g}) then []
          else
            let
              path = "secrets/vm-host-keys/${g}-ssh.age";
              hvKeys = hypervisorKeysFor g;
            in
            builtins.seq hvKeys (
              if !(secretsRules ? ${path})
              then [ { secret = path; guest = g; reason = "the rule is missing"; } ]
              else if !(hasAny hvKeys secretsRules.${path}.publicKeys)
              then [ { secret = path; guest = g; reason = "recipients omit the host hypervisor's key"; } ]
              else []
            )
        ) guestNames;
      in { inherit recipientGaps hostKeyGaps; };

    real = hypervisorRecipientDiagnostics {
      inherit machines machineHostKeys;
      secretsRules = secretsNix;
      primaryKeys = identity.hostPublicKeys;
      primaryName = identity.hostname;
    };

    fixturePrimaryName = "fixture-primary-hv";
    fixtureSecondaryName = "fixture-secondary-hv";

    fixtureSingleMachines = {
      fixture-solo-guest = { type = "dev"; };
    };
    fixtureSingleMachineHostKeys = {
      fixture-solo-guest = { active = "fixture-solo-guest-key"; staged = null; };
    };
    fixtureSingleArgs = secretsRules: {
      machines = fixtureSingleMachines;
      machineHostKeys = fixtureSingleMachineHostKeys;
      primaryKeys = [ "fixture-solo-primary-key" ];
      primaryName = "fixture-solo-primary-hv";
      inherit secretsRules;
    };
    fixtureSingleHealthy = hypervisorRecipientDiagnostics (fixtureSingleArgs {
      "secrets/fixture-solo-guest-token.age".publicKeys =
        [ "fixture-solo-primary-key" "fixture-solo-guest-key" ];
      "secrets/vm-host-keys/fixture-solo-guest-ssh.age".publicKeys =
        [ "fixture-solo-primary-key" ];
    });

    fixtureTwoMachines = {
      ${fixturePrimaryName} = { type = "hypervisor"; };
      ${fixtureSecondaryName} = { type = "hypervisor"; };
      fixture-guest-on-primary = { type = "dev"; host = fixturePrimaryName; };
      fixture-guest-on-secondary = { type = "dev"; host = fixtureSecondaryName; };
    };
    fixtureTwoMachineHostKeys = {
      fixture-guest-on-primary = { active = "fixture-guest-on-primary-key"; staged = null; };
      fixture-guest-on-secondary = { active = "fixture-guest-on-secondary-key"; staged = null; };
      ${fixtureSecondaryName} = { active = "fixture-secondary-hv-key"; staged = null; };
    };
    fixtureTwoPrimaryKeys = [ "fixture-two-primary-key" ];
    fixtureTwoArgs = secretsRules: {
      machines = fixtureTwoMachines;
      machineHostKeys = fixtureTwoMachineHostKeys;
      primaryKeys = fixtureTwoPrimaryKeys;
      primaryName = fixturePrimaryName;
      inherit secretsRules;
    };
    fixtureTwoHealthySecrets = {
      "secrets/fixture-guest-on-primary-token.age".publicKeys =
        [ "fixture-two-primary-key" "fixture-guest-on-primary-key" ];
      "secrets/fixture-guest-on-secondary-token.age".publicKeys =
        [ "fixture-secondary-hv-key" "fixture-guest-on-secondary-key" ];
      "secrets/vm-host-keys/fixture-guest-on-primary-ssh.age".publicKeys =
        [ "fixture-two-primary-key" ];
      "secrets/vm-host-keys/fixture-guest-on-secondary-ssh.age".publicKeys =
        [ "fixture-secondary-hv-key" ];
    };
    fixtureTwoHealthy = hypervisorRecipientDiagnostics (fixtureTwoArgs fixtureTwoHealthySecrets);

    fixtureSabotageASecrets = fixtureTwoHealthySecrets // {
      "secrets/fixture-guest-on-secondary-token.age".publicKeys =
        [ "fixture-guest-on-secondary-key" ];
    };
    fixtureSabotagedA = hypervisorRecipientDiagnostics (fixtureTwoArgs fixtureSabotageASecrets);

    fixtureSabotageBSecrets = fixtureTwoHealthySecrets // {
      "secrets/fixture-guest-on-primary-token.age".publicKeys =
        [ "fixture-guest-on-primary-key" ];
    };
    fixtureSabotagedB = hypervisorRecipientDiagnostics (fixtureTwoArgs fixtureSabotageBSecrets);

    fixtureHostKeyRecipientsSecrets = fixtureTwoHealthySecrets // {
      "secrets/vm-host-keys/fixture-guest-on-secondary-ssh.age".publicKeys =
        [ "fixture-unrelated-key" ];
    };
    fixtureSabotagedHostKeyRecipients =
      hypervisorRecipientDiagnostics (fixtureTwoArgs fixtureHostKeyRecipientsSecrets);

    fixtureHostKeyMissingRuleSecrets =
      builtins.removeAttrs fixtureTwoHealthySecrets
        [ "secrets/vm-host-keys/fixture-guest-on-primary-ssh.age" ];
    fixtureSabotagedHostKeyMissingRule =
      hypervisorRecipientDiagnostics (fixtureTwoArgs fixtureHostKeyMissingRuleSecrets);

    fixtureUnregisteredHostArgs = (fixtureTwoArgs fixtureTwoHealthySecrets) // {
      machines = fixtureTwoMachines // {
        fixture-guest-on-unregistered = { type = "dev"; host = "fixture-unregistered-hv"; };
      };
      machineHostKeys = fixtureTwoMachineHostKeys // {
        fixture-guest-on-unregistered = { active = "fixture-guest-on-unregistered-key"; staged = null; };
      };
      secretsRules = fixtureTwoHealthySecrets // {
        "secrets/fixture-guest-on-unregistered-token.age".publicKeys =
          [ "fixture-guest-on-unregistered-key" ];
      };
    };
    rejects = args: !(builtins.tryEval (builtins.deepSeq (hypervisorRecipientDiagnostics args) true)).success;
  in
  assert lib.assertMsg (fixtureSingleHealthy.recipientGaps == [] && fixtureSingleHealthy.hostKeyGaps == [])
    "hypervisor-recipient-coverage: a correctly-covered single-hypervisor fixture was refused";
  assert lib.assertMsg (fixtureTwoHealthy.recipientGaps == [] && fixtureTwoHealthy.hostKeyGaps == [])
    "hypervisor-recipient-coverage: a correctly-covered two-hypervisor fixture was refused";
  assert lib.assertMsg (fixtureSabotagedA.recipientGaps == [
    { secret = "secrets/fixture-guest-on-secondary-token.age"; guest = "fixture-guest-on-secondary"; }
  ] && fixtureSabotagedA.hostKeyGaps == [])
    "hypervisor-recipient-coverage: sabotage (a) accepted or tripped an unexpected diagnostic";
  assert lib.assertMsg (fixtureSabotagedB.recipientGaps == [
    { secret = "secrets/fixture-guest-on-primary-token.age"; guest = "fixture-guest-on-primary"; }
  ] && fixtureSabotagedB.hostKeyGaps == [])
    "hypervisor-recipient-coverage: sabotage (b) accepted or tripped an unexpected diagnostic";
  assert lib.assertMsg (fixtureSabotagedHostKeyRecipients.recipientGaps == []
    && fixtureSabotagedHostKeyRecipients.hostKeyGaps == [
      { secret = "secrets/vm-host-keys/fixture-guest-on-secondary-ssh.age";
        guest = "fixture-guest-on-secondary";
        reason = "recipients omit the host hypervisor's key"; }
    ])
    "hypervisor-recipient-coverage: sabotage (host-key recipients) accepted or tripped an unexpected diagnostic";
  assert lib.assertMsg (fixtureSabotagedHostKeyMissingRule.recipientGaps == []
    && fixtureSabotagedHostKeyMissingRule.hostKeyGaps == [
      { secret = "secrets/vm-host-keys/fixture-guest-on-primary-ssh.age";
        guest = "fixture-guest-on-primary";
        reason = "the rule is missing"; }
    ])
    "hypervisor-recipient-coverage: sabotage (host-key rule missing) accepted or tripped an unexpected diagnostic";
  assert lib.assertMsg (rejects fixtureUnregisteredHostArgs)
    "hypervisor-recipient-coverage: sabotage (c) accepted: a guest named a host with no registered keys";
  assert lib.assertMsg (real.recipientGaps == [])
    "hypervisor-recipient-coverage: secrets.nix entries missing their guest's host hypervisor: ${
      lib.concatMapStringsSep ", " (g: "${g.secret} (${g.guest})") real.recipientGaps
    }";
  assert lib.assertMsg (real.hostKeyGaps == [])
    "hypervisor-recipient-coverage: a guest's host-key secret is missing its host hypervisor: ${
      lib.concatMapStringsSep ", " (g: "${g.secret} (${g.guest}): ${g.reason}") real.hostKeyGaps
    }";
  pkgs.runCommand "hypervisor-recipient-coverage-check" {} ''
    echo "hypervisor recipient coverage validation passed"
    touch "$out"
  ''
