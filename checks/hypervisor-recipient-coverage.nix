{ lib, pkgs, identity, secretsNix, machineHostKeys, machines }:
  let
    # The rule as a function of exactly what it needs, so the fixtures below
    # drive the same logic the real data is checked against: if a secret's
    # recipients include any key of guest g, they must also include a key of
    # the hypervisor that runs g (machines.<g>.host, or the primary when
    # absent). A guest's own host-key secret is checked the same way even
    # though it never lists the guest's own key as a recipient.
    hypervisorRecipientDiagnostics = { machines, secretsRules, primaryKeys, machineHostKeys }:
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
          in if host == null then primaryKeys else vmKeys host;

        secretsList = lib.mapAttrsToList
          (path: s: { inherit path; publicKeys = s.publicKeys; })
          secretsRules;

        hasAny = keys: candidates: lib.any (k: builtins.elem k candidates) keys;

        recipientGaps = lib.concatMap (g:
          let
            guestKeys = vmKeys g;
            hvKeys = hypervisorKeysFor g;
          in
          lib.concatMap (s:
            if guestKeys != [] && hasAny guestKeys s.publicKeys
               && !(hasAny hvKeys s.publicKeys)
            then [ { secret = s.path; guest = g; } ]
            else []
          ) secretsList
        ) guestNames;

        hostKeyGaps = lib.concatMap (g:
          let
            path = "secrets/vm-host-keys/${g}-ssh.age";
            hvKeys = hypervisorKeysFor g;
          in
          if secretsRules ? ${path} && !(hasAny hvKeys secretsRules.${path}.publicKeys)
          then [ { secret = path; guest = g; } ]
          else []
        ) guestNames;
      in { inherit recipientGaps hostKeyGaps; };

    real = hypervisorRecipientDiagnostics {
      inherit machines machineHostKeys;
      secretsRules = secretsNix;
      primaryKeys = identity.hostPublicKeys;
    };

    # A second, fixture-only hypervisor: one guest it hosts, and one guest
    # left on the primary by omitting `host`, so both branches of "which
    # hypervisor runs g" run.
    fixtureMachines = {
      fixture-guest-hosted = { type = "dev"; host = "fixture-hv-2"; };
      fixture-guest-primary = { type = "dev"; };
      fixture-hv-2 = { type = "hypervisor"; };
    };
    fixtureMachineHostKeys = {
      fixture-guest-hosted = { active = "fixture-guest-hosted-key"; staged = null; };
      fixture-guest-primary = { active = "fixture-guest-primary-key"; staged = null; };
      fixture-hv-2 = { active = "fixture-hv-2-key"; staged = null; };
    };
    fixturePrimaryKeys = [ "fixture-primary-key" ];

    fixtureHealthySecrets = {
      "secrets/fixture-guest-hosted-token.age".publicKeys =
        [ "fixture-primary-key" "fixture-hv-2-key" "fixture-guest-hosted-key" ];
      "secrets/fixture-guest-primary-token.age".publicKeys =
        [ "fixture-primary-key" "fixture-guest-primary-key" ];
      "secrets/vm-host-keys/fixture-guest-hosted-ssh.age".publicKeys =
        [ "fixture-primary-key" "fixture-hv-2-key" ];
      "secrets/vm-host-keys/fixture-guest-primary-ssh.age".publicKeys =
        [ "fixture-primary-key" ];
    };

    # A recipient set naming the hosted guest but not its host hypervisor:
    # the property this check exists to catch.
    fixtureSabotagedSecrets = fixtureHealthySecrets // {
      "secrets/fixture-guest-hosted-token.age".publicKeys =
        [ "fixture-primary-key" "fixture-guest-hosted-key" ];
    };

    fixtureArgs = secretsRules: {
      machines = fixtureMachines;
      machineHostKeys = fixtureMachineHostKeys;
      primaryKeys = fixturePrimaryKeys;
      inherit secretsRules;
    };

    fixtureHealthy = hypervisorRecipientDiagnostics (fixtureArgs fixtureHealthySecrets);
    fixtureSabotaged = hypervisorRecipientDiagnostics (fixtureArgs fixtureSabotagedSecrets);
  in
  assert lib.assertMsg (fixtureHealthy.recipientGaps == [] && fixtureHealthy.hostKeyGaps == [])
    "hypervisor-recipient-coverage: a correctly-covered two-hypervisor fixture was refused";
  assert lib.assertMsg (fixtureSabotaged.recipientGaps == [
    { secret = "secrets/fixture-guest-hosted-token.age"; guest = "fixture-guest-hosted"; }
  ]) "hypervisor-recipient-coverage: sabotage accepted: a guest's recipient set named the guest but not its host hypervisor";
  assert lib.assertMsg (fixtureSabotaged.hostKeyGaps == [])
    "hypervisor-recipient-coverage: sabotage tripped an unrelated diagnostic";
  assert lib.assertMsg (real.recipientGaps == [])
    "hypervisor-recipient-coverage: secrets.nix entries missing their guest's host hypervisor: ${
      lib.concatMapStringsSep ", " (g: "${g.secret} (${g.guest})") real.recipientGaps
    }";
  assert lib.assertMsg (real.hostKeyGaps == [])
    "hypervisor-recipient-coverage: a guest's host-key secret is missing its host hypervisor: ${
      lib.concatMapStringsSep ", " (g: "${g.secret} (${g.guest})") real.hostKeyGaps
    }";
  pkgs.runCommand "hypervisor-recipient-coverage-check" {} ''
    echo "hypervisor recipient coverage validation passed"
    touch "$out"
  ''
