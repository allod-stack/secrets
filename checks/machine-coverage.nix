{ lib, pkgs, identity, machineHostKeys, machines }:
  let
    # Contract: inventory guests, machine-host-keys.json entries and
    # identity.nix names are one set, each identity in its type's attrset.
    # Trap: the primary hypervisor is never in machine-host-keys.json (its
    # key is identity.hostPublicKeys); a second hypervisor may be.
    identitySets = { dev = "devVMs"; privacy = "privacyVMs"; service = "serviceVMs"; };

    machineCoverageDiagnostics = { machines, machineHostKeys, identity, primaryName }:
      let
        guests = lib.filterAttrs (_: m: (m.type or null) != "hypervisor") machines;
        guestNames = builtins.attrNames guests;
        machineNames = builtins.attrNames machines;
        hostKeyNames = builtins.attrNames machineHostKeys;

        guestsWithoutHostKey = builtins.filter (g: !(machineHostKeys ? ${g})) guestNames;
        hostKeysWithoutMachine = builtins.filter (n: !(builtins.elem n machineNames)) hostKeyNames;
        hostKeysForPrimary = builtins.filter (n: n == primaryName) hostKeyNames;

        # Every declared identity, tagged with the attrset it came from.
        declared = lib.concatMap (set:
          map (name: { inherit name set; }) (builtins.attrNames (identity.${set} or {}))
        ) (builtins.attrValues identitySets);
        declaredNames = map (d: d.name) declared;

        guestsWithoutIdentity = builtins.filter (g: !(builtins.elem g declaredNames)) guestNames;
        identitiesWithoutMachine = builtins.filter (d: !(guests ? ${d.name})) declared;
        identitiesInWrongSet = builtins.filter (d:
          guests ? ${d.name}
          && identitySets.${guests.${d.name}.type or "<untyped>"} or null != d.set
        ) declared;
        duplicateIdentities = lib.unique (builtins.filter
          (n: builtins.length (builtins.filter (m: m == n) declaredNames) > 1)
          declaredNames);
      in {
        inherit guestsWithoutHostKey hostKeysWithoutMachine hostKeysForPrimary
          guestsWithoutIdentity identitiesWithoutMachine identitiesInWrongSet
          duplicateIdentities;
      };

    clean = d:
      d.guestsWithoutHostKey == [] && d.hostKeysWithoutMachine == [] && d.hostKeysForPrimary == []
      && d.guestsWithoutIdentity == [] && d.identitiesWithoutMachine == []
      && d.identitiesInWrongSet == [] && d.duplicateIdentities == [];

    real = machineCoverageDiagnostics {
      inherit machines machineHostKeys identity;
      primaryName = identity.hostname;
    };

    # Fixtures: one healthy deployment with a guest of every type and a
    # second hypervisor, then one sabotage per refusal. No real machine is
    # named (testing.md), so the fleet can change without touching these.
    fixturePrimary = "fixture-hv";
    fixtureMachines = {
      ${fixturePrimary} = { type = "hypervisor"; };
      fixture-second-hv = { type = "hypervisor"; };
      fixture-dev = { type = "dev"; };
      fixture-privacy = { type = "privacy"; };
      fixture-service = { type = "service"; };
    };
    fixtureHostKeys = {
      fixture-second-hv = { active = "fixture-second-hv-key"; staged = null; };
      fixture-dev = { active = "fixture-dev-key"; staged = null; };
      fixture-privacy = { active = "fixture-privacy-key"; staged = null; };
      fixture-service = { active = "fixture-service-key"; staged = null; };
    };
    fixtureIdentity = {
      devVMs = { fixture-dev = { sshKeyName = "fixture_dev"; }; };
      privacyVMs = { fixture-privacy = { username = "fixture"; }; };
      serviceVMs = { fixture-service = { }; };
    };
    fixtureArgs = {
      machines = fixtureMachines;
      machineHostKeys = fixtureHostKeys;
      identity = fixtureIdentity;
      primaryName = fixturePrimary;
    };
    fixture = overrides: machineCoverageDiagnostics (fixtureArgs // overrides);

    healthy = fixture { };
    sabotageNoHostKey = fixture {
      machineHostKeys = builtins.removeAttrs fixtureHostKeys [ "fixture-privacy" ];
    };
    sabotageOrphanHostKey = fixture {
      machineHostKeys = fixtureHostKeys // {
        fixture-gone = { active = "fixture-gone-key"; staged = null; };
      };
    };
    sabotagePrimaryHostKey = fixture {
      machineHostKeys = fixtureHostKeys // {
        ${fixturePrimary} = { active = "fixture-hv-key"; staged = null; };
      };
    };
    sabotageNoIdentity = fixture {
      identity = fixtureIdentity // { serviceVMs = { }; };
    };
    sabotageOrphanIdentity = fixture {
      identity = fixtureIdentity // {
        privacyVMs = fixtureIdentity.privacyVMs // { fixture-gone = { username = "gone"; }; };
      };
    };
    sabotageWrongSet = fixture {
      identity = fixtureIdentity // {
        devVMs = { };
        privacyVMs = fixtureIdentity.privacyVMs // { fixture-dev = { username = "dev"; }; };
      };
    };
    sabotageDuplicate = fixture {
      identity = fixtureIdentity // {
        serviceVMs = fixtureIdentity.serviceVMs // { fixture-dev = { }; };
      };
    };

    names = lib.concatStringsSep ", ";
    describe = d: "${d.name} (${d.set})";
  in
  assert lib.assertMsg (clean healthy)
    "machine-coverage: a fixture whose three sets agree was refused";
  assert lib.assertMsg (sabotageNoHostKey.guestsWithoutHostKey == [ "fixture-privacy" ])
    "machine-coverage: sabotage accepted: a guest with no machine-host-keys.json entry";
  assert lib.assertMsg (sabotageOrphanHostKey.hostKeysWithoutMachine == [ "fixture-gone" ])
    "machine-coverage: sabotage accepted: a machine-host-keys.json entry for no machine";
  assert lib.assertMsg (sabotagePrimaryHostKey.hostKeysForPrimary == [ fixturePrimary ])
    "machine-coverage: sabotage accepted: a machine-host-keys.json entry for the primary hypervisor";
  assert lib.assertMsg (sabotageNoIdentity.guestsWithoutIdentity == [ "fixture-service" ])
    "machine-coverage: sabotage accepted: a guest with no identity";
  assert lib.assertMsg (map describe sabotageOrphanIdentity.identitiesWithoutMachine == [ "fixture-gone (privacyVMs)" ])
    "machine-coverage: sabotage accepted: an identity for no machine";
  assert lib.assertMsg (map describe sabotageWrongSet.identitiesInWrongSet == [ "fixture-dev (privacyVMs)" ])
    "machine-coverage: sabotage accepted: a dev machine's identity under privacyVMs";
  assert lib.assertMsg (sabotageDuplicate.duplicateIdentities == [ "fixture-dev" ]
    && map describe sabotageDuplicate.identitiesInWrongSet == [ "fixture-dev (serviceVMs)" ])
    "machine-coverage: sabotage accepted: one name in two identity sets";
  assert lib.assertMsg (real.guestsWithoutHostKey == [])
    "machine-coverage: inventory guests with no entry in machine-host-keys.json: ${names real.guestsWithoutHostKey}";
  assert lib.assertMsg (real.hostKeysWithoutMachine == [])
    "machine-coverage: machine-host-keys.json entries naming no inventory machine: ${names real.hostKeysWithoutMachine}";
  assert lib.assertMsg (real.hostKeysForPrimary == [])
    "machine-coverage: machine-host-keys.json must not carry the primary hypervisor (${identity.hostname}); its key is identity.hostPublicKeys";
  assert lib.assertMsg (real.guestsWithoutIdentity == [])
    "machine-coverage: inventory guests with no identity in identity.nix (devVMs, privacyVMs or serviceVMs): ${names real.guestsWithoutIdentity}";
  assert lib.assertMsg (real.identitiesWithoutMachine == [])
    "machine-coverage: identity.nix entries naming no inventory guest: ${names (map describe real.identitiesWithoutMachine)}";
  assert lib.assertMsg (real.identitiesInWrongSet == [])
    "machine-coverage: identity.nix entries in the attrset of another machine type: ${names (map describe real.identitiesInWrongSet)}";
  assert lib.assertMsg (real.duplicateIdentities == [])
    "machine-coverage: identity.nix names one machine in two attrsets: ${names real.duplicateIdentities}";
  pkgs.runCommand "machine-coverage-check" {} ''
    echo "machine coverage validation passed"
    touch "$out"
  ''
