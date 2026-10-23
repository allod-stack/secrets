{ lib, pkgs, registryRecipients, secretsNix }:
  let
    derive = args: (import ../lib/registry-recipients.nix args).recipients;
    diagnose = args: (import ../lib/registry-recipients.nix args).diagnostics;
    rejects = args:
      !(builtins.tryEval (builtins.deepSeq (derive args) true)).success;

    fixtureKeys = {
      dev-a = { active = "dev-a-active"; staged = null; };
      dev-b = { active = "dev-b-active"; staged = "dev-b-staged"; };
      hv-b = { active = "hv-b-active"; staged = "hv-b-staged"; };
    };
    fixtureHypervisorPublicKeys = [ "forge-host-active" "forge-host-staged" ];
    target = system: kind: {
      inherit system kind;
      deployed_path = "/run/credentials/${system}";
      verify = "true";
    };
    fixtureRegistry = {
      shared = {
        service = "forgejo";
        registry_alias = "shared";
        rotation_strategy = "overlap";
        credentials = [
          {
            credential = "cred-a";
            secret_path = "secrets/cred-a.age";
            targets = [ (target "dev-a" "dev-vm") (target "forge-host" "nixos-host") ];
          }
          {
            credential = "cred-b";
            secret_path = "secrets/cred-b.age";
            targets = [ (target "dev-b" "dev-vm") (target "dev-a" "dev-vm") (target "dev-b" "dev-vm") ];
          }
        ];
      };
      solo = {
        service = "none";
        registry_alias = "solo";
        rotation_strategy = "in-place";
        credentials = [
          {
            credential = "host-only";
            secret_path = "secrets/host-only.age";
            targets = [ (target "forge-host" "nixos-host") ];
          }
          {
            credential = "host-b-only";
            secret_path = "secrets/host-b-only.age";
            targets = [ (target "hv-b" "nixos-host") ];
          }
        ];
      };
    };
    fixtureArgs = {
      registry = fixtureRegistry;
      machineHostKeys = fixtureKeys;
      hypervisorPublicKeys = fixtureHypervisorPublicKeys;
      primaryHostname = "forge-host";
    };
    fixture = derive fixtureArgs;

    withSolo = credential: fixtureArgs // {
      registry = fixtureRegistry // {
        solo = fixtureRegistry.solo // { credentials = [ credential ]; };
      };
    };
    unknownMachineSabotage = withSolo {
      credential = "stray";
      secret_path = "secrets/stray.age";
      targets = [ (target "missing-dev" "dev-vm") ];
    };
    duplicatePathSabotage = withSolo {
      credential = "twin";
      secret_path = "secrets/cred-a.age";
      targets = [ (target "dev-b" "dev-vm") ];
    };
    emptyHypervisorSabotage = fixtureArgs // { hypervisorPublicKeys = []; };
    duplicateHypervisorSabotage = fixtureArgs // {
      hypervisorPublicKeys = [ "forge-host-active" "forge-host-active" ];
    };
    unregisteredHypervisorSabotage = withSolo {
      credential = "rogue-hv";
      secret_path = "secrets/rogue-hv.age";
      targets = [ (target "hv-ghost" "nixos-host") ];
    };

    consumed = lib.all
      (path: secretsNix ? ${path} && secretsNix.${path}.publicKeys == registryRecipients.${path}.publicKeys)
      (builtins.attrNames registryRecipients);
  in
  assert lib.assertMsg (derive (fixtureArgs // { registry = {}; }) == {})
    "registry-recipients: an empty registry derived recipients";
  assert lib.assertMsg (fixture == {
    "secrets/cred-a.age".publicKeys = [ "forge-host-active" "forge-host-staged" "dev-a-active" ];
    "secrets/cred-b.age".publicKeys = [ "forge-host-active" "forge-host-staged" "dev-b-active" "dev-b-staged" "dev-a-active" ];
    "secrets/host-only.age".publicKeys = [ "forge-host-active" "forge-host-staged" ];
    "secrets/host-b-only.age".publicKeys = [ "forge-host-active" "forge-host-staged" "hv-b-active" "hv-b-staged" ];
  }) "registry-recipients: recipient derivation drifted";
  assert lib.assertMsg (diagnose fixtureArgs == [])
    "registry-recipients: the positive fixture produced diagnostics";
  assert lib.assertMsg (rejects unknownMachineSabotage)
    "registry-recipients: a target machine absent from machine-host-keys.json was accepted";
  assert lib.assertMsg (diagnose unknownMachineSabotage == [
    "credential 'stray' targets machine 'missing-dev', which has no entry in machine-host-keys.json; a hypervisor target needs kind \"nixos-host\""
  ]) "registry-recipients: the unknown-machine refusal does not name the credential and the machine";
  assert lib.assertMsg (rejects duplicatePathSabotage)
    "registry-recipients: two credentials on one secret_path were accepted";
  assert lib.assertMsg (diagnose duplicatePathSabotage == [
    "more than one registry credential names the secret_path 'secrets/cred-a.age'"
  ]) "registry-recipients: the duplicate-path refusal does not name the path";
  assert lib.assertMsg (rejects emptyHypervisorSabotage)
    "registry-recipients: an empty hypervisor key list was accepted";
  assert lib.assertMsg (rejects duplicateHypervisorSabotage)
    "registry-recipients: a duplicate hypervisor key was accepted";
  assert lib.assertMsg (fixture."secrets/host-b-only.age".publicKeys == [
    "forge-host-active" "forge-host-staged" "hv-b-active" "hv-b-staged"
  ]) "registry-recipients: a nixos-host target on a registered second hypervisor did not resolve to its own keys";
  assert lib.assertMsg (fixture."secrets/host-only.age".publicKeys == [
    "forge-host-active" "forge-host-staged"
  ]) "registry-recipients: a nixos-host target on the primary resolved to more than the primary's keys";
  assert lib.assertMsg (rejects unregisteredHypervisorSabotage)
    "registry-recipients: a nixos-host target naming neither the primary nor a registered hypervisor was accepted";
  assert lib.assertMsg (diagnose unregisteredHypervisorSabotage == [
    "credential 'rogue-hv' targets hypervisor 'hv-ghost', which is neither the primary hypervisor nor registered in machine-host-keys.json"
  ]) "registry-recipients: the unregistered-hypervisor refusal does not name the credential and the hypervisor";
  assert lib.assertMsg consumed
    "registry-recipients: secrets.nix does not carry every derived recipient line unchanged";
  pkgs.runCommand "registry-recipients" { } ''
    touch "$out"
  ''
