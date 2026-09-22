{ lib, pkgs, devSshHosts, devIdentities, identity }:
  let
    # A fixture deployment: its own hypervisor, forge host, dev and
    # privacy machines, so the reserved-name refusals are pinned
    # against names this template never uses.
    fixtureIdentity = {
      hostname = "fixture-hyp";
      forgeHost = "forge.fixture.invalid";
      devVMs = {
        fixture-dev = { sshKeyName = "fixture_vm"; };
        fixture-bare = { sshKeyName = "bare_vm"; };
      };
      privacyVMs = {
        fixture-privacy = { username = "privacy"; };
      };
    };

    projectFixture = sshHosts: devSshHosts.project {
      identity = fixtureIdentity;
      machineName = "fixture-dev";
      vm = { sshKeyName = "fixture_vm"; } // sshHosts;
    };

    bare = devSshHosts.project {
      identity = fixtureIdentity;
      machineName = "fixture-bare";
      vm = fixtureIdentity.devVMs.fixture-bare;
    };

    projected = projectFixture {
      sshHosts = {
        fixture-cache = {
          hostname = "198.51.100.40";
          user = "cache";
          extraOptions.HostKeyAlias = "fixture-cache";
        };
        fixture-own-key = {
          hostname = "198.51.100.41";
          identityFile = "~/.ssh/fixture_other";
        };
      };
    };

    # Each sabotage is a thunk, forced one at a time, so the whole set
    # is never live at once.
    rejectsSet = sshHosts:
      !(builtins.tryEval
        (builtins.deepSeq (projectFixture { inherit sshHosts; }) true)).success;

    rejects = alias: entry: rejectsSet { ${alias} = entry; };

    goodEntry = { hostname = "198.51.100.42"; };
  in
  assert lib.assertMsg (bare == {})
    "dev-ssh-hosts: a dev machine without sshHosts must project to an empty set";
  assert lib.assertMsg (projected.fixture-cache.identityFile == "~/.ssh/fixture_vm")
    "dev-ssh-hosts: identityFile must default to the VM's own key";
  assert lib.assertMsg (projected.fixture-cache.identitiesOnly == true)
    "dev-ssh-hosts: identitiesOnly must default to true";
  assert lib.assertMsg (projected.fixture-cache.hostname == "198.51.100.40"
      && projected.fixture-cache.user == "cache"
      && projected.fixture-cache.extraOptions.HostKeyAlias == "fixture-cache")
    "dev-ssh-hosts: the entry's own fields must survive the defaults";
  assert lib.assertMsg (projected.fixture-own-key.identityFile == "~/.ssh/fixture_other")
    "dev-ssh-hosts: an entry that sets identityFile must keep its own value";
  assert lib.assertMsg (rejects "FIXTURE-DEV" goodEntry)
    "dev-ssh-hosts: an upper-cased machine name must be refused";
  assert lib.assertMsg (rejects "forge.fixture.invalid" goodEntry)
    "dev-ssh-hosts: the forge host must be refused";
  assert lib.assertMsg (rejects "*" goodEntry)
    "dev-ssh-hosts: a glob alias must be refused";
  assert lib.assertMsg (rejects "a b" goodEntry)
    "dev-ssh-hosts: a two-pattern alias must be refused";
  assert lib.assertMsg (rejects "Host x" goodEntry)
    "dev-ssh-hosts: a literal Host header must be refused";
  assert lib.assertMsg (rejects "fixture-nohost" { user = "cache"; })
    "dev-ssh-hosts: an entry without a string hostname must be refused";
  assert lib.assertMsg (rejects "fixture-string" "198.51.100.43")
    "dev-ssh-hosts: an entry that is not an attribute set must be refused";
  assert lib.assertMsg (rejects "fixture-header" {
      hostname = "198.51.100.44";
      extraOptions.header = "Host forge.fixture.invalid";
    })
    "dev-ssh-hosts: an extraOptions header must be refused";
  assert lib.assertMsg (rejects "fixture-newline" {
      hostname = "198.51.100.45\nHost forge.fixture.invalid";
    })
    "dev-ssh-hosts: a newline inside a string field must be refused";
  assert lib.assertMsg (rejectsSet {
      "A-cache" = { hostname = "198.51.100.46"; };
      "a-cache" = { hostname = "198.51.100.47"; };
    })
    "dev-ssh-hosts: two aliases differing only by case must be refused";
  # The composed half: the template's own projection, not a fixture.
  assert lib.assertMsg
    (devIdentities.allod-dev.sshHosts.example-build-cache.identityFile
       == "~/.ssh/${identity.devVMs.allod-dev.sshKeyName}"
     && devIdentities.allod-dev.sshHosts.example-build-cache.identitiesOnly == true
     && devIdentities.allod-dev.sshHosts.example-build-cache.extraOptions.HostKeyAlias
       == "example-build-cache")
    "dev-ssh-hosts: the template's own dev machine must carry the defaulted external alias";
  pkgs.runCommand "dev-ssh-hosts-check" {} ''
    echo "dev VM SSH alias projection validation passed"
    touch $out
  ''
