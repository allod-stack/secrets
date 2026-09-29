{ lib, pkgs, hypervisorIdentities, nexusIdentity, mkVmUsernames }:
  let
    fixtureHypervisors = {
      fixture-hv-a = { username = "hv-a"; hostname = "fixture-hv-a"; };
      fixture-hv-b = { username = "hv-b"; hostname = "fixture-hv-b"; };
    };
    fixtureGuestUsernames = { fixture-guest = "guest"; };

    merged = mkVmUsernames {
      guestUsernames = fixtureGuestUsernames;
      hypervisorIdentities = fixtureHypervisors;
    };

    collidingGuestUsernames = { fixture-hv-a = "guest"; };
    collides = !(builtins.tryEval (builtins.deepSeq
      (mkVmUsernames {
        guestUsernames = collidingGuestUsernames;
        hypervisorIdentities = fixtureHypervisors;
      })
      true)).success;
  in
  assert lib.assertMsg (builtins.attrNames hypervisorIdentities == [ nexusIdentity.hostname ])
    "hypervisor-identities: with one hypervisor declared, hypervisorIdentities must contain exactly the primary";
  assert lib.assertMsg (hypervisorIdentities.${nexusIdentity.hostname} == nexusIdentity)
    "hypervisor-identities: hypervisorIdentities.<primary> must equal nexusIdentity";
  assert lib.assertMsg
    (merged == fixtureGuestUsernames // { fixture-hv-a = "hv-a"; fixture-hv-b = "hv-b"; })
    "hypervisor-identities: mkVmUsernames must fold every hypervisor identity, not just one";
  assert lib.assertMsg collides
    "hypervisor-identities: a hypervisor hostname colliding with a guest machine name must be refused";
  pkgs.runCommand "hypervisor-identities-check" {} ''
    echo "hypervisor identity export and vmUsernames merge validation passed"
    touch $out
  ''
