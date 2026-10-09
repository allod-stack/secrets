{ lib, pkgs, mkForgeUrl, devIdentities, nexusIdentity, identity }:
  let
    fixtureNoUrl = { forgeHost = "forge.fixture.invalid"; };
    fixtureWithUrl = {
      forgeHost = "forge.fixture.invalid";
      forgeUrl = "http://192.0.2.12";
    };
  in
  assert lib.assertMsg (mkForgeUrl fixtureNoUrl == "https://forge.fixture.invalid")
    "forge-url: an identity without forgeUrl must default to https on forgeHost";
  assert lib.assertMsg (mkForgeUrl fixtureWithUrl == "http://192.0.2.12")
    "forge-url: an identity's own forgeUrl must survive verbatim";
  assert lib.assertMsg (devIdentities.allod-dev.forgeUrl == identity.forgeUrl)
    "forge-url: the template's own dev VM must carry the template's forgeUrl";
  assert lib.assertMsg (nexusIdentity.forgeUrl == identity.forgeUrl)
    "forge-url: nexusIdentity must carry the template's forgeUrl";
  pkgs.runCommand "forge-url-check" {} ''
    echo "forge URL default and override validation passed"
    touch $out
  ''
