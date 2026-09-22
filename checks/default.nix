# The check suite, one file per check (allod/secrets#37).
#
# flake.nix calls this once per supported platform with the composition: pkgs,
# the identity and credential data, and the validators lib/ exposes over them.
# Every check is a function of exactly what it reads, declared in its own
# file's argument list, and this index is where each is handed it.
{ lib
, pkgs
, self
, identity
, devSshHosts
, devIdentities
, credentials
, secretsNix
, machineHostKeys
, credentialRegistryDiagnostics
, validateCredentialRegistry
, credentialStoreUrl
, isCredentialStoreUrlTemplate
, isCredentialStoreUrlSource
, credentialStoreUrlSourceClause
, localAuthRefreshDiagnostics
, mkLocalAuthRefreshSources
, rotationRegistry
, mkPiCredentialContract
, piCredentialContract
}:
{
  external-ssh-trust-targets = import ./external-ssh-trust-targets.nix {
    inherit lib pkgs identity;
  };

  dev-ssh-hosts = import ./dev-ssh-hosts.nix {
    inherit lib pkgs devSshHosts devIdentities identity;
  };

  credential-registry = import ./credential-registry.nix {
    inherit lib pkgs credentialRegistryDiagnostics validateCredentialRegistry;
  };

  credential-store-url = import ./credential-store-url.nix {
    inherit lib pkgs credentialStoreUrl isCredentialStoreUrlSource isCredentialStoreUrlTemplate;
  };

  local-auth-refresh = import ./local-auth-refresh.nix {
    inherit lib pkgs localAuthRefreshDiagnostics mkLocalAuthRefreshSources
      credentialStoreUrlSourceClause rotationRegistry;
  };

  pi-credential-registry = import ./pi-credential-registry.nix {
    inherit lib pkgs mkPiCredentialContract piCredentialContract secretsNix;
  };

  credential-inventory = import ./credential-inventory.nix {
    inherit lib pkgs self credentials secretsNix machineHostKeys;
  };
}
