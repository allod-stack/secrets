rec {
  username = "allod";
  email = "allod@example.com";

  hostname = "hypervisor";
  hostPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKrf3aZ6bTnSYT+GpotLCyaRw8irbkwY1DdUgrLcewFj host";

  forgeHost = "forge.anarch.diy";
  forgePort = 2222;
  forgeUser = "allod-agent";

  gpgSigningKey = null;

  devVMs = {
    dev-1 = { sshKeyName = "dev_1"; };
  };

  privacyVMs = {};

  sshHosts = {
    dev-1 = {
      hostname = "192.0.2.10";
      user = "allod";
      identityFile = "~/.ssh/dev_1";
    };
    "forge.anarch.diy" = {
      hostname = "forge.anarch.diy";
      user = "git";
      port = 2222;
      identityFile = "~/.ssh/allod_forge_host";
      identitiesOnly = true;
    };
  };
}
