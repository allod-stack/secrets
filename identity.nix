rec {
  username = "allod";
  email = "allod@example.com";

  hostname = "nexus";
  hostPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJvgPQ/XEO5jFd5Q5lfp1tMnCeK3RbRP0k0U05fBR0iu nexus";
  hostPublicKeys = [ hostPublicKey ];

  forgeHost = "forge.anarch.diy";
  forgePort = 2222;
  forgeUser = "allod-agent";

  gpgSigningKey = null;

  devVMs = {
    allod-dev = { sshKeyName = "allod_vm"; };
  };

  privacyVMs = {
    privacy-1 = { username = "privacy"; };
  };

  sshHosts = {
    allod-dev = {
      hostname = "192.0.2.10";
      user = "allod";
      identityFile = "~/.ssh/allod_vm";
    };
    privacy-1 = {
      hostname = "192.0.2.11";
      user = "privacy";
      identityFile = "~/.ssh/host";
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
