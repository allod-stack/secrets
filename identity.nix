rec {
  username = "allod";
  email = "allod@example.com";

  hostname = "nexus";
  hostPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJvgPQ/XEO5jFd5Q5lfp1tMnCeK3RbRP0k0U05fBR0iu nexus";
  hostPublicKeys = [ hostPublicKey ];

  forgeHost = "forge.anarch.diy";
  forgePort = 2222;
  forgeUrl = "https://forge.anarch.diy";
  forgeUser = "allod-agent";

  gpgSigningKey = null;

  devVMs = {
    allod-dev = {
      sshKeyName = "allod_vm";
      # false: this VM gets no agent token and no forge identity; every repo
      # it checks out must be host-provided (inventory `host_provided_repos`).
      forgeAccess = true;
      # External hosts this VM reaches with its own key, rendered beside its
      # forge entry. Never a machine of the deployment or the forge host.
      sshHosts = {
        example-build-cache = {
          hostname = "192.0.2.40";
          user = "cache";
          extraOptions.HostKeyAlias = "example-build-cache";
        };
      };
    };
  };

  privacyVMs = {
    privacy-1 = { username = "privacy"; };
  };

  # A service VM has no operator account; its identity's username is root.
  serviceVMs = {
    forge = { };
  };

  sshHosts = {
    # The hypervisor reaches a VM as that VM's login user with its own host
    # key, the one the VM authorizes; the forge key is the VM's, not ours.
    allod-dev = {
      hostname = "192.0.2.10";
      user = username;
      identityFile = "~/.ssh/host";
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
    example-backup-vps = {
      hostname = "192.0.2.30";
      user = "backup";
      identityFile = "~/.ssh/host";
    };
    example-offsite-console = {
      hostname = "192.0.2.31";
      user = "storage";
      identityFile = "~/.ssh/host";
      localForwards = [
        { bind = { address = "127.0.0.1"; port = 8443; }; host = { address = "192.0.2.31"; port = 443; }; }
        { bind.port = 5900; host = { address = "192.0.2.31"; port = 5900; }; }
      ];
    };
    example-provider-support = {
      hostname = "192.0.2.32";
      user = "support";
      port = 2222;
      identityFile = "~/.ssh/host";
      extraOptions = { ServerAliveInterval = "30"; };
    };
  };

  externalSshTrustTargets = {
    example-backup-vps = {
      sshHost = "example-backup-vps";
      authorizedKeysPath = "~/.ssh/authorized_keys";
      recovery = "old-key";
    };
    example-offsite-console = {
      sshHost = "example-offsite-console";
      authorizedKeysPath = "~/.ssh/authorized_keys";
      recovery = "provider-console";
    };
    example-provider-support = {
      sshHost = "example-provider-support";
      authorizedKeysPath = "~/.ssh/authorized_keys";
      recovery = "provider-support";
    };
  };
}
