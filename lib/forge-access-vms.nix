# Dev VMs holding a forge identity; none means no agent token ciphertext.
{ identity }:
builtins.filter (vm: identity.devVMs.${vm}.forgeAccess or true)
  (builtins.attrNames identity.devVMs)
