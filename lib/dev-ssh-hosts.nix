# Projection of a dev VM's own external SSH aliases.
#
# `devVMs.<vm>.sshHosts` declares the few external hosts that VM reaches with
# its own key, in the same entry shape as `identity.sshHosts`. The framework
# renders those aliases beside the VM's forge entry, so the projection must
# refuse anything that could capture or replace that entry: the forge host
# itself, any machine of the deployment, and any alias that is not one literal
# host token. OpenSSH matches `Host` patterns case-insensitively and treats a
# space as a pattern separator, so both comparisons are made on that basis
# rather than on Nix string equality.
{ lib }:
let
  # One literal host token: no space (two patterns), no glob character, and no
  # room for a smuggled `Host ` header inside the alias.
  aliasPattern = "^[A-Za-z0-9][A-Za-z0-9._-]*$";

  isLiteralToken = alias:
    builtins.isString alias && builtins.match aliasPattern alias != null;

  hasStringField = entry: field:
    builtins.hasAttr field entry && builtins.isString entry.${field};

  # Names a dev VM may not alias: every machine of the deployment, the
  # hypervisor, and the forge host. VM-to-VM aliases stay on the hypervisor's
  # address book; the forge entry is rendered by the framework.
  reservedNames = identity:
    builtins.attrNames identity.devVMs
    ++ builtins.attrNames identity.privacyVMs
    ++ [ identity.hostname identity.forgeHost ];

  # `vm` is the machine's `devVMs` record, `machineName` its roster name.
  # A record without `sshHosts` projects to `{ }`, so a fork that predates the
  # field composes unchanged.
  project = { identity, machineName, vm }:
    let
      entries = vm.sshHosts or { };
      reservedLower = map lib.toLower (reservedNames identity);

      problemFor = alias:
        let entry = entries.${alias};
        in
        if !(isLiteralToken alias)
        then [ "alias \"${alias}\" is not one literal host token matching ${aliasPattern}; a space or a glob character renders a pattern that can capture another host" ]
        else if builtins.elem (lib.toLower alias) reservedLower
        then [ "alias \"${alias}\" names a machine of the deployment or the forge host (matched case-insensitively, as OpenSSH matches Host patterns)" ]
        else if !(builtins.isAttrs entry)
        then [ "alias \"${alias}\" is not an attribute set" ]
        else if !(hasStringField entry "hostname")
        then [ "alias \"${alias}\" has no string hostname" ]
        else [];

      problems = builtins.concatMap problemFor (builtins.attrNames entries);

      projected = builtins.mapAttrs (_alias: entry: {
        identityFile = "~/.ssh/${vm.sshKeyName}";
        identitiesOnly = true;
      } // entry) entries;
    in
    if problems != []
    then throw "dev-ssh-hosts: ${machineName}: ${builtins.head problems}"
    else projected;
in
{
  inherit reservedNames project;
}
