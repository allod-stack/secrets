# Projection of a dev VM's own external SSH aliases.
#
# `devVMs.<vm>.sshHosts` declares the few external hosts that VM reaches with
# its own key, in the same entry shape as `identity.sshHosts`. The framework
# renders those aliases beside the VM's forge entry, so the projection must
# refuse anything that could capture or replace that entry: the forge host
# itself, any machine of the deployment, and any alias that is not one literal
# host token. OpenSSH matches `Host` patterns case-insensitively and treats a
# space as a pattern separator, so both comparisons are made on that basis
# rather than on Nix string equality, and two aliases that differ only by case
# are refused as the one alias OpenSSH sees.
#
# An entry's own fields can open a block just as an alias can, so the
# projection also refuses the `extraOptions` key `header` (the block's own
# `Host`/`Match` line), a `__`-prefixed or non-bare-directive `extraOptions`
# key, and a newline or carriage return inside any string anywhere in the
# entry — each would render a second block that can capture the forge host.
{ lib }:
let
  # One literal host token: no space (two patterns), no glob character, and no
  # room for a smuggled `Host ` header inside the alias.
  aliasPattern = "^[A-Za-z0-9][A-Za-z0-9._-]*$";

  # A bare ssh_config directive name, the only shape `extraOptions` may carry.
  directivePattern = "^[A-Za-z][A-Za-z0-9]*$";

  isLiteralToken = alias:
    builtins.isString alias && builtins.match aliasPattern alias != null;

  hasStringField = entry: field:
    builtins.hasAttr field entry && builtins.isString entry.${field};

  opensBlock = value: lib.hasInfix "\n" value || lib.hasInfix "\r" value;

  # Every string in an entry lands in the rendered block, so walk attrsets and
  # lists to their leaves rather than checking the top-level fields alone.
  stringProblems = path: value:
    if builtins.isString value then
      lib.optional (opensBlock value)
        "field ${path} contains a newline or carriage return, which would open a second ssh_config block"
    else if builtins.isList value then
      builtins.concatLists (lib.imap0 (index: item: stringProblems "${path}[${toString index}]" item) value)
    else if builtins.isAttrs value then
      builtins.concatMap (name: stringProblems "${path}.${name}" value.${name}) (builtins.attrNames value)
    else [];

  entryStringProblems = entry:
    builtins.concatMap (name: stringProblems name entry.${name}) (builtins.attrNames entry);

  # `extraOptions` is flattened into the block, and Home Manager's submodule
  # declares `header` as the block's own `Host`/`Match` line: an entry that
  # sets it chooses which hosts the block matches.
  extraOptionProblems = entry:
    let options = entry.extraOptions or { };
    in
    if !(builtins.isAttrs options)
    then [ "extraOptions is not an attribute set" ]
    else builtins.concatMap (key:
      if key == "header"
      then [ "extraOptions key \"header\" is the block's own Host/Match line; setting it would render a block that can capture another host" ]
      else if lib.hasPrefix "__" key
      then [ "extraOptions key \"${key}\" starts with __, which the module system reserves" ]
      else if builtins.match directivePattern key == null
      then [ "extraOptions key \"${key}\" is not a bare ssh_config directive name matching ${directivePattern}" ]
      else []
    ) (builtins.attrNames options);

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
      aliases = builtins.attrNames entries;
      reservedLower = map lib.toLower (reservedNames identity);

      # Two aliases that lower-case to the same string are one alias to
      # OpenSSH; whichever block it reads first wins, silently.
      loweredAliases = map lib.toLower aliases;
      clashingLower = lib.unique (builtins.filter
        (lowered: builtins.length (builtins.filter (other: other == lowered) loweredAliases) > 1)
        loweredAliases);
      duplicateProblems = map (lowered:
        let clashing = builtins.filter (alias: lib.toLower alias == lowered) aliases;
        in "aliases ${lib.concatMapStringsSep " and " (alias: "\"${alias}\"") clashing} differ only by case, so OpenSSH matches the same host against both"
      ) clashingLower;

      problemFor = alias:
        let
          entry = entries.${alias};
          detail = message: "alias \"${alias}\" ${message}";
        in
        if !(isLiteralToken alias)
        then [ (detail "is not one literal host token matching ${aliasPattern}; a space or a glob character renders a pattern that can capture another host") ]
        else if builtins.elem (lib.toLower alias) reservedLower
        then [ (detail "names a machine of the deployment or the forge host (matched case-insensitively, as OpenSSH matches Host patterns)") ]
        else if !(builtins.isAttrs entry)
        then [ (detail "is not an attribute set") ]
        else if !(hasStringField entry "hostname")
        then [ (detail "has no string hostname") ]
        else map detail (extraOptionProblems entry ++ entryStringProblems entry);

      problems = duplicateProblems ++ builtins.concatMap problemFor aliases;

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
