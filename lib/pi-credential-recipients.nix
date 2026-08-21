{
  registry,
  machineHostKeys,
  nexusName,
}:
let
  unique = builtins.foldl'
    (acc: value: if builtins.elem value acc then acc else acc ++ [ value ])
    [];

  entryNames =
    if builtins.isAttrs registry
    then builtins.attrNames registry
    else [];

  entriesWithInvalidTargets = builtins.filter
    (name:
      let entry = registry.${name};
      in !(builtins.isAttrs entry)
         || !(entry ? targets)
         || !(builtins.isList entry.targets)
         || !(builtins.all builtins.isString entry.targets))
    entryNames;

  targetNames = unique (builtins.concatLists (map
    (name:
      let entry = registry.${name};
      in if builtins.isAttrs entry
            && entry ? targets
            && builtins.isList entry.targets
            && builtins.all builtins.isString entry.targets
         then entry.targets
         else [])
    entryNames));

  recipientMachineNames = unique ([ nexusName ] ++ targetNames);
  missingMachineKeys = builtins.filter
    (name: !(builtins.hasAttr name machineHostKeys))
    recipientMachineNames;

  presentMachineNames = builtins.filter
    (name: builtins.hasAttr name machineHostKeys)
    recipientMachineNames;

  badMachineKeys = builtins.filter
    (name:
      let keys = machineHostKeys.${name};
      in !(builtins.isAttrs keys)
         || !(keys ? active)
         || !(builtins.isString keys.active)
         || keys.active == ""
         || !(keys ? staged)
         || !(keys.staged == null
              || (builtins.isString keys.staged && keys.staged != "")))
    presentMachineNames;

  recipientsFor = name:
    let keys = machineHostKeys.${name};
    in [ keys.active ] ++ (if keys.staged == null then [] else [ keys.staged ]);
in
assert builtins.isAttrs registry;
assert entriesWithInvalidTargets == [];
assert missingMachineKeys == [];
assert badMachineKeys == [];
builtins.listToAttrs (map
  (credential: {
    name = "secrets/pi-credentials/${credential}.age";
    value.publicKeys = unique (builtins.concatLists
      (map recipientsFor (unique ([ nexusName ] ++ registry.${credential}.targets))));
  })
  entryNames)
