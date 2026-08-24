{
  registry,
  machineHostKeys,
  nexusPublicKeys,
}:
let
  schema = import ./pi-credential-schema.nix { inherit registry; };
  checkedRegistry = schema.checkedRegistry;
  unique = builtins.foldl'
    (acc: value: if builtins.elem value acc then acc else acc ++ [ value ])
    [];

  entryNames = schema.credentialIds;

  targetNames = unique (builtins.concatLists (map schema.targetsFor entryNames));
  machineNames = builtins.attrNames machineHostKeys;

  missingMachineKeys = builtins.filter
    (name: !(builtins.hasAttr name machineHostKeys))
    targetNames;

  presentMachineNames = builtins.filter
    (name: builtins.hasAttr name machineHostKeys)
    machineNames;

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
  validNexusPublicKeys = builtins.isList nexusPublicKeys
    && nexusPublicKeys != []
    && builtins.all (key: builtins.isString key && key != "") nexusPublicKeys
    && builtins.length nexusPublicKeys == builtins.length (unique nexusPublicKeys);
  allRecipientKeys = nexusPublicKeys
    ++ builtins.concatLists (map recipientsFor presentMachineNames);
  duplicateRecipientKeys = builtins.length allRecipientKeys
    != builtins.length (unique allRecipientKeys);
in
assert builtins.seq checkedRegistry true;
assert missingMachineKeys == [];
assert badMachineKeys == [];
assert validNexusPublicKeys;
assert !duplicateRecipientKeys;
builtins.listToAttrs (builtins.concatLists (map
  (credential:
    let
      # Every named token of a credential shares one recipient set: the
      # ciphertexts differ only in which bearer they carry.
      publicKeys = nexusPublicKeys ++ builtins.concatLists
        (map recipientsFor checkedRegistry.${credential}.targets);
    in map
      (token: {
        name = "secrets/pi-credentials/${credential}/${token}.age";
        value = { inherit publicKeys; };
      })
      checkedRegistry.${credential}.tokens)
  entryNames))
