{
  registry,
  machineHostKeys,
  hypervisorPublicKeys,
}:
let
  schema = import ./pi-credential-schema.nix { inherit registry; };
  checkedRegistry = schema.checkedRegistry;
  inherit (schema) targetTokenOf;
  unique = builtins.foldl'
    (acc: value: if builtins.elem value acc then acc else acc ++ [ value ])
    [];

  entryNames = schema.credentialIds;

  targetNames = unique (builtins.concatLists (map schema.targetNamesFor entryNames));
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
  validHypervisorPublicKeys = builtins.isList hypervisorPublicKeys
    && hypervisorPublicKeys != []
    && builtins.all (key: builtins.isString key && key != "") hypervisorPublicKeys
    && builtins.length hypervisorPublicKeys == builtins.length (unique hypervisorPublicKeys);
  allRecipientKeys = hypervisorPublicKeys
    ++ builtins.concatLists (map recipientsFor presentMachineNames);
  duplicateRecipientKeys = builtins.length allRecipientKeys
    != builtins.length (unique allRecipientKeys);

  # A token claimed by an object target's override is that target's alone:
  # the plain-string (shared) targets of the same credential do not get it,
  # or the override would buy no isolation. An unclaimed token keeps
  # today's union of every plain-string target.
  claimingNames = credential: token:
    builtins.concatMap
      (entry: if !(builtins.isString entry) && targetTokenOf entry == token then [ entry.name ] else [])
      checkedRegistry.${credential}.targets;
  namesForToken = credential: token:
    let claiming = claimingNames credential token;
    in if claiming != []
       then claiming
       else builtins.concatMap
         (entry: if builtins.isString entry then [ entry ] else [])
         checkedRegistry.${credential}.targets;
in
assert builtins.seq checkedRegistry true;
assert missingMachineKeys == [];
assert badMachineKeys == [];
assert validHypervisorPublicKeys;
assert !duplicateRecipientKeys;
builtins.listToAttrs (builtins.concatLists (map
  (credential:
    map
      (token:
        let
          publicKeys = hypervisorPublicKeys ++ builtins.concatLists
            (map recipientsFor (namesForToken credential token));
        in {
          name = "secrets/pi-credentials/${credential}/${token}.age";
          value = { inherit publicKeys; };
        })
      checkedRegistry.${credential}.tokens)
  entryNames))
