# agenix evaluates secrets.nix with no flake inputs: builtins only, no lib.
{
  registry,
  machineHostKeys,
  hypervisorPublicKeys,
}:
let
  unique = builtins.foldl'
    (acc: value: if builtins.elem value acc then acc else acc ++ [ value ])
    [];

  credentials = builtins.concatLists
    (map (group: group.credentials) (builtins.attrValues registry));

  credentialName = credential:
    if builtins.isString (credential.credential or null) then credential.credential
    else if builtins.isString (credential.secret_path or null) then credential.secret_path
    else "?";

  # A "nixos-host" target is the hypervisor, which hypervisorPublicKeys covers.
  guestSystems = credential: unique (builtins.concatMap
    (target: if (target.kind or null) == "nixos-host" then [] else [ target.system ])
    credential.targets);

  recipientsFor = system:
    let keys = machineHostKeys.${system};
    in [ keys.active ] ++ (if keys.staged == null then [] else [ keys.staged ]);

  missingMachineKeys = builtins.concatMap
    (credential: map
      (system: "credential '${credentialName credential}' targets machine '${system}', which has no entry in machine-host-keys.json; a hypervisor target needs kind \"nixos-host\"")
      (builtins.filter (system: !(builtins.hasAttr system machineHostKeys)) (guestSystems credential)))
    credentials;

  secretPaths = map (credential: credential.secret_path) credentials;
  duplicateSecretPaths = unique (builtins.filter
    (path: builtins.length (builtins.filter (other: other == path) secretPaths) > 1)
    secretPaths);

  validHypervisorPublicKeys = builtins.isList hypervisorPublicKeys
    && hypervisorPublicKeys != []
    && builtins.all (key: builtins.isString key && key != "") hypervisorPublicKeys
    && builtins.length hypervisorPublicKeys == builtins.length (unique hypervisorPublicKeys);

  diagnostics =
    (if validHypervisorPublicKeys then []
     else [ "hypervisorPublicKeys must be a non-empty list of distinct non-empty strings" ])
    ++ missingMachineKeys
    ++ map (path: "more than one registry credential names the secret_path '${path}'") duplicateSecretPaths;
in
{
  inherit diagnostics;
  recipients =
    if diagnostics != [] then
      throw "registry-recipients: ${builtins.concatStringsSep "; " diagnostics}"
    else
      builtins.listToAttrs (map
        (credential: {
          name = credential.secret_path;
          value.publicKeys = hypervisorPublicKeys
            ++ builtins.concatLists (map recipientsFor (guestSystems credential));
        })
        credentials);
}
