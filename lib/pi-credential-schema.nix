{ registry }:
let
  idPattern = "^[a-z0-9][a-z0-9-]*$";
  expectedFields = [ "providers" "rotationStrategy" "targets" ];
  validStrategies = [ "overlap" "in-place" ];
  unique = builtins.foldl'
    (acc: value: if builtins.elem value acc then acc else acc ++ [ value ])
    [];
  duplicates = values:
    builtins.filter
      (value: builtins.length (builtins.filter (other: other == value) values) > 1)
      (unique values);
  validId = value:
    builtins.isString value && builtins.match idPattern value != null;

  registryIsAttrs = builtins.isAttrs registry;
  safeRegistry = if registryIsAttrs then registry else {};
  credentialIds = builtins.attrNames safeRegistry;
  entryIsAttrs = id: builtins.isAttrs safeRegistry.${id};
  field = id: name: fallback:
    if entryIsAttrs id && builtins.hasAttr name safeRegistry.${id}
    then safeRegistry.${id}.${name}
    else fallback;
  targetsFor = id:
    let value = field id "targets" [];
    in if builtins.isList value then value else [];
  providersFor = id:
    let value = field id "providers" [];
    in if builtins.isList value then value else [];

  badCredentialIds = builtins.filter (id: !(validId id)) credentialIds;
  nonAttrEntries = builtins.filter (id: !(entryIsAttrs id)) credentialIds;
  badFields = builtins.filter
    (id:
      entryIsAttrs id
      && builtins.sort builtins.lessThan (builtins.attrNames safeRegistry.${id})
         != expectedFields)
    credentialIds;
  badTargets = builtins.filter
    (id:
      let values = field id "targets" null;
      in !(builtins.isList values)
         || values == []
         || !(builtins.all validId values)
         || builtins.length values != builtins.length (unique values))
    credentialIds;
  badProviders = builtins.filter
    (id:
      let values = field id "providers" null;
      in !(builtins.isList values)
         || values == []
         || !(builtins.all validId values)
         || builtins.length values != builtins.length (unique values))
    credentialIds;
  badStrategies = builtins.filter
    (id:
      let value = field id "rotationStrategy" null;
      in !(builtins.isString value) || !(builtins.elem value validStrategies))
    credentialIds;

  allProviders = builtins.concatLists (map providersFor credentialIds);
  duplicateProviders = duplicates allProviders;

  errors =
    (if registryIsAttrs then [] else [ "registry must be an object" ])
    ++ (if badCredentialIds == [] then [] else [ "invalid credential IDs: ${builtins.concatStringsSep ", " badCredentialIds}" ])
    ++ (if nonAttrEntries == [] then [] else [ "entries must be objects: ${builtins.concatStringsSep ", " nonAttrEntries}" ])
    ++ (if badFields == [] then [] else [ "entries have missing or unknown fields: ${builtins.concatStringsSep ", " badFields}" ])
    ++ (if badTargets == [] then [] else [ "targets must be non-empty unique ID lists: ${builtins.concatStringsSep ", " badTargets}" ])
    ++ (if badProviders == [] then [] else [ "providers must be non-empty unique ID lists: ${builtins.concatStringsSep ", " badProviders}" ])
    ++ (if badStrategies == [] then [] else [ "invalid rotationStrategy: ${builtins.concatStringsSep ", " badStrategies}" ]);

  checkedRegistry =
    if errors != []
    then throw "pi-credential-registry: ${builtins.concatStringsSep "; " errors}"
    else if duplicateProviders != []
    then throw "pi-credential-registry: providers referenced by multiple credentials: ${builtins.concatStringsSep ", " duplicateProviders}"
    else safeRegistry;
in
{
  inherit
    allProviders
    checkedRegistry
    credentialIds
    duplicateProviders
    errors
    providersFor
    safeRegistry
    targetsFor
    unique
    validId
    ;
}
