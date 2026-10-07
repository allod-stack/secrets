{ registry }:
let
  idPattern = "^[a-z0-9][a-z0-9-]*$";
  tokenPattern = "^[a-z][a-z0-9-]{0,62}$";
  expectedFields = [ "defaultToken" "providers" "targets" "tokens" ];
  unique = builtins.foldl'
    (acc: value: if builtins.elem value acc then acc else acc ++ [ value ])
    [];
  duplicates = values:
    builtins.filter
      (value: builtins.length (builtins.filter (other: other == value) values) > 1)
      (unique values);
  validId = value:
    builtins.isString value && builtins.match idPattern value != null;
  validTokenName = value:
    builtins.isString value && builtins.match tokenPattern value != null && value != "none";
  # A plain string target keeps today's shared-token meaning. An object
  # target names, by token name, the one ciphertext that machine alone
  # should receive; the name is resolved through the credential's own
  # `tokens` list, mirroring how `defaultToken` already resolves.
  validTargetEntry = entry:
    validId entry
    || (builtins.isAttrs entry
        && builtins.sort builtins.lessThan (builtins.attrNames entry) == [ "name" "token" ]
        && validId entry.name
        && validTokenName entry.token);
  targetNameOf = entry:
    if builtins.isString entry then entry
    else if builtins.isAttrs entry && entry ? name then entry.name
    else null;
  targetTokenOf = entry:
    if builtins.isString entry then null else entry.token or null;
  claimedTokensFor = id:
    builtins.concatMap
      (entry: if builtins.isAttrs entry && entry ? token then [ entry.token ] else [])
      (targetsFor id);

  registryIsAttrs = builtins.isAttrs registry;
  safeRegistry = if registryIsAttrs then registry else {};
  credentialIds = builtins.attrNames safeRegistry;
  entryIsAttrs = id: builtins.isAttrs safeRegistry.${id};
  hasField = id: name: entryIsAttrs id && builtins.hasAttr name safeRegistry.${id};
  field = id: name: fallback:
    if hasField id name
    then safeRegistry.${id}.${name}
    else fallback;
  targetsFor = id:
    let value = field id "targets" [];
    in if builtins.isList value then value else [];
  targetNamesFor = id: map targetNameOf (targetsFor id);
  providersFor = id:
    let value = field id "providers" [];
    in if builtins.isList value then value else [];
  tokensFor = id:
    let value = field id "tokens" [];
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
      let
        values = field id "targets" null;
        names = if builtins.isList values then map targetNameOf values else [];
      in !(builtins.isList values)
         || values == []
         || !(builtins.all validTargetEntry values)
         || builtins.length names != builtins.length (unique names))
    credentialIds;
  badTargetTokenRefs = builtins.filter
    (id:
      let
        values = field id "targets" [];
        tokens = tokensFor id;
      in builtins.isList values
         && builtins.any
              (entry: builtins.isAttrs entry && entry ? token && !(builtins.elem entry.token tokens))
              values)
    credentialIds;
  badDuplicateTokenClaims = builtins.filter
    (id:
      let claims = claimedTokensFor id;
      in builtins.length claims != builtins.length (unique claims))
    credentialIds;
  badProviders = builtins.filter
    (id:
      let values = field id "providers" null;
      in !(builtins.isList values)
         || values == []
         || !(builtins.all validId values)
         || builtins.length values != builtins.length (unique values))
    credentialIds;
  badTokens = builtins.filter
    (id:
      let values = field id "tokens" null;
      in !(builtins.isList values)
         || values == []
         || !(builtins.all validTokenName values)
         || builtins.length values != builtins.length (unique values))
    credentialIds;
  badDefaultTokens = builtins.filter
    (id:
      !(hasField id "defaultToken")
      || (let value = safeRegistry.${id}.defaultToken;
          in value != null
             && !(builtins.isString value
                  && builtins.elem value (tokensFor id))))
    credentialIds;
  badDefaultTokenClaimedByOverride = builtins.filter
    (id:
      hasField id "defaultToken"
      && safeRegistry.${id}.defaultToken != null
      && builtins.isString safeRegistry.${id}.defaultToken
      && builtins.any builtins.isString (targetsFor id)
      && builtins.elem safeRegistry.${id}.defaultToken (claimedTokensFor id))
    credentialIds;

  allProviders = builtins.concatLists (map providersFor credentialIds);
  # Uniqueness is per (provider, target): a provider may be split across
  # credentials as long as their targets stay disjoint.
  providerTargetPairs = builtins.concatLists (map
    (id: builtins.concatLists (map
      (provider: map
        (entry: "${provider}@${targetNameOf entry}")
        (targetsFor id))
      (providersFor id)))
    credentialIds);
  duplicateProviderTargets = duplicates providerTargetPairs;

  errors =
    (if registryIsAttrs then [] else [ "registry must be an object" ])
    ++ (if badCredentialIds == [] then [] else [ "invalid credential IDs: ${builtins.concatStringsSep ", " badCredentialIds}" ])
    ++ (if nonAttrEntries == [] then [] else [ "entries must be objects: ${builtins.concatStringsSep ", " nonAttrEntries}" ])
    ++ (if badFields == [] then [] else [ "entries have missing or unknown fields: ${builtins.concatStringsSep ", " badFields}" ])
    ++ (if badTargets == [] then [] else [ "targets must be non-empty unique ID lists: ${builtins.concatStringsSep ", " badTargets}" ])
    ++ (if badTargetTokenRefs == [] then [] else [ "target token overrides must name one listed token: ${builtins.concatStringsSep ", " badTargetTokenRefs}" ])
    ++ (if badDuplicateTokenClaims == [] then [] else [ "a token override must be claimed by at most one target: ${builtins.concatStringsSep ", " badDuplicateTokenClaims}" ])
    ++ (if badProviders == [] then [] else [ "providers must be non-empty unique ID lists: ${builtins.concatStringsSep ", " badProviders}" ])
    ++ (if badTokens == [] then [] else [ "tokens must be non-empty unique token-name lists: ${builtins.concatStringsSep ", " badTokens}" ])
    ++ (if badDefaultTokens == [] then [] else [ "defaultToken must be null or one listed token: ${builtins.concatStringsSep ", " badDefaultTokens}" ])
    ++ (if badDefaultTokenClaimedByOverride == [] then [] else [ "defaultToken must not name a token claimed by a target override while a plain target exists: ${builtins.concatStringsSep ", " badDefaultTokenClaimedByOverride}" ]);

  checkedRegistry =
    if errors != []
    then throw "pi-credential-registry: ${builtins.concatStringsSep "; " errors}"
    else if duplicateProviderTargets != []
    then throw "pi-credential-registry: providers referenced by multiple credentials for the same target: ${builtins.concatStringsSep ", " duplicateProviderTargets}"
    else safeRegistry;
in
{
  inherit
    allProviders
    checkedRegistry
    credentialIds
    duplicateProviderTargets
    errors
    providersFor
    safeRegistry
    targetNameOf
    targetNamesFor
    targetTokenOf
    targetsFor
    tokensFor
    unique
    validId
    validTargetEntry
    validTokenName
    ;
}
