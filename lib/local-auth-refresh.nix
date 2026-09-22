{ lib, isCredentialStoreUrlSource, credentialStoreUrlSourceClause }:
rec {
  localAuthRefreshContract = "nixos-netrc-from-root-git-credentials";
  localAuthRefreshDeployedPath = "/root/.git-credentials";
  
  # What a group declares for local_auth_refresh, or null when it declares
  # nothing.  An explicit `null` is the same as no entries at all, following
  # the `//` in the jq this replaces; `false` is not, because a boolean is not
  # a list and the registry that wrote one meant something this cannot guess.
  localAuthRefreshDeclaration = group:
    if builtins.isAttrs group then group.local_auth_refresh or null else null;
  localAuthRefreshEntries = group:
    let entries = localAuthRefreshDeclaration group;
    in if builtins.isList entries then entries else [];
  
  # The rules allod/nexus' scripts/refresh-local-auth used to apply in jq
  # before installing a root-owned netrc bundle.  They live here so the
  # script consumes a projection this flake has already validated, the way
  # every consumer of lib.rotationRegistry already trusts it to have
  # validated the registry.
  localAuthRefreshDiagnostics = registry:
    let
      isNonEmptyString = value: builtins.isString value && value != "";
      # A registry entry's own field may be missing or the wrong type, and a
      # diagnostic that interpolates it must not abort evaluation instead of
      # reporting the problem.
      display = value: if builtins.isString value then value else "?";
      groupCredentials = group:
        if builtins.isAttrs group && builtins.isList (group.credentials or null)
        then group.credentials
        else [];
      entryDiagnostic = group: entry:
        let
          named = builtins.filter
            (credential:
              builtins.isAttrs credential &&
              (credential.credential or null) == entry.source_credential)
            (groupCredentials group);
          sourceCredential = builtins.head named;
          sourceName = display (entry.source_credential or null);
          targets =
            if builtins.isList (sourceCredential.targets or null)
            then sourceCredential.targets
            else [];
          rootTargets = builtins.filter
            (target:
              builtins.isAttrs target &&
              (target.system or null) == entry.system &&
              (target.deployed_path or null) == localAuthRefreshDeployedPath)
            targets;
        in
          if !(builtins.isAttrs entry) then
            "a local_auth_refresh entry is not an attribute set"
          else if (entry.contract or null) != localAuthRefreshContract then
            "a local_auth_refresh entry has unsupported contract '${display (entry.contract or null)}'"
          else if !(isNonEmptyString (entry.system or null)) then
            "a local_auth_refresh entry has no system"
          else if !(isNonEmptyString (entry.local_username or null)) then
            "a local_auth_refresh entry has no local_username"
          else if !(isNonEmptyString (entry.source_credential or null)) then
            "a local_auth_refresh entry has no source_credential"
          # builtins.match is whole-string, so this is the anchored
          # ^[A-Za-z_][A-Za-z0-9_-]*$ the jq predicate spelled out.
          else if builtins.match "[A-Za-z_][A-Za-z0-9_-]*" entry.local_username == null then
            "local_username '${entry.local_username}' is not a valid user name"
          else if builtins.length named != 1 then
            "source_credential '${sourceName}' names ${toString (builtins.length named)} credentials of this group, not exactly one"
          else if !(isNonEmptyString (sourceCredential.secret_path or null)) then
            "source credential '${sourceName}' has no secret_path"
          else if !(isCredentialStoreUrlSource sourceCredential) then
            "source credential '${sourceName}' ${credentialStoreUrlSourceClause}"
          else if builtins.length rootTargets != 1 then
            "source credential '${sourceName}' has no single target at ${entry.system}:${localAuthRefreshDeployedPath}"
          else null;
      groupDiagnostics = groupAlias: group:
        let entries = localAuthRefreshDeclaration group;
        in
          if entries == null then []
          else if !(builtins.isList entries) then
            [ "${groupAlias}: local_auth_refresh is not an array" ]
          else
            map (diagnostic: "${groupAlias}: ${diagnostic}")
              (builtins.filter (diagnostic: diagnostic != null)
                (map (entryDiagnostic group) entries));
    in
      lib.concatMap (groupAlias: groupDiagnostics groupAlias registry.${groupAlias})
        (builtins.attrNames registry);
  
  # Every group alias is a key, so a consumer selecting an unknown group gets
  # a missing key rather than an empty answer that looks like "nothing to do".
  localAuthRefreshSourcesFor = registry:
    builtins.mapAttrs (_: group:
      let
        credentialFor = alias:
          builtins.head (builtins.filter
            (credential: (credential.credential or null) == alias)
            (group.credentials or []));
      in
        map (entry: {
          inherit (entry) contract system local_username source_credential;
          secret_path = (credentialFor entry.source_credential).secret_path;
        }) (localAuthRefreshEntries group)
    ) registry;
  
  # Exported as a function of a registry beside its applied result, the way
  # mkPiCredentialContract sits beside lib.piCredentials: a downstream fork
  # validates its own registry, so it calls this on that registry instead of
  # copying the field mapping and gating it with the diagnostics itself.
  mkLocalAuthRefreshSources = registry:
    let diagnostics = localAuthRefreshDiagnostics registry;
    in assert lib.assertMsg (diagnostics == [])
      "local-auth-refresh: ${lib.concatStringsSep "; " diagnostics}";
      localAuthRefreshSourcesFor registry;
}
