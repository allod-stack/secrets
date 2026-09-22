{ lib, pkgs, identity }:
  let
    targets = identity.externalSshTrustTargets or {};
    targetNames = builtins.attrNames targets;
    validRecoveries = [ "old-key" "provider-console" "provider-support" ];
    fieldOrNull = target: field:
      if builtins.isAttrs target && builtins.hasAttr field target
      then target.${field}
      else null;
    badShape = builtins.filter (name:
      let target = targets.${name};
      in !(builtins.isAttrs target) ||
         !(builtins.isString (fieldOrNull target "sshHost")) ||
         !(builtins.isString (fieldOrNull target "authorizedKeysPath")) ||
         !(builtins.isString (fieldOrNull target "recovery"))
    ) targetNames;
    wellShapedNames = builtins.filter (name: !(builtins.elem name badShape)) targetNames;
    unresolvedSshHosts = builtins.filter (name:
      !(builtins.hasAttr targets.${name}.sshHost identity.sshHosts)
    ) wellShapedNames;
    badRecovery = builtins.filter (name:
      !(builtins.elem targets.${name}.recovery validRecoveries)
    ) wellShapedNames;
  in
  assert lib.assertMsg (badShape == [])
    "external-ssh-trust-targets: invalid schema: ${lib.concatStringsSep ", " badShape}";
  assert lib.assertMsg (unresolvedSshHosts == [])
    "external-ssh-trust-targets: sshHost alias not found in identity.sshHosts: ${lib.concatStringsSep ", " unresolvedSshHosts}";
  assert lib.assertMsg (badRecovery == [])
    "external-ssh-trust-targets: unknown recovery value: ${lib.concatStringsSep ", " badRecovery}";
  pkgs.runCommand "external-ssh-trust-targets-check" {} ''
    echo "external SSH trust target validation passed"
    touch $out
  ''
