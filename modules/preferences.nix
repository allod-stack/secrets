{ pkgs, ... }:

{
  programs.git.settings.core.editor = "nvim";

  programs.bash = {
    enable = true;
    shellAliases = {
      claude = "mkdir -p ~/work && cd ~/work && command claude";
      codex = "mkdir -p ~/work && cd ~/work && command codex";
    };
    sessionVariables = {
      GIT_TERMINAL_PROMPT = "1";
    };
    initExtra = ''
      unset SSH_ASKPASS
    '';
  };

  programs.neovim = {
    enable = true;
    defaultEditor = true;
    viAlias = true;
    vimAlias = true;
  };

  home.stateVersion = "25.11";
}
