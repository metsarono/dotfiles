# Path to your oh-my-fish.
set fish_path $HOME/.oh-my-fish

# Path to your custom folder (default path is ~/.oh-my-fish/custom)
# set fish_custom $HOME/dotfiles/oh-my-fish

# Load oh-my-fish configuration.
. $fish_path/oh-my-fish.fish

# Custom plugins and themes may be added to ~/.oh-my-fish/custom
# Plugins and themes can be found at https://github.com/oh-my-fish/
Theme 'bobthefish'
Plugin 'theme'
Plugin 'tmux'
Plugin 'mc'
Plugin 'sublime'
Plugin 'vi-mode'

set -gx TERM xterm-256color
set -gx EDITOR vim
set -gx PATH $PATH /home/tiago/.gem/ruby/2.2.0/bin
set -U fish_greeting ""

#set fish_function_path $fish_function_path "$HOME/.local/lib/python2.7/site-#packages/powerline/bindings/fish"
#powerline-setup

if test -f $HOME/.local/lib/python2.7/site-packages/powerline/bindings/tmux/powerline.conf
      tmux source "$HOME/.local/lib/python2.7/site-packages/powerline/bindings/tmux/powerline.conf"
else if test -f /usr/lib/python3.4/site-packages/powerline/bindings/tmux/powerline.conf
      tmux source "/usr/lib/python3.4/site-packages/powerline/bindings/tmux/powerline.conf"
else if test -f /usr/local/lib/python2.7/site-packages/powerline/bindings/tmux/powerline.conf
      tmux source "/usr/local/lib/python2.7/site-packages/powerline/bindings/tmux/powerline.conf"
end
if test -f source /Users/tiago/.iterm2_shell_integration.fish
    source /Users/tiago/.iterm2_shell_integration.fish
end