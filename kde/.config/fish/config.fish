# Path to your oh-my-fish.
set fish_path $HOME/.oh-my-fish

# Theme
# set fish_theme robbyrussell

# All built-in plugins can be found at ~/.oh-my-fish/plugins/
# Custom plugins may be added to ~/.oh-my-fish/custom/plugins/
# Enable plugins by adding their name separated by a space to the line below.
set fish_plugins tmux archlinux mc sublime vi-mode

# Path to your custom folder (default path is ~/.oh-my-fish/custom)
#set fish_custom $HOME/dotfiles/oh-my-fish

# Load oh-my-fish configuration.
. $fish_path/oh-my-fish.fish

set -x EDITOR vim

set fish_function_path $fish_function_path "/usr/lib/python3.4/site-packages/powerline/bindings/fish"
powerline-setup

set -gx PATH $PATH /home/tiago/.gem/ruby/2.2.0/bin

set -U fish_greeting ""

if test -f /usr/lib/python3.4/site-packages/powerline/bindings/tmux/powerline.conf
      tmux source "/usr/lib/python3.4/site-packages/powerline/bindings/tmux/powerline.conf"
end

