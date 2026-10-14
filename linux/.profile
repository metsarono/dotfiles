# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.

# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022

# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
	. "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi

# set PATH so it includes user's private bin if it exists
if [ "${DOTCORTEX_SANCTUARY_GUEST:-0}" != 1 ] && [ -d "$HOME/.cargo/bin" ] ; then
    PATH="$HOME/.cargo/bin:$PATH"
fi

# DXC compiler
if [ -d "$HOME/dxc-artifacts/bin" ] ; then
    PATH="$HOME/dxc-artifacts/bin:$PATH"
fi

# npm global prefix (package-npm.org): codex, claude and the other npm CLIs.
# Agent sessions started from a plain sh login (the tmux seats) read only this
# file, so without this line they cannot see codex on Kikin.
if [ -d "$HOME/.npm-global/bin" ] ; then
    PATH="$HOME/.npm-global/bin:$PATH"
fi

export aquaria_data_path=~/.config/aquaria
export qt_qpa_platformtheme=gtk2
export MOZ_X11_EGL=1
if [ "${DOTCORTEX_SANCTUARY_GUEST:-0}" != 1 ]; then
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
fi
