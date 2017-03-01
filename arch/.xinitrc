#!/bin/sh
#
# ~/.xinitrc
#
# Executed by startx (run your window manager from here)

if [ -d /etc/X11/xinit/xinitrc.d ]; then
  for f in /etc/X11/xinit/xinitrc.d/*; do
    [ -x "$f" ] && . "$f"
  done
  unset f
fi

# export qt5 app menus
#export QT_QPA_PLATFORMTHEME=appmenu-qt5
#export QT_STYLE_OVERRIDE=qt5ct
#/usr/bin/VBoxClient-all &

#xset b off
setxkbmap -option ctrl:nocaps

# exec gnome-session
exec startgnome
# exec startxfce4
# ...or the Window Manager of your choice

xrandr --setprovideroutputsource modesetting NVIDIA-0
xrandr --auto

export DESKTOP_SESSION=gnome
