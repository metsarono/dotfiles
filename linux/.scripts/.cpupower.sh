#!/bin/bash

# Tested on Ubuntu 12.04 (Precise Pangolin) 64 bit.
# Should work on all versions with Unity.

# System Requirements: A processor that supports frequency scaling.

# Dependencies: cpufrequtils - Can be installed from software center.
#               zenity - preinstalled on Ubuntu, not on Lubuntu.

# Copy this to a file in your home directory.
# Name the file "Freq.sh"
# Make it executable with the command: chmod +x Freq.sh

# Available options on my machine:
#   conservative
#   ondemand
#   userspace
#   powersave
#   performance
#
# Yours may be different. Run this command to check, make changes if necessary.
#
# cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors

# I have a quad core processor with hyperthreading, so I have eight threads running.
# Change the scaling governor for all of them (--cpu 0 - 7)
# You will need to add/delete lines to equal the number of threads you have running.
# Run System Monitor and look at the Resources tab to see how many threads are running.
# System Monitor starts counting at one, you will need to start from zero.

# Run the program from the terminal with the command: gksudo ./Freq.sh

# Check to make sure it is working with this command:
#
#   cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

# To create a launcher:
#
# install alacarte with the command: sudo apt-get install alacarte
#
# Run alacarte, click New Item
#
# Type: Application
# Name: Freq
# Command: gksudo /home/YOUR_USER_NAME/Freq.sh
# Commant: Whatever you want to say.
#
# I left the springboard icon, you can click on the icon to change it.
#
# Click Okay
#
# This will create a file named Freq.desktop in /home/YOUR_USER_NAME/.local/share/applications.
# It can be found in the dash.
# It will have an entirly different name if you open a terminal
# and look for it from the command line. This is normal.



GOV=`zenity --title="Freq" --text="Set Frequency Scaling Governor" --height=300 --width=300 \
--list --column="Available Settings:" "Conservative" "Ondemand" "Userspace" "Powersave" "Performance"`

if [ "$GOV" = "Performance" ]; then
   cpupower frequency-set -g performance
fi

if [ "$GOV" = "Conservative" ]; then
    cpupower frequency-set -g conservative
fi

if [ "$GOV" = "Powersave" ]; then
    cpupower frequency-set -g powersave
fi

if [ "$GOV" = "Userspace" ]; then
   cpupower frequency-set -g userspace
fi
