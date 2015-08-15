#!/bin/sh
if [ ! -d "/Volume/Elementary" ]; then
   mkdir -p /Volumes/{Elementary,Arch,Ubuntu}
   if [ -e "/dev/disk1s8" ]; then
	  sudo /usr/local/bin/fuse-ext2 /dev/disk1s8 /Volumes/Elementary -o rw+ -o allow_other
	  sudo /usr/local/bin/fuse-ext2 /dev/disk1s9 /Volumes/Arch -o rw+ -o allow_other
	  sudo /usr/local/bin/fuse-ext2 /dev/disk1s10 /Volumes/Ubuntu -o rw+ -o allow_other
   elif [ -e "/dev/disk0s8" ]; then
	  sudo /usr/local/bin/fuse-ext2 /dev/disk0s8 /Volumes/Elementary -o rw+ -o allow_other
	  sudo /usr/local/bin/fuse-ext2 /dev/disk0s9 /Volumes/Arch -o rw+ -o allow_other
	  sudo /usr/local/bin/fuse-ext2 /dev/disk0s10 /Volumes/Ubuntu -o rw+ -o allow_other
   fi
fi
