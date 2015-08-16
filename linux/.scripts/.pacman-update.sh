#!/bin/bash

#This script is used to do a full update.  It will:
# 1).  Update the pacman mirrorlist to be headed by the most recently
#      updated, then fastest (best options on top of list)
# 2).  Then it will display the new mirrorlist for you to verify.
#      -Hit "Y" to proceed with update.
# 3).  It will execute pacman -Syu to find packages to update.
#      -Hit "Y" to proceed with update.
# 4).  It will give you a choice to proceed to clean the cache to 3 versions
#      of each program.  (better than pacman -Scc)
#      -Hit "Y" to clean out the cache.
# 5).  Script exits.


#****************************************************************************************************
#  1). Update mirrors to a combo of fastest and most recently sync'ed including only U.S.:

echo " "
echo "*************************************************************"
echo "* Querying German mirror servers for speed and timeliness...  *"
echo "*************************************************************"

sudo /usr/bin/reflector --verbose -c "Germany" -l 50 -p http --sort rate --save /etc/pacman.d/mirrorlist

wait

#****************************************************************************************************
# 2). Display new mirrorlist:

echo " "
echo "*************************************************************"
echo "* Please check the new mirrorlist for accuracy or problems: *"
echo "*************************************************************"
echo " "

#leafpad /etc/pacman.d/mirrorlist
cat /etc/pacman.d/mirrorlist

wait

#****************************************************************************************************
# 3). Procede with pacman update if desired:

echo " "
read -p "Continue full system upgrade (Y/n)?" CONT


# Set to "Y" as default if user simply hit [ENTER]:
 
if [[ $CONT == "" ]]; then
   myvar="y"
else
   myvar=$CONT
fi

#Check entry:

case $myvar in
   [yY])
   echo " "
   echo "*************************************************************"
   echo "* Performing system upgrade                                 *"
   echo "*************************************************************"
   echo " "
   sudo pacman -Syu
   ;;
   [nN])
   echo " "
   echo "*************************************************************"
   echo "* Exiting full_update                                       *"
   echo "*************************************************************"
   echo " "
   exit	
;;
esac

wait

#****************************************************************************************************
# 4). Procede with cache cleaning if desired:

echo " "
echo "*************************************************************"
echo "* Cache Cleaning: *"
echo "*************************************************************"
echo " "

echo " "
read -p "Perform cache clean (Y/n)?" CONT


# Set to "Y" as default if user simply hit [ENTER]:
 
if [[ $CONT == "" ]]; then
   myvar="y"
else
   myvar=$CONT
fi

#Check entry and clean:
#   -n is preview mode, no files deleted
#   -v is verbose mode, shows deleted packges
#    # is number of versions of each package to keep. ( current + previous )

case $myvar in
   [yY])
   # determine packages to be cleaned and display them:
   echo " "
   echo "*************************************************************"
   echo "* Finding packages to be cleaned...                         *"
   echo "*************************************************************"
   echo " "
   sudo pkgcacheclean -n -v 3
   ;;
   [nN])
   echo " "
   echo "*************************************************************"
   echo "* Exiting full_update                                       *"
   echo "*************************************************************"
   echo " "
   exit	
;;
esac

# debug exit:
# exit

# perform the cleaning
