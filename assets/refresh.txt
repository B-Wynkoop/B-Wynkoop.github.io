#!/usr/bin/env bash
##!/bin/bash

############## Bash Script For Updating Debian Linux ###############
####################################################################
# bin/bash - Runs Only If Located In Specified Path		           #
# usr/bin/env bash - Any Bash In User Path (Respects Custom Paths) #
# && Allows Run Text To Only Display Printf If The Command Runs    #
# sha256sum update.sh > update.sh.sha256			               #
####################################################################

# Checking Integrity of File Before Updating
sha256sum -c update.sh.sha256 &&
printf '\e[36mHash Verified\e[0m\n'

# Updates Package List & Prints Run Text In Green
sudo apt update &&
printf '\e[32m^^Updates^^\e[0m\n'

# Installs Available Package Updates From The List & Prints Run Text In Green
sudo apt upgrade -y &&
printf '\e[32m^^Upgrades^^\e[0m\n'

# Updates Available Snap Packages & Prints Run Text In Green
sudo snap refresh &&
printf '\e[32m^^Snap-Updates^^\e[0m\n'

# Updates Available System & User FlatPak Packages & Prints Run Text In Green
sudo flatpak update --system -y && flatpak update --user -y &&
printf '\e[32m^^Flatpak-Updates^^\e[0m\n'

# Removes Unused Packages and Configurations & Prints Run Text In Green
sudo apt autoremove --purge &&
printf '\e[32m^^Auto-Remove^^\e[0m\n'

# Cleans Old System Packages & Prints Run Text In Green
sudo apt autoclean &&
printf '\e[32m^^Auto-Clean^^\e[0m\n'

# Purple Message of Script Completion
printf '\e[35m[-------------------------------Script Complete--------------------------------]\e[0m\n'

##################################
# Printf > Echo			         #
# Printf = Versatile & Control   #
# Echo = Bash & Control		     #
#        #########################
#Bwynkoop#
##########
