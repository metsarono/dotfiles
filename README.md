# metsarono's dotfiles

## Installation

### Configure Keyboard
```bash
# Proxmox
# sudo apt install console-data
sudo dpkg-reconfigure keyboard-configuration
setxkbmap us -variant colemak
```

### Installing git and stow
#### Arch
```sudo pacman -S git stow```
#### Debian
```bash
sudo apt update
sudo apt install git stow
```
#### MacOS
```bash
homebrew update
homebrew install git stow
```

### Clone dotfiles
```bash
git clone --recursive https://github.com/metsarono/dotfiles.git ~/.dotfiles
cd ~/.dotfiles
git submodule update --recursive --remote
```

### Stowing dotfiles
#### Arch
```stow all linux arch```
#### Debian
```stow all linux debian```
#### MacOS
```stow all osx```

### Installing tools
#### Arch
```bash
sudo pacman -S vim zsh ranger rxvt-unicode
chsh -s $(which zsh)
```
#### Debian
```bash
sudo apt install vim zsh ranger rxvt-unicode
chsh -s $(which zsh)
```
#### Ubuntu
```sudo apt-get install software-properties-common
sudo apt-get install python-software-properties
sudo add-apt-repository ppa:neovim-ppa/stable
sudo apt-get update
sudo apt-get install neovim
sudo apt-get install python-dev python-pip python3-dev python3-pip
sudo apt-get install python-dev python-pip python3-dev
sudo apt-get install python3-setuptools
sudo easy_install3 pip
sudo update-alternatives --install /usr/bin/vi vi /usr/bin/nvim 60
sudo update-alternatives --install /usr/bin/vim vim /usr/bin/nvim 60
sudo update-alternatives --install /usr/bin/editor editor /usr/bin/nvim 60
```

#### MacOS
```homebrew install vim zsh ranger```

### Updating fonts
```fc-cache -f $fond_dir```

#### Load .Xresources
```xrdb ~/.Xresources```

### Install Powerline
#### Debian
```bash
wget https://bootstrap.pypa.io/get-pip.py
sudo python get-pip.py
sudo pip install powerline-status
```

#### Install ZPlug ZSH Plugins
```bash
export ZPLUG_HOME=~/.dotfiles/all/.zplug
git clone https://github.com/zplug/zplug $ZPLUG_HOME
zsh
zplug install
chsh -s /bin/zsh
sudo reboot now
```

#### Copy XFCE4 Terminal Colorschemes
```sudo \cp ~/.colors/base16-xfce4-terminal/colorschemes/*.theme /usr/share/xfce4/terminal/colorschemes```

## Compile and Install Synergy
```bash
sudo apt install cmake make g++ xorg-dev libqt4-dev libcurl4-openssl-dev libavahi-compat-libdnssd-dev libssl-dev libx11-dev fakeroot lintian
git clone https://github.com/symless/synergy.git
cd synergy
QT_SELECT=4 ./hm.sh conf -g1 
./hm.sh build
./hm.sh package deb
sudo dpkg -i ./bin/synergy-master-stable-ec56ac4-Linux-x86_64.deb
synergy &
```

## Windows installation using Chocolatey
 0.a Install with cmd.exe
Run the following command:
```bat
@powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
Install with PowerShell.exe
```

0.b With PowerShell, there is an additional step. You must ensure Get-ExecutionPolicy is not Restricted. We suggest using Bypass to bypass the policy to get things installed or AllSigned for quite a bit more security.

Run Get-ExecutionPolicy. If it returns Restricted, then run Set-ExecutionPolicy AllSigned or Set-ExecutionPolicy Bypass.
Now run the following command:
```Powershell
# Don't forget to ensure ExecutionPolicy above
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```
1. Install using [Chocolatey](https://chocolatey.org/) with `choco install keepass-keepasshttp`
 2. Restart KeePass if it is currently running to load the plugin
