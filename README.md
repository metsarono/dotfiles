# metsarono's dotfiles

## Installation

### Configure Keyboard
```sudo dpkg-reconfigure keyboard-configuration```

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
```sudo apt install vim zsh ranger rxvt-unicode```
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
```zplug install```

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
