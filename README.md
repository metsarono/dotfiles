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
```sudo pacman -S vim zsh ranger rxvt-unicode```
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
pip install powerline-status

