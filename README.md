# metsarono's dotfiles

## Installation

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

### Installing vim and zsh
#### Arch
```sudo pacman -S vim zsh```
#### Debian
```sudo apt install vim zsh```
#### MacOS
```homebrew install vim zsh```

### Updating fonts
```fc-cache -f $fond_dir```

### Installing Rxvt-Unicode
#### Arch
```sudo pacman -S rxvt-unicode```
#### Debian
```sudo apt install rxvt-unicode```

#### Load .Xresources
```xrdb ~/.Xresources```

