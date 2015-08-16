# bumblebeed
# Autogenerated from man page /usr/share/man/man1/bumblebeed.1.gz
# using Deroffing man parser
complete -c bumblebeed -s D -l daemon --description 'run daemonized (backgrounded).  Implies --use-syslog.'
complete -c bumblebeed -s x -l xconf --description 'xorg. conf file to use.'
complete -c bumblebeed -l xconfdir --description 'xorg. conf. d directory to use.'
complete -c bumblebeed -s g -l group --description 'allow GROUP to communicate with the daemon.'
complete -c bumblebeed -l driver --description 'the driver to use for the nvidia card.'
complete -c bumblebeed -s m -l module-path --description 'ModulePath to use for Xorg (only useful for nvidia).'
complete -c bumblebeed -s k -l driver-module --description 'Name of kernel module to be loaded if different… [See Man Page]'
complete -c bumblebeed -l pm-method --description 'method to use for disabling the discrete video … [See Man Page]'
complete -c bumblebeed -s q -l quiet -l silent --description 'supresses all logging messages.'
complete -c bumblebeed -s v -l verbose --description 'increase the verbosity level of log messages.'
complete -c bumblebeed -l debug --description 'show all logging messsages by setting the verbo… [See Man Page]'
complete -c bumblebeed -s C -l config --description 'retrieve settings for Bumblebee from FILE.'
complete -c bumblebeed -s d -l display --description 'start the Bumblebee X server on VDISPLAY.'
complete -c bumblebeed -s l -l ldpath --description 'libraries like nvidia_drv.'
complete -c bumblebeed -s s -l socket --description 'use FILENAME for communication with the daemon.'
complete -c bumblebeed -s h -l help --description 'display this help and exit.'
complete -c bumblebeed -l version --description 'output version information and exit REPORTING B… [See Man Page]'
