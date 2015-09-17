" Updated: Thu 20 Aug 00:50:21 2015
" Revision: 235
" Author: tiago@Tiagos-MBP.fritz.box

" http://www.askapache.com/linux/fast-vimrc.html

" For all key mappings like ', .' to reload vimrc
let maplocalleader=','




" BACKUPS, SWAPFILES, VIEWDIR, TMPDIR  "{{{1
" ====================================================================================

" SET RUNTIMEPATH {{{4
if isdirectory(expand("$HOME/.vim"))
   if isdirectory(expand("$HOME/.vim/colors"))
          if filereadable(expand("$HOME/colors/flatlandia.vim"))
                 let $VIMRUNTIME=expand("$HOME/.vim")
                 set runtimepath=$VIMRUNTIME
          endif
   endif
endif

"echomsg &runtimepath
"echomsg expand("$VIMRUNTIME")


" IF BKDIR IS NOT SET OR EMPTY, SET {{{4
if $BKDIR == ""
   let $BKDIR=expand("$HOME/.bk")
   if !isdirectory(expand("$BKDIR"))
          call mkdir(expand("$BKDIR"), "p", 0700)
   endif
endif


" MAKE DIRS IF mkdir exists {{{4
if exists("*mkdir")
   let &viewdir=expand("$BKDIR") . "/.vim/viewdir"
   if !isdirectory(expand(&viewdir))|call mkdir(expand(&viewdir), "p", 0700)|endif
   if !isdirectory(expand("$BKDIR/tmp/.vim"))|call mkdir(expand("$BKDIR/tmp/.vim"), "p", 0700)|endif
   if !isdirectory(expand("$BKDIR/.vim/backups"))|call mkdir(expand("$BKDIR/.vim/backups"), "p", 0700)|endif
   if !isdirectory(expand("$BKDIR/.vim/undos"))|call mkdir(expand("$BKDIR/.vim/undos"), "p", 0700)|endif
endif


" SETTINGS USING NEW DIRS {{{4
let &dir=expand("$BKDIR") . "/.vim"
let &backupdir=expand("$BKDIR") . "/.vim/backups"
"let &undodir=expand("$BKDIR") . "/.vim/undos"
"set undofile
"let &verbosefile=expand("$BKDIR") . "/.vim/vim-messages.


" VIMINFO {{{4
" COMMENTED OUT {{{5
"  "       Maximum number of lines saved for each register
"  %       When included, save and restore the buffer lis
"  '       Maximum number of previously edited files for which the marks are remembere
"  /       Maximum number of items in the search pattern history to be saved
"  :        Maximum number of items in the command-line history
"  <       Maximum number of lines saved for each register.
"   @       Maximum number of items in the input-line history
"  h       Disable the effect of 'hlsearch' when loading the viminfo
"  n       Name of the viminfo file.  The name must immediately follow the 'n'.
"  r       Removable media.  The argument is a string
"  s       Maximum size of an item in Kbyte
" }}}5 COMMENTED OUT

let &viminfo="%203,'200,/800,h,<500,:500,s150,r/tmp,r" . expand("$BKDIR") . "/tmp/.vim,n" . expand("$BKDIR") ."/.vim/.vinfo"
" }}}4 ENDOF VIMINFO

" --------------------------------------------------- }}}1 ENDOF BACKUPS, SWAPFILES, VIEWDIR, TMPDIR

" DYNAMIC SETTINGS / COLORS / TERMINAL {{{1
" ====================================================================================
"echomsg &t_Co
"echomsg &term

if &t_Co > 2

   if &term =~ "256"

          set bg=dark t_Co=256 vb
          let &t_vb="\<Esc>[?5h\<Esc>[?5l"      " flash screen for visual bell

          if filereadable(expand("$VIMRUNTIME/colors/flatlandia.vim"))
                 colorscheme flatlandia
          elseif filereadable(expand("$HOME/.vim/colors/flatlandia.vim"))
                 colorscheme flatlandia
          else
                 colorscheme default
          endif

   else
          " things like cfdisk, crontab -e, visudo, vless, etc.
          set term=screen-16color
          set t_Co=16

   endif

   filetype indent plugin on
   syntax on

endif
" -------------------------------------------------------------- }}}1 ENDOF DYNAMIC SETTINGS / COLORS / TERMINAL





" CUSTOM FUNCTIONS "{{{1
" ====================================================================================
if !exists("AskApacheLoaded")
   let AskApacheLoaded=1

   " http://dotfiles.org/~samba/.vimrc
   " www.gregsexton.org/2011/03/improving-the-text-displayed-in-a-fold/

   " DECLARATIONS {{{2
   " ================================================================================
   " FUNCTION - ManualLastMod {{{4
   function! ManualLastMod()
          "echomsg 'LastMod RUNNING'

          for [l,v,d] in [[2,'Updated'," "], [3,'Revision',1], [4,'Author'," "],[5,'','']]
                 call setline(l, printf('%s%s: %s', printf(&commentstring, ' '), v,d))
          endfor


          call LastMod()
   endfunction


   " FUNCTION - LastMod {{{4
   " Warning, this is controlled by an autocmd triggered when closing the file that updates the file (in a great way)
   function! LastMod()
          "echomsg 'LastMod RUNNING'
          if line("$") > 20|let l = 20|else|let l = line("$")|endif
          exe "silent! 1,".l."g/ Revision:[ \\d]\\+/s/\\d\\+/\\=submatch(0) + 1/e 1"
          exe "silent! 1,".l."g/ Author:/s/Author:.*/" . printf('Author: %s@%s', expand("$LOGNAME"), hostname()) . "/e 1"
          exe "silent! 1,".l."g/ Updated:/s/Updated:.*/" . printf('Updated: %s', strftime("%c")) . "/e 1"
   endfunction



   " FUNCTION - LastModAAZZZ {{{4
   " AA_UPDATED='2/24/12-00:56:00'
   function! LastModAAZZZ()
          exe "silent! 1,60 /^AA_VERSION=/s/\\d\\+$/\\=submatch(0) + 1/e 1"
          exe "silent! 1,60 /^AA_UPDATED=/s/AA_UPDATED=.*/AA_UPDATED='" . strftime("%c") . "'/e 1"

          exe "silent! 1,60 /^ISC_S_VERSION=/s/\\d\\+$/\\=submatch(0) + 1/e 1"
          exe "silent! 1,60 /^ISC_S_UPDATED=/s/ISC_S_UPDATED=.*/ISC_S_UPDATED='" . strftime("%c") . "'/e 1"
          "echomsg 'LastModAAZZZ RUNNING'
   endfunction


   " FUNCTION - AppendModeline {{{4
   " Append modeline after last line in buffer.  Use substitute() instead of printf() to handle '%%s' modeline
   function! AppendModeline()
          let l:modeline = printf(" vim: set ft=%s ts=%d sw=%d tw=%d :", &filetype, &tabstop, &shiftwidth, &textwidth)
          let l:modeline = substitute(&commentstring, "%s", l:modeline, "")
          call append(line("$"), l:modeline)
   endfunction


   " FUNCTION - StripTrailingWhitespace {{{4
   " automatically remove trailing whitespace before write
   function! StripTrailingWhitespace()
          normal mZ
          %s/\s\+$//e
          if line("'Z") != line(".")|echo "Stripped whitespace\n"|endif
          normal `Z
   endfunction


   " FUNCTION - MyTabL {{{3
   function! MyTabL()
          let s = ''|let t = tabpagenr()|let i = 2
          while i <= tabpagenr('$')
                 let bl = tabpagebuflist(i)|let wn = tabpagewinnr(i)
                 let s .= '%' . i . 'T'. (i == t ? '%2*' : '%2*') . '%*' . (i == t ? ' %#TabLineSel# ' : '%#TabLine#')
                 let file = (i == t ? fnamemodify(bufname(bl[wn - 2]), ':p') : fnamemodify(bufname(bl[wn - 1]), ':t') )
                 if file == ''
                        let file = '[No Name]'
                 endif
                 let s .= i.' '. file .(i == t ? ' ' : '')|let i += 2
          endwhile
          let s .= '%T%#TabLineFill#%=' . (tabpagenr('$') > 2 ? '%999XX' : 'X')
          return s
   endfunction


   " FUNCTION - DiffWithSaved {{{3
   " Diff with saved version of the file
   function! s:DiffWithSaved()
          let filetype=&ft
          diffthis
          vnew | r # | normal! 2Gdd
          diffthis
          exe "setlocal bt=nofile bh=wipe nobl noswf ro ft=" . filetype
   endfunction
   com! DiffSaved call s:DiffWithSaved()


   " FUNCTION - ShowWhitespace() {{{3
   function! ShowWhitespace(flags)
          let bad = ''
          let pat = []
          for c in split(a:flags, '\zs')
                 if c == 'e'
                        call add(pat, '\s\+$')
                 elseif c == 'i'
                        call add(pat, '^\t*\zs \+')
                 elseif c == 's'
                        call add(pat, ' \+\ze\t')
                 elseif c == 't'
                        call add(pat, '[^\t]\zs\t\+')
                 else
                        let bad .= c
                 endif
          endfor

          if len(pat) > 1
                 let s = join(pat, '\|')
                 exec 'syntax match ExtraWhitespace "'.s.'" containedin=ALL'
          else
                 syntax clear ExtraWhitespace
          endif

          if len(bad) > 1|echo 'ShowWhitespace ignored: '.bad|endif
   endfunction



   " FUNCTION - ToggleShowWhitespace {{{3
   " I use this all the time, it's mapped to , ts
   function! ToggleShowWhitespace()
          if !exists('b:ws_show')|let b:ws_show = 1|endif
          if !exists('b:ws_flags')|let b:ws_flags = 'est'|endif
          let b:ws_show = !b:ws_show
          if b:ws_show|call ShowWhitespace(b:ws_flags)|else|call ShowWhitespace('')|endif
   endfunction


   " FUNCTION - ValidVimCheck {{{3
   function! ValidVimCheck()
          if has('quickfix') && &buftype =~ 'nofile'
                 "echoerr "Buffer is marked as not a file"
                 return 0
          endif

          if empty(glob(expand('%:p')))
                 "echoerr "File does not exist on disk"
                 return 0
          endif

          if len($TMP) && expand('%:p:h') == $TMP
                 "echoerr "Also in temp dir"
                 return 0
          endif
          return 1
   endfunction


   " ------------------------------------------------------------- }}}2 ENDOF DECLARATIONS

endif

" ------------------------------------------------------------------------------------ }}}1 ENDOF CUSTOM FUNCTIONS




" OPTIONS "{{{1
" ====================================================================================


" DYNAMIC OPTIONS {{{2
" ================================================================================
" DISABLE MOUSE NO GOOEYS {{{3
"if has('mouse')|set mouse=|endif
" ENABME MOUSE SCROLL
set mouse=a

" SET TITLESTRING {{{3
if has('title')|set titlestring=%t%(\ [%R%M]%)|endif

" SET TABLINE {{{3
if exists("*s:MyTabL")|set tabline=%!MyTabL()|endif

let g:vimsyn_folding='af'

"DISABLE FILETYPE-SPECIFIC MAPS {{{3
let no_plugin_maps=1

"}}}2 DYNAMIC OPTIONS



" BACKUP, FILE OPTIONS {{{2
" ================================================================================
set backup                        " Make a backup before overwriting a file.
set backupcopy=auto " When writing a file and a backup is made.  comma separated list of words. - value: yes,no,auto

set swapfile
set swapsync=fsync

"}}}2 BACKUP, FILE OPTIONS

" BASIC SETTINGS "{{{2
" ================================================================================
set nocompatible                " vim, not vi.. must be first, because it changes other options as a side effect
set modeline

set statusline=%M%h%y\ %t\ %F\ %p%%\ %l/%L\ %=[%{&ff},%{&ft}]\ [a=\%03.3b]\ [h=\%02.2B]\ [%l,%v]
set title titlelen=150 titlestring=%(\ %M%)%(\ (%{expand(\"%:p:h\")})%)%(\ %a%)\ -\ %{v:servername}

"set tags=tags;/                        " search recursively up for tags

set ttyfast                             " we have a fast terminal
set scrolljump=5          " when scrolling up down, show at least 5 lines
"set ttyscroll=999        " make vim redraw screen instead of scrolling when there are more than 3 lines to be scrolled

"set tw=500                             " default textwidth is a max of 5

set undolevels=1000             " 50 undos - saved in undodir
set updatecount=250             " switch every 250 chars, save swap

set whichwrap+=b,s,<,>,h,l,[,]                  " backspaces and cursor keys wrap to
"set wildignore+=*.o,*~,.lo,*.exe,*.bak " ignore object files
"set wildmenu                                                   " menu has tab completion
"set wildmode=longest:full                              " *wild* mode
set nowrap

set autoindent smartindent              " auto/smart indent

set autoread                                    " watch for file changes

set backspace=indent,eol,start  " backspace over all kinds of things

set cmdheight=1                                 " command line two lines high
set complete=.,w,b,u,U,t,i,d    " do lots of scanning on tab completion
set cursorline                                  " show the cursor line
"set enc=utf-8 fenc=utf-8               " utf-8

set history=3000                                " keep 3000 lines of command line history

set keywordprg=TERM=mostlike\ man\ -s\ -Pless

set laststatus=2

"set lazyredraw                                 " don't redraw when don't have to
set linebreak                                   " wrap at 'breakat' instead of last char
set magic                                               " Enable the "magic"

set maxmem=25123        " 24 MB -  max mem in Kbyte to use for one buffer.  Max is 2000000

set noautowrite                                 " don't automagically write on :next

set noexpandtab                                 " no expand tabs to spaces"
set noruler                                     " show the line number on the bar
set nospell
set nohidden                                    " close the buffer when I close a tab (I use tabs more than buffers)

set noerrorbells visualbell t_vb= " Disable ALL bells

set number                                      " line numbers
":set numberwidth=3								" width of the numbering column

set pastetoggle=<F11>

set scrolloff=3                         " keep at least 3 lines above/below
set shiftwidth=3                        " shift width

set showcmd                                     " Show us the command we're typing
set showfulltag                         " show full completion tags
set showmode                            " show the mode all the time

set sidescroll=2                        " if wrap is off, this is fasster for horizontal scrolling
set sidescrolloff=2                     "keep at least 5 lines left/right

set noguipty

set splitright
set splitbelow

set restorescreen=on " restore screen contents when vim exits -  disable withset t_ti= t_te=

"set sessionoptions=word,blank,buffers,curdir,folds,globals,help,localoptions,resize,sesdir,tabpages,winpos,winsize
set winheight=25
"set winminheight=1      " minimal value for window height
"set winheight=30       " set the minimal window height
set equalalways         " all the windows are automatically sized same
set eadirection=both    " only equalalways for horizontally split windows

set hlsearch

set laststatus=2

set tabstop=4
set softtabstop=4

set shiftwidth=3
set switchbuf=usetab

set commentstring=#%s

set tabpagemax=55
set showtabline=2               " 2 always, 1 only if multiple tabs
set smarttab                    " tab and backspace are smart

set foldmethod=marker
set nofoldenable
"set foldenable
set foldcolumn=0                                " the blank left-most bar left of the numbered lines

set incsearch                                   " incremental search
"set ignorecase                                 " search ignoring case
set sc                                                  " override 'ignorecase' when pattern has upper case characters
set smartcase                                   " Ignore case when searching lowercase

set showmatch                                   " show matching bracket
set diffopt=filler,iwhite               " ignore all whitespace and sync"
set stal=2

set viewoptions=folds,localoptions,cursor

" ------------------------------------------------------------------------------------ }}}1 ENDOF OPTIONS


" PLUGIN SETTINGS {{{1
" ====================================================================================
" Settings for :TOhtml "{{{3
let html_number_lines=1
let html_use_css=1
let use_xhtml=1
" ------------------------------------------------------------------------------------ }}}1 ENDOF PLUGIN SETTINGS


" AUTOCOMMANDS "{{{1
" ====================================================================================
"{
"if !exists(":DiffOrig") | command DiffOrig vert new | set bt=nofile | r # | 0d_ | diffthis | wincmd p | diffthis | endif

" auto load extensions for different file types
if has('autocmd')

   if !exists("autocommands_loaded")

          let autocommands_loaded = 1



          " LASTMOD COMMANDS {{{2
          " ================================================================================
          augroup aazzlastmod
                 autocmd!

                 " INSERT CURRENT DATE AND TIME WHEN WRITING IT {{{3
                 autocmd BufWritePre,FileWritePre *.sh,.htaccess,*.conf,vimrc,.bash*,.*,*.cron ks|call LastMod()|'s

                 " AA_ZZZ LAST MOD {{{3
                 autocmd BufWritePre,FileWritePre zzz_askapache-bash.sh,*.sh ks|call LastModAAZZZ()|'s
          augroup END
          " ------------------------------------------------------------- }}}2 ENDOF LASTMOD COMMANDS


          " AUTOMKVIEW COMMANDS {{{2
          " ================================================================================
                 augroup aazzzmakeviewcheck
                        autocmd!

                        autocmd BufWinLeave * if ValidVimCheck() | mkview! |endif
                        autocmd BufWinEnter * if ValidVimCheck() | silent loadview | endif
                 augroup END
          " ------------------------------------------------------------- }}}2 ENDOF AUTOMKVIEW COMMANDS



          " MISC COMMANDS {{{2
          " ================================================================================

          " SAVE BACKUPFILE AS BACKUPDIR/FILENAME-06-13-1331 {{{3
          autocmd BufWritePre * let &bex = strftime("-%m-%d-%H%M")


          " CLEARMATCHES ON BUFWINLEAVE {{{3
          if exists("*clearmatches")
                 autocmd BufWinLeave *.* call clearmatches()
          endif

          " STRIP TRAILING WHITESPACE {{{3
          if exists("*s:StripTrailingWhitespace")
                 autocmd BufWritePre *.cpp,*.hpp,*.i,*.sh,.htaccess,*.conf :call s:StripTrailingWhitespace()
          endif
          " ------------------------------------------------------------- }}}2 ENDOF MISC COMMANDS





          " FILETYPES {{{2
          " ================================================================================
          " SET VIM SETTINGS FOR AA_ZZZ SCRIPTS {{{3
          autocmd BufRead .bash_profile,.bashrc,.bash_logout setlocal ts=4 sw=3 ft=sh foldmethod=marker tw=500 foldcolumn=7

          " TMUX FILETYPE {{{3
          autocmd BufRead tmux.conf,.tmux.conf,.tmux*,*/tmux-sessions/* setlocal filetype=tmux foldmethod=marker

          " LOGROTATE FILETYPE {{{3
          autocmd BufRead /etc/logrotate.d/*,/etc/logrotate.conf setlocal filetype=logrotate

          " FSTAB FILETYPE {{{3
          autocmd BufRead /etc/fstab,fstab setlocal foldmethod=marker


          " APACHE2 FILETYPE {{{3
          autocmd BufRead /etc/httpd/*.conf,httpd.conf setlocal filetype=apache foldmethod=marker foldcolumn=7 foldlevel=2


          " SH FILETYPES {{{3
          autocmd BufRead *.sh,*.cron,*.bash setlocal filetype=sh


          " SYSLOG-NG FILETYPE {{{3
          autocmd BufRead syslog-ng.conf setlocal filetype=syslog-ng


          " NET-PROFILES FILETYPE {{{3
          autocmd BufRead /etc/network.d/* setlocal filetype=conf


          " XDEFAULTS "{{{3
          autocmd FileType xdefaults setlocal foldmethod=marker foldlevel=2 commentstring=!%s

          " ------------------------------------------------------------- }}}2 ENDOF FILETYPES


          " MAN RUNTIME - TODO REPLACE WITH TMUXES CTRL-M BINDING {{{2
          " Lets you type :Man anymanpage and it will load in vim, color-coded and searchable
          " runtime ftplugin/man.vim

   endif
endif

" ------------------------------------------------------------------------------------ }}}1 ENDOF AUTOCOMMANDS





" MAPS "{{{1
" ====================================================================================

" FUNCTION MAPS {{{2
" ---------------------------------
" APPEND MODELINE {{{3
map <silent> <LocalLeader>ml :call AppendModeline()<CR>


" SHOW WHITESPACE {{{3
nnoremap <LocalLeader>ts :call ToggleShowWhitespace()<CR>


" SUDO A WRITE {{{3
command! W :execute ':silent w !sudo tee % > /dev/null' | :edit!
"cmap w!! %!sudo tee > /dev/null %
" :w !sudo tee > /dev/null %


" SET TABLINE {{{3
" My Personal Fav, inserts last-modified manually on current line when you press <F12> key
if exists("*ManualLastMod")
   map <silent> <F12> :call ManualLastMod()<CR>
endif


" RELOAD VIMRC FILES {{{3
map <LocalLeader>. :mkview<CR>:unlet! AskApacheLoaded autocommands_loaded<CR>:mapclear<CR>:source /etc/vimrc<CR>:loadview<CR>



" SCROLLING MAPS {{{3
map <PageDown> :set scroll=0<CR>:set scroll^=2<CR>:set scroll-=1<CR><C-D>:set scroll=0<CR>
map <PageUp> :set scroll=0<CR>:set scroll^=2<CR>:set scroll-=1<CR><C-U>:set scroll=0<CR>
nnoremap <silent> <PageUp> <C-U><C-U>
vnoremap <silent> <PageUp> <C-U><C-U>
inoremap <silent> <PageUp> <C-\><C-O><C-U><C-\><C-O><C-U>
nnoremap <silent> <PageDown> <C-D><C-D>
vnoremap <silent> <PageDown> <C-D><C-D>
inoremap <silent> <PageDown> <C-\><C-O><C-D><C-\><C-O><C-D>
"}}}3





" KEY MAPS {{{2
" physically map keys to produce different key, type CTRL-V in insert mode followed by any key to see how vim sees it
" ----------------------------------------
imap <ESC>[8~ <End>
map <ESC>[8~ <End>

imap <ESC>[7~ <Home>
map <ESC>[7~ <Home>

imap <ESC>OH <Home>
map <ESC>OH <Home>

imap <ESC>OF <End>
map <ESC>OF <End>


" Basic Maps  {{{2
" ----------------------------------------
" TOGGLE PASTE MODE {{{3
map <LocalLeader>pm :set nonumber! foldcolumn=0<CR>

" REINDENT FILE {{{3
map <LocalLeader>ri G=gg<CR>

" CLEAR SPACES AT END OF LINE {{{3
map <LocalLeader>cs :%s/\s\+$//e<CR>

" Y YANKS FROM CURSOR TO $ {{{3
map <LocalLeader>y "5y$
map <LocalLeader>r "_d$p




map <LocalLeader>dd _d<CR>

" DON'T USE EX MODE, USE Q FOR FORMATTING {{{3
map Q gq
map! ^H ^?

" NEXT SEARCH RESULT {{{3
map <silent> <LocalLeader>cn :cn<CR>

" WRAP? {{{3
map <silent> <LocalLeader>ww :ww

" ERR INSERTION {{{3
"map <silent> <LocalLeader>e <Home>A<C-R>=printf('%s', '_err "$0 $FUNCNAME:$LINENO FAILED WITH ARGS= $*"')<CR><Home><Esc>

" CUSTOM LINES FOR CODING {{{3
map <silent> <LocalLeader>l1 <Home>A<C-R>=printf('%s%s', printf(&commentstring, ' '), repeat('=', 160))<CR><Home><Esc>
map <silent> <LocalLeader>l2 <Home>A<C-R>=printf('%s%s', printf(&commentstring, ' '), repeat('=', 80))<CR><Home><Esc>
map <silent> <LocalLeader>l3 <Home>A<C-R>=printf('%s%s', printf(&commentstring, ' '), repeat('-', 40))<CR><Home><Esc>
map <silent> <LocalLeader>l4 <Home>A<C-R>=printf('%s%s', printf(&commentstring, ' '), repeat('-', 20))<CR><Home><Esc>

" CHANGE DIRECTORY TO THAT OF CURRENT FILE {{{3
nmap <LocalLeader>cd :cd%:p:h<CR>

" CHANGE LOCAL DIRECTORY TO THAT OF CURRENT FILE {{{3
nmap <LocalLeader>lcd :lcd%:p:h<CR>

" TOGGLE WRAPPING {{{3
nmap <LocalLeader>ww :set wrap!<CR>
nmap <LocalLeader>wo :set wrap<CR>



" TABS "{{{2
" ---------------------------------

" CREATE A NEW TAB {{{3
map <LocalLeader>tc :tabnew %<CR>

" LAST TAB {{{3
map <LocalLeader>t<Space> :tablast<CR>

" CLOSE A TAB {{{3
map <LocalLeader>tk :tabclose<CR>

" NEXT TAB {{{3
map <LocalLeader>tn :tabnext<CR>

" PREVIOUS TAB {{{3
map <LocalLeader>tp :tabprev<CR>









" FOLDS  "{{{2
" ---------------------------------
" Fold with paren begin/end matching
nmap F zf%

" When I use ,sf - return to syntax folding with a big foldcolumn
nmap <LocalLeader>sf :set foldcolumn=6 foldmethod=syntax<cr>
"}}}2

" ------------------------------------------------------------------------------------ }}}1 ENDOF MAPS


" HILITE "{{{1
" ====================================================================================
hi NonText cterm=NONE ctermfg=NONE
hi Search cterm=bold ctermbg=99 ctermfg=17
" ------------------------------------------------------------------------------------ }}}1 ENDOF HILITE







" VIM TIPS / HELP / TRICKS   {{{1
" ====================================================================================

" BEST TRICKS {{{2

" TERMCAP HELP {{{3
" :help termcap

" :g/^\s*$/;//-1sort to sort each block of lines in a file.


" VIEW DIFF OF EDITS AGAINST BUFFER VS ORIGINAL FILE {{{3
" :w !colordiff -u % -


" INSERT CURRENT FILENAME {{{3
" :r! echo %

" DELETE TRAILING WHITESPACE {{{3
" :%s/\s\+$//

" Changing Case
" guu                             : lowercase line
" gUU                             : uppercase line
" Vu                              : lowercase line
" VU                              : uppercase line
" g~~                             : flip case line
" vEU                             : Upper Case Word
" vE~                             : Flip Case Word
" ggguG                           : lowercase entire file
" " Titlise Visually Selected Text (map for .vimrc)
" vmap ,c :s/\<\(.\)\(\k*\)\>/\u\1\L\2/g<CR>
" " Title Case A Line Or Selection (better)
" vnoremap <F6> :s/\%V\<\(\w\)\(\w*\)\>/\u\1\L\2/ge<cr> [N]
" " titlise a line
" nmap ,t :s/.*/\L&/<bar>:s/\<./\u&/g<cr>  [N]
" " Uppercase first letter of sentences
" :%s/[.!?]\_s\+\a/\U&\E/g


" :r file " read text from file and insert below current line

" :so $VIMRUNTIME/syntax/hitest.vim       " view highlight options

"}}}2


" HELP HELP {{{3
" ---------------------------------
" :helpg pattern                                          search grep!! ---  JUMP TO OTHER MATCHES WITH: >
" :help holy-grail
" :help all
" :help termcap
"  :help user-toc.txt          Table of contents of the User Manual. >
"  :help :subject              Ex-command "subject", for instance the following: >
"  :help :help                 Help on getting help. >
"  :help CTRL-B                Control key <C-B> in Normal mode. >
"  :help 'subject'             Option 'subject'. >
"  :help EventName             Autocommand event "EventName"
"  :help pattern<Tab>          Find a help tag starting with "pattern".  Repeat <Tab> for others. >
"  :help pattern<Ctrl-D>       See all possible help tag matches "pattern" at once. >
"                 :cn                         next match >
"                 :cprev, :cN                 previous match >
"                 :cfirst, :clast             first or last match >
"                 :copen,  :cclose            open/close the quickfix window; press <Enter> to jump to the item under the cursor



" SET HELP {{{3
" ---------------------------------
" :verbose set opt? - show where opt was set
" set opt!              - invert
" set invopt            - invert
" set opt&              - reset to default
" set all&              - set all to def
" :se[t]                        Show all options that differ from their default value.
" :se[t] all            Show all but terminal options.
" :se[t] termcap                Show all terminal options.  Note that in the GUI the



" TAB HELP   {{{3
" ---------------------------------
" tc    - create a new tab
" td    - close a tab
" tn    - next tab
" tp    - previous tab



" UPPERCASE, LOWERCASE, INDENTS {{{3
" ---------------------------------
" '.    - last modification in file!
" gf  - open file under cursor
" guu - lowercase line
" gUU - uppercase line
" =   - reindent text



" FOLDS {{{3
" ---------------------------------
" F     - create a fold from matching parenthesis
" fm    - (zm)  more folds
" fl  - (zr) less/reduce folds
" fo    - open all folds (zR)
" fc    - close all folds (zM)
" ff  -  (zf)   - create a fold
" fd    - (zd)  - delete fold at cursor
" zF    - create a fold N lines
" zi    - invert foldenable



" KEYSEQS HELP {{{3
" ---------------------------------
" CTRL-I - forward trace of changes
" CTRL-O - backward trace of changes!
" C-W W  - Switch to other split window
" CTRL-U                  - DELETE FROM CURSOR TO START OF LINE
" CTRL-^                  - SWITCH BETWEEN FILES
" CTRL-W-TAB  - CREATE DUPLICATE WINDOW
" CTRL-N                  - Find keyword for word in front of cursor
" CTRL-P                  - Find PREV diddo


" SEARCH / REPLACE {{{3
" ---------------------------------
" :%s/\s\+$//    - delete trailing whitespace
" :%s/a\|b/xxx\0xxx/g             modifies a b      to xxxaxxxbxxx
" :%s/\([abc]\)\([efg]\)/\2\1/g   modifies af fa bg to fa fa gb
" :%s/abcde/abc^Mde/              modifies abcde    to abc, de (two lines)
" :%s/$/\^M/                      modifies abcde    to abcde^M
" :%s/\w\+/\u\0/g                 modifies bla bla  to Bla Bla
" :g!/\S/d                              delete empty lines in file


"  COMMANDS {{{3
" ---------------------------------
" :runtime! plugin/**/*.vim  - load plugins
" :so $VIMRUNTIME/syntax/hitest.vim       " view highlight options
" :so $VIMRUNTIME/syntax/colortest.vim

" :!!date - insert date
" :%!sort -u  - only show uniq (and sort)

" :r file " read text from file and insert below current line
" :v/./.,/./-1join  - join empty lines

" :e! return to unmodified file
" :tabm n  - move tab to pos n
" :jumps
" :history
" :reg   -  list registers

" delete empty lines
" global /^ *$/ delete


" ------------------------------------------------------------------------------------ }}}1 ENDOF VIM TIPS / HELP / TRICKS

" Line number values
highlight LineNr term=bold cterm=NONE ctermfg=DarkGrey ctermbg=NONE gui=NONE guifg=DarkGrey guibg=NONE

set laststatus=2 " Always display the statusline in all windows
set showtabline=2 " Always display the tabline, even if there is only one tab
set noshowmode " Hide the default mode text (e.g. -- INSERT -- below the statusline)

" Syntax auto complete
filetype plugin on
set omnifunc=syntaxcomplete#Complete

" SuperTab Plugin
let g:SuperTabDefaultCompletionType = "<C-X><C-O>"
"let g:SuperTabDefaultCompletionType = "context"

execute pathogen#infect()

" Compatible with ranger 1.4.2 through 1.6.*
"
" Add ranger as a file chooser in vim
"
" If you add this code to the .vimrc, ranger can be started using the command
" ":RangerChooser" or the keybinding "<leader>r".  Once you select one or more
" files, press enter and ranger will quit again and vim will open the selected
" files.

function! RangeChooser()
    let temp = tempname()
    " The option "--choosefiles" was added in ranger 1.5.1. Use the next line
    " with ranger 1.4.2 through 1.5.0 instead.
    "exec 'silent !ranger --choosefile=' . shellescape(temp)
    exec 'silent !ranger --choosefiles=' . shellescape(temp)
    if !filereadable(temp)
        redraw!
        " Nothing to read.
        return
    endif
    let names = readfile(temp)
    if empty(names)
        redraw!
        " Nothing to open.
        return
    endif
    " Edit the first item.
    exec 'edit ' . fnameescape(names[0])
    " Add any remaning items to the arg list/buffer list.
    for name in names[1:]
        exec 'argadd ' . fnameescape(name)
    endfor
    redraw!
endfunction
command! -bar RangerChooser call RangeChooser()
nnoremap <leader>r :<C-U>RangerChooser<CR>

"let $PYTHONPATH='/$HOME/.local/lib/python2.7/site-packages'

"python from powerline.vim import setup as powerline_setup
"python powerline_setup()
"python del powerline_setup

" tab navigation like firefox
nnoremap <F7>	   gT
nnoremap <F8>    gt
nnoremap <C-t>     :tabnew<CR>
inoremap <C-t>     <Esc>:tabnew<CR>
nnoremap <C-w>     :tabclose<CR>

" Allow saving of files as sudo when I forgot to start vim using sudo.
cmap w!! w !sudo tee > /dev/null %

" With the default leader key, just press \s to save any changes to the current file.
noremap <Leader>s :update<CR>

let g:airline_powerline_fonts = 1
"let g:airline_theme = "flatlandia"
