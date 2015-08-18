Config Notes
====

By default panels are locked and browsing through workspaces with the mouse wheel disabled (yes, unity-like). 
To unlock panels simply change the two lines *Frozen=true* to false. 
To revert the mouse wheel behaviour, change *WheelOnLMB=true* to false, under [BE::Desk]. 

Always from the config file, there are preconfigured WmCtrl applets(close, minimize, maximize) that you can add to the array list of top panel: 

*Applets=close,min,max,GlobalMenu,stretch,pager,mediatray,systray,Volume,infocenter,clock,Sessionbutton*

Then, you could also want maximized windows without borders, which takes a small modification to kwinrc:

    kwriteconfig --file kwinrc --group Windows --key BorderlessMaximizedWindows true
    
Reload the WM with the new config:

    qdbus org.kde.kwin /KWin reconfigure
    
If you need a battery indicator, you can add the default applet to the top panel Applets array.

*Applets=GlobalMenu,stretch,pager,battery,mediatray,systray,Volume,infocenter,clock,Sessionbutton*

There are also different logos included in WunderBar/Starter:
logo-bespin, logo-arch, logo-ubuntu, logo-suse, logo-debian, logo-gentoo, logo-chakra
You can change the default one by simply editing the configuration for [starter]:

*Icon=logo-kde*

