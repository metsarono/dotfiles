#!/bin/sh
# info.sh
# Output general information with formatted background colors in bar-aint-recursive format
# TODO: If Verbose_bar has a value in bar/profile, will output more information

# default location for a battery capacity
export BATC=/sys/class/power_supply/BAT0/capacity

clock() {
    date '+%H:%M'
}

battery() {
    BATS=/sys/class/power_supply/BAT0/status
    #Check if there is a battery on the cyrrent computer we are on.
    if [ -f $BATC ]; then
        test "`cat $BATS`" = "Charging" && echo -n '+' || echo -n '-'
        sed -n p $BATC
    else
        #yeah
        echo "+0"
    fi
}

volume() {
    amixer get Master | sed -n 's/^.*\[\([0-9]\+%\).*$/\1/p'
}

network() {
    read lo int1 int2 <<< `ip link | sed -n 's/^[0-9]: \(.*\):.*$/\1/p'`
    if iwconfig $int1 >/dev/null 2>&1; then
        wifi=$int1
        eth0=$int2
    else
        wifi=$int2
        eth0=$int1
    fi
    ip link show $eth0 | grep 'state UP' >/dev/null && int=$eth0 ||int=$wifi

    #int=eth0

    ping -c 1 8.8.8.8 >/dev/null 2>&1 &&
        echo "✔" || echo "✖"
}


pBGS1="%{B$pS1}"  # bg shade 1
pBGS2="%{B$pS2}"  # bg shade 2

pFG="%{F$pFG}"    # reset fg color

# The {e} and {n} bar commands are specific to this slant fork: http://github.com/neeasade/bar
delim="${pBGS1}%{E5}    ${pFG}"
delim2="${pBGS2}%{E5}    ${pFG}"

while :; do
    buf="S$delim2"
    if [ -f $BATC ]; then
        buf="${buf} $(battery) $delim "
    else
        buf="${buf} ⇅ $(network) $delim "
    fi
    buf="${buf} vol $(volume) $delim2 "
    buf="${buf} $(clock)"

    echo "$buf"
    sleep 1 # The HUD will be updated every second
done

