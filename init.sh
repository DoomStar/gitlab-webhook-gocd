#! /bin/sh
### BEGIN INIT INFO
# Provides:          githookevent
# Required-Start:    $remote_fs $syslog $network
# Required-Stop:     $remote_fs $syslog $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Script to start Autodeploy Git
# Description:       Autodeploy script for Gitlab
### END INIT INFO

# Author: JA Nache <nache.nache@gmail.com>

NAME=githookevent
PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="GitAutodeploy"
DAEMON=/opt/Git_Hook_Event/GitHookEvent.py
DAEMON_UID=nobody
DAEMON_GID=nobody
RUNDIR=/var/run/$NAME
PIDFILE=/var/run/githookevent/githookevent.pid
PWD=/opt/Git_Hook_Event/
OPTIONS="--daemon-mode"
SCRIPTNAME=/etc/init.d/$NAME

# Exit if the package is not installed
[ -x $DAEMON ] || exit 0

. /etc/init.d/functions


# Source networking configuration.
. /etc/sysconfig/network

# Check that networking is up.
[ "$NETWORKING" = "no" ] && exit 0

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME || ENABLE_GITHOOKEVENT=yes



#
# Function that starts the daemon/service
#
do_start()
{
        # Return
        #   0 if daemon has been started
        #   1 if daemon was already running
        #   2 if daemon could not be started

        if [ ! -d $RUNDIR ]; then
                mkdir $RUNDIR
                chown $DAEMON_UID:$DAEMON_GID $RUNDIR
                chmod g-w,o-rwx $RUNDIR
        fi

        cd $PWD 
        daemon sudo -u $DAEMON_UID $DAEMON $OPTIONS
}

#
# Function that stops the daemon/service
#
do_stop()
{
        kill `cat $PIDFILE`
}

#
# Function that reload the daemon/service
#
do_reload()
{
        do_stop
        do_start
}

case "$1" in
  start)
        do_start
  ;;
  stop)
        do_stop
        ;;
  status)
        kill -0 `cat $PIDFILE` 2>/dev/null && echo $NAME is up and running || echo $NAME is not running

        ;;
  reload|restart)
        do_reload
        ;;
  *)
        echo "Usage: $SCRIPTNAME {start|stop|status|restart|force-reload}" >&2
        exit 3
        ;;
esac

:
