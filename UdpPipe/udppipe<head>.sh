# sample start/stop script for head (commands are start/stop/restart)
# copy to head host and rename it to udppipe.sh
# pid file is by default /tmp/udppipe.pid
# log file is by default /tmp/udppipe.log
export PYTHONPATH=.
python eu/liebrand/udppipe/__init__.py $1 -H