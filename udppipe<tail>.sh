# sample start script
# copy to head host and rename it to udppipe.sh
# pid file is by default /tmp/udppipe.pid
# log file is by default /tmp/udppipe.log

# if setup as a service change the working directory
cd /home/<udppipe user>/...

export PYTHONPATH=.
source ./venv/bin/activate
python eu/liebrand/udppipe/Pipe.py $1 -T