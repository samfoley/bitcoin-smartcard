#!/bin/bash
FLASK_PID=`cat flask.pid`
kill $FLASK_PID `ps h --ppid $FLASK_PID -o pid`
