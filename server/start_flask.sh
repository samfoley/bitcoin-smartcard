#!/bin/bash
. venv/bin/activate
python bitcoin.py > flask.log &
FLASK_PID=$!
echo $FLASK_PID > flask.pid
