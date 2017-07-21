#!/bin/bash

TIME=`date +%a`
FILENAME=backup-$TIME.tar.gz
SRCDIR=/home/joe.suber/phones
DESDIR=/home/joe.suber/backup
tar -cpzf $DESDIR/$FILENAME $SRCDIR
