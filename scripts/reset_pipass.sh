#!/bin/bash
sudo rm -rf /pipass/users/*
sudo echo -n "" > /pipass/users.conf
sudo /home/pi/R502-fingerprint/examples/example_delete /dev/ttyS0
