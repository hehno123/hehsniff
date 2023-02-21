#!/bin/bash

g++ hehmitm/*.c -lpcap -lpthread -o /usr/local/sbin/hehmitm
g++ hehsniff/*.c -lpcap -lpthread -o /usr/local/sbin/hehsniff
