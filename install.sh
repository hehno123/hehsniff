#!/bin/bash

g++ hehmitm/*.c -lpcap -lpthread -o /usr/sbin/hehmitm
g++ hehsniff/*.c -lpcap -lpthread -o /usr/sbin/hehsniff
