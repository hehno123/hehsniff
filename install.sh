#!/bin/bash

g++ hehmitm/*.c -lpcap -lpthread -o /usr/local/bin/hehmitm
g++ hehsniff/*.c -lpcap -lpthread -o /usr/local/bin/hehsniff
