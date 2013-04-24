#!/bin/sh
set -ex

cc -o libpreload-cgrulesengd-open.so -shared -fPIC preload-cgrulesengd-open.c -ldl -lpcre
