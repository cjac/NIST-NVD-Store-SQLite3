#!/bin/bash

SQLITE_DIR=$CWD
rm *.db
cd /usr/src/git/f5/NIST-NVD
perl Makefile.PL && \
make && \
cd /usr/src/git/f5/NIST-NVD-Store-SQLite3
perl Makefile.PL && \
make && \
perl -I $PWD/blib/lib\
     -I /usr/src/git/f5/NIST-NVD/blib/lib\
 /usr/src/git/f5/NIST-NVD-Store-SQLite3/bin/convert-nvdcve\
 --nvd /usr/src/git/f5/NIST-NVD-Store-SQLite3/t/data/nvdcve-2.0-test.xml\
 --cwe /usr/src/git/f5/NIST-NVD-Store-SQLite3/t/data/cwec_v2.1.xml\
 --store SQLite3
