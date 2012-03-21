#!/usr/bin/perl

use Test::Harness::Verbose;

@tests =glob("*.t");
runtests(@tests);
