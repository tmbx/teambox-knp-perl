#!/usr/bin/perl

use Test::TAP::HTMLMatrix;
use Test::TAP::Model::Visual;

$t = Test::TAP::Model::Visual->new_with_tests(glob("*.t"));
$t->run_tests;
my $v = Test::TAP::HTMLMatrix->new($t);

print $v->html;
