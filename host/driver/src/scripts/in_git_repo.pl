#!/usr/bin/perl

use strict;
use warnings;

my ($value, $exit_code);

# Is git installed?
$value = system "which git 1>/dev/null 2>&1";
$exit_code = $value >> 8;
if ($exit_code) {
    # git not found
    exit 1;
}

# Are we in a git repository?
$value = system "git rev-parse --verify HEAD 1>/dev/null 2>&1";
$exit_code = $value >> 8;
if ($exit_code) {
    # git repository not found
    exit 2;
}

# git repository found
exit 0;
