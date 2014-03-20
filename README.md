vzp_cisco-config-evaluator
==========================

Just a python script to parse cisco configs and output pertinent data for non-cisco people to analyze and understand.

Usage:

python.exe vzp_cisco-evaluator.py <config filename>

The program will ask you for the config filename if you didn't provide it.

The program will then parse the config and ask you for a filename to output the html report to.

It will create tables that show you local users, enabled interfaces with IP addresses and ACLs, static routes in the config, routing protocols and their configuration.

Needs a lot of work, but is useful for doing quick analysis of the config without having to read, memorize, and assimilate the whole thing in your head.
