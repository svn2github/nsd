#!/usr/bin/perl

# strip all non essential stuff from
# the dig output. Should be something left
# that can be used for comparisons.

while(<>) {
	if ( /^;; ([A-Z]+) SECTION:/i ) {
		print "\n$1 SECTION:\n";
		next;
	}
	if ( /^;[a-z0-9]+/i ) {
		# this is the question
		s/^;//;
		print;
		next;
	}

	if ( /^;/ or /^$/ ) { next; }

	# quick hack the not entirely correct fixes the TCR
	s/ TYPE46 / RRSIG /;
	s/ TYPE47 / NSEC /;
	s/ TYPE48 / DNSKEY /;


	print;
}




