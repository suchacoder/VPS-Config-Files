#!/usr/bin/perl
use strict;
use warnings;

my @chainList_filter = ();
my @chainList_nat = ();
my @chainList_mangle = ();
my @chainList_raw = ();
my @chainList_security = ();
my %chainHash;
my %output;
my @all_tables = qw{filter nat mangle raw security};

sub create_chainlist{
	my $chain_list = shift;
	my $chains = shift;
	foreach my $l (split(/\n/, $chains)){
		$l =~ s/^Chain\s(.*?)\s.*/$1/;
		push @$chain_list, $l if defined $1;
	}
}

create_chainlist(\@chainList_filter, scalar `iptables -xnvL -t filter | grep "^Chain"`);
create_chainlist(\@chainList_nat, scalar `iptables -xnvL -t nat | grep "^Chain"`);
create_chainlist(\@chainList_mangle, scalar `iptables -xnvL -t mangle | grep "^Chain"`);
create_chainlist(\@chainList_raw, scalar `iptables -xnvL -t raw | grep "^Chain"`);
create_chainlist(\@chainList_security, scalar `iptables -xnvL -t security | grep "^Chain"`);

my $full_result = "";
my @chainList;

while(1){

sleep(1);
#system("clear");
for (keys %chainHash){
	delete $chainHash{$_};
};

%output = map{$_ => scalar `iptables -xnvL -t $_ -Z | grep -v "0        0"`} @all_tables;

sub get_chaindata{
	my $chain_name = shift;
	$full_result =~ m/(^Chain $chain_name.*?)\n\n/ms;
	my $chain_data = "";
	$chain_data = scalar $1 if defined $1;
	return $chain_data;
}
sub append_hash{
	my $table_name = shift;
	my $chain_name = shift;
	my $chain_data = get_chaindata($chain_name);
	if($chain_data =~ m/^\d+|^\s+\d+\s+/ms){
#		print "$chain_name\n";
#		print "$chain_data\n";
		$chainHash{$table_name}{$chain_name} = $chain_data;
	}
	return;
};

foreach my $table (keys %output){
$full_result = $output{$table};
$full_result =~ s/^Zeroing.*/\n/ms;
#print  $full_result;
print "\e[01;34m-----------", uc($table), '-' x (100 - length($table)),"\n";

# Use and print correct chain data for the corresponding table

@chainList = @chainList_filter if $table eq "filter";
@chainList = @chainList_nat if $table eq "nat";
@chainList = @chainList_mangle if $table eq "mangle";
@chainList = @chainList_raw if $table eq "raw";
@chainList = @chainList_security if $table eq "security";


foreach my $chain (@chainList){
	append_hash($table, $chain);
};

foreach my $key (keys %{$chainHash{$table}}){
	foreach my $i (split /\n/, $chainHash{$table}{$key}){
#		print "$table:- \n $chainHash{$table}{$key}\n";
		print $i =~ m/^\s*(\d+)/ || $i =~ m/(\d+) packets/
		?  ($1 > 0
		    ? ($i =~ m/DROP|DENY|REJECT/
		      ? "\e[01;40;31m"
		      : "\e[01;40;32m")
          	    : "\e[00;40;37m")
        	: "\e[00;40;33m";
     		print "\e[K$i\e[01;40;37m\n";
	}
}

}
print "\n\nNEXT UPDATE\n\n";
}
