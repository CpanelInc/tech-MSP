#!/usr/bin/perl

use warnings;
use Sys::Hostname;
use Getopt::Long;
use Term::ANSIColor qw(:constants);
use POSIX;
use File::Find;
use Term::ANSIColor;

$ENV{'PATH'} = '/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin';

## OPTIONS ##

my %opts;
my $domain;
my $sent;
my $help;

GetOptions(\%opts, 'domain=s'=> \$domain, 'sent:s'=> \$sent, 'help'=>\$help) or die ("Please see --help\n");

## GLOBALS ##

my $hostname = hostname;
chomp (my $queue_cnt = `exim -bpc`);
my @local_ipaddrs_list = get_local_ipaddrs();
get_local_ipaddrs();

## GUTS ##

if ($domain){ ## --domain{
hostname_check();
domain_exist();
check_local_or_remote();
domain_resolv();
check_spf();
check_dkim();
}

elsif ($help) { ##--help
help();
}

elsif (defined $sent) {
sent_email();
}

else { ## No options passed.
print "There are currently $queue_cnt messages in the Exim queue.\n";
port_26();
custom_etc_mail();
check_blacklists();
rdns_lookup();
}

##INFORMATIONAL CHEX##

sub help {
print "Usage: ./sse.pl [OPTION] [VALUE]\n","Without options:  Run informational checks on Exim's configuration and server status.\n","--domain=DOMAIN   Check for domain's existence, ownership, and resolution on the server.\n","--email=EMAIL        Not yet implimented.\n";
}

sub run {  #Directly ripped run() from SSP; likely more gratuitous than what is actually needed.  Remember to look into IPC::Run.

    my $cmdline = \@_;
    my $output;
    local ($/);
    my ( $pid, $prog_fh );
    if ( $pid = open( $prog_fh, '-|' ) ) {

    }
    else {
        open STDERR, '>', '/dev/null';
        ( $ENV{'PATH'} ) = $ENV{'PATH'} =~ m/(.*)/;
        exec(@$cmdline);
        exit(127);
    }

    if ( !$prog_fh || !$pid ) {
        $? = -1;
        return \$output;
    }
    $output = readline($prog_fh);
    close($prog_fh);
    return $output;
}

sub get_local_ipaddrs { ## Ripped from SSP as well.  Likely less gratuitous, but will likely drop the use of run() in the future cuz IPC.
    my @ifconfig = split /\n/, run( 'ifconfig', '-a' );
    for my $line (@ifconfig) {
        if ( $line =~ m{ (\d+\.\d+\.\d+\.\d+) }xms ) {
            my $ipaddr = $1;
            unless ( $ipaddr =~ m{ \A 127\. }xms ) {
                push @local_ipaddrs_list, $ipaddr;
            }
        }
    }
    return @local_ipaddrs_list;
}

### GENERAL CHEX ###

sub custom_etc_mail{
    print "/etc/mailips is NOT empty.\n"  if -s '/etc/mailips';
    print "/etc/mailhelo is NOT empty.\n" if -s '/etc/mailhelo';
    print "/etc/reversedns (Custom RDNS) EXISTS.\n" if -e '/etc/reversedns';
  }
  
sub port_26 {  ## You'll need to remove the double /n as more checks are written.
if (`netstat -an | grep :26`) {
    print "Port 26 is ENABLED.\n\n";
    return;
}
else{
    print "Port 26 is DISABLED.\n\n";
}
}


sub rdns_lookup {
my @files = qw(/var/cpanel/mainip /etc/mailips);
my @ips = '';

foreach my $files (@files) {
open FILE, "$files";
while ( $lines = <FILE> ) {
if ($lines =~ m/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/) {
$lines = $1;
my $check = qx/host $lines/;
print "$lines has RDNS entry:   $check";
}
}
}
}

### DOMAIN CHEX ###

sub hostname_check{
if ($hostname eq $domain){
    print "Your hostname $hostname appears to be the same as $domain.  Was this intentional?\n";
    }}

sub domain_exist {
open( USERDOMAINS, "/etc/userdomains" );
while (<USERDOMAINS>) {
    if (/^$domain: (\S+)/i) {
        my $user = $1;
        print "The domain $domain is owned by $user.\n";
        my $suspchk = "/var/cpanel/suspended/$user";
            if (-e $suspchk) {
                print "The user $user is SUSPENDED.\n";
            }
        return;
    }}
        print "The domain $domain DOES NOT exist on this server.\n";
close (USERDOMAINS);
}

sub check_local_or_remote {

open my $loc_domain, '<', '/etc/localdomains';
while (<$loc_domain>) {
    if (/^${domain}$/){
        print "$domain is in LOCALDOMAINS.\n";      
        }}
    close $loc_domain;

open my $remote_domain, '<', '/etc/remotedomains';
while (<$remote_domain>) {
    if (/^${domain}$/){
        print "$domain is in REMOTEDOMAINS.\n";
        last;
        }}
    close $remote_domain;
}

sub domain_resolv {
chomp($domain_ip = run('dig',$domain,'@8.8.4.4','+short'));
if (grep {$_ eq $domain_ip} @local_ipaddrs_list) {
        print "The domain $domain resolves to IP: $domain_ip.\n";
        return;
    }
    elsif ((!defined $domain_ip) || ($domain_ip eq '')) {
    return;
}
    else {
        print "The domain $domain DOES NOT resolve to this server.\n";
	print "It currently resolves to: \n$domain_ip \n"; 
}


sub check_blacklists {
# Way more lists out there, but I'll add them later.
my %list = (
    'sbl-xbl.spamhaus.org'        => 'http://www.spamhaus.org',
    'pbl.spamhaus.org'            => 'http://www.spamhaus.org',
    'bl.spamcop.net'              => 'http://www.spamcop.net',
    'dsn.rfc-ignorant.org'        => 'http://www.rfc-ignorant.org',
    'postmaster.rfc-ignorant.org' => 'http://www.rfc.ignorant.org',
    'abuse.rfc-ignorant.org'      => 'http://www.rfc.ignorant.org',
    'whois.rfc-ignorant.org'      => 'http://www.rfc.ignorant.org',
    'ipwhois.rfc-ignorant.org'    => 'http://www.rfc.ignorant.org',
    'bogusmx.rfc-ignorant.org'    => 'http://www.rfc.ignorant.org',
    'dnsbl.sorbs.net'             => 'http://www.sorbs.net',
    'badconf.rhsbl.sorbs.net'     => 'http://www.sorbs.net',
    'nomail.rhsbl.sorbs.net'      => 'http://www.sorbs.net',
    'cbl.abuseat.org'             => 'http://www.abuseat.org/support',
    'relays.visi.com'             => 'http://www.visi.com',
    'list.dsbl.org'               => 'http://www.dsbl.org',
    'opm.blitzed.org'             => 'http://www.blitzed.org',
    'zen.spamhaus.org'            => 'http://www.spamhaus.org',
);

# Grab the mail addresses

my @files = qw(/var/cpanel/mainip /etc/mailips);

my @ips = '';

foreach my $files (@files) {
open FILE, "$files";
while ( $lines = <FILE> ) {
if ($lines =~ m/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/) {
$lines = $1;
chomp $lines;
push @ips, $lines;
}
}
close FILE;
}

shift @ips;


foreach my $line (keys %list) {
    foreach my $ip (@ips) {
    my $host = "$ip.$line";
    my $ret = qx/dig +short $host/;

    my $status = $ret ? "is listed" : "not listed";
    if ( $status eq "not listed" ) {
    return;
}
    else {
    print "$ip is listed on $line\n";
}
}
}


sub check_spf {
my @check = qx/dig $domain TXT/;
if ( grep ( m/.*spf.*/, @check) ) {
print "$domain has the folloiwng SPF records:\n"; 
foreach my $check (@check) {
if ( $check =~ m/.*spf.*/) {
print "$check";
}
}
}
else {
return;
}
}

sub check_dkim {
my @check = qx/dig default._domainkey.$domain TXT/;
if (@check) {
foreach my $check (@check) {
if ( $check =~ m/.*DKIM.*/ ) {
print "$domain has the following domain keys:\n ";
print $check;
}
}
}
else {
return;
}
}


sub sent_email {
open FILE, "/var/log/exim_mainlog";

print color 'red';
print "\nEmails by user: " . color 'reset';
print "\n\n";
our @system_users = "";

while ( $lines_users = <FILE> ){
if ( $lines_users=~/(U\=)(.+?)(\sP\=)/i ) {
my $line_users = $2;
push (@system_users, $line_users)
}
}
my %count;
$count{$_}++ foreach @system_users;
while (my ($key, $value) = each(%count)) {
	if ($key =~ /^$/ ) {
		delete($count{$key});
}
}

foreach my $value (reverse sort { $count{$a} <=> $count{$b} }  keys %count) {
print " " . $count{$value} . " : " . $value . "\n";
}

print "\n\n";
print colored ['red on_blue'], "Total:  " . scalar (@system_users - 1);
print "\n";
}


}
}

