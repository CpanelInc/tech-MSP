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

GetOptions(\%opts, 'domain=s'=> \$domain, 'sent:s'=> \$sent, 'email:s'=> \$email, 'help'=>\$help) or die ("Please see --help\n");

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

elsif (defined $email) {
print "Email Section!\n";
}

else { ## No options passed.
print_info("\n[INFO] * "); 
print_normal("There are currently $queue_cnt messages in the Exim queue.\n");
port_26();
custom_etc_mail();
check_blacklists();
rdns_lookup();
}


## Colors ##

sub print_info {
    my $text = shift;
    print BOLD YELLOW ON_BLACK $text;
    print color 'reset';
}

sub print_warning {
    my $text = shift;
    print BOLD RED ON_BLACK "$text";
    print color 'reset';
}

sub print_normal {
    my $text = shift;
    print BOLD CYAN ON_BLACK "$text";
    print color 'reset';
}

##INFORMATIONAL CHEX##

sub help {
print "Usage: ./sse.pl [OPTION] [VALUE]\n","Without options:  Run informational checks on Exim's configuration and server status.\n","--domain=DOMAIN   Check for domain's existence, ownership, and resolution on the server.\n","--email=EMAIL     Email specific checks.\n","-s                View Breakdown of sent mail.\n";
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
    print_warning("[WARN] * /etc/mailips is NOT empty.\n")  if -s '/etc/mailips';
    print_warning("[WARN] * /etc/mailhelo is NOT empty.\n") if -s '/etc/mailhelo';
    print_warning("[WARN] * /etc/reversedns (Custom RDNS) EXISTS.\n") if -e '/etc/reversedns';
  }

sub port_26 {  ## You'll need to remove the double /n as more checks are written.
if (`netstat -an | grep :26`) {
    print_info("[INFO] *");
    print_normal(" Port 26 is ENABLED.\n");
    return;
}
else{
    print_warning("[WARN] * Port 26 is DISABLED.\n");
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
if ($check =~ /NXDOMAIN/) {
print_warning("[WARN] * $lines does not have a RDNS entry: $check\n");
}
else {
print_info("[INFO] *");
print_normal(" $lines has RDNS entry:   $check\n");
}
}
}
}
}

### DOMAIN CHEX ###

sub hostname_check{
if ($hostname eq $domain){
    print_warning("[WARN] * Your hostname $hostname appears to be the same as $domain.  Was this intentional?\n");
    }}

sub domain_exist {
open( USERDOMAINS, "/etc/userdomains" );
while (<USERDOMAINS>) {
    if (/^$domain: (\S+)/i) {
        my $user = $1;
        print_info("\n[INFO] *");
        print_normal(" The domain $domain is owned by $user.\n");
        my $suspchk = "/var/cpanel/suspended/$user";
            if (-e $suspchk) {
                print_warning("[WARN] * The user $user is SUSPENDED.\n");
            }
        return;
    }}
        print_warning("[WARN] * The domain $domain DOES NOT exist on this server.\n");
close (USERDOMAINS);
}

sub check_local_or_remote {

open my $loc_domain, '<', '/etc/localdomains';
while (<$loc_domain>) {
    if (/^${domain}$/){
        print_info("[INFO] *");
        print_normal(" $domain is in LOCALDOMAINS.\n");
        }}
    close $loc_domain;

open my $remote_domain, '<', '/etc/remotedomains';
while (<$remote_domain>) {
    if (/^${domain}$/){
        print_info("[INFO] *");
        print_normal(" $domain is in REMOTEDOMAINS.\n");
        last;
        }}
    close $remote_domain;
}

sub domain_resolv {
chomp($domain_ip = run('dig',$domain,'@8.8.4.4','+short'));
if (grep {$_ eq $domain_ip} @local_ipaddrs_list) {
        print_info("[INFO] *");
        print_normal(" The domain $domain resolves to IP: \n\t \\_ $domain_ip\n");
        return;
    }
    elsif ((!defined $domain_ip) || ($domain_ip eq '')) {
    return;
}
    else {
        print_warning("[WARN] * The domain $domain DOES NOT resolve to this server.\n");
	print_warning("\t\\_ It currently resolves to:      $domain_ip \n");
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
    print_warning("[WARN] * $ip is listed on $line\n");
}
}
}


sub check_spf {
my @check = qx/dig $domain TXT/;
if ( grep ( m/.*spf.*/, @check) ) {
print_info("[INFO] *");
print_normal(" $domain has the folloiwng SPF records:\n");
foreach my $check (@check) {
if ( $check =~ m/.*spf.*/) {
print_normal("\t\\_ $check");
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
print_info("[INFO] *");
print_normal(" $domain has the following domain keys:\n ");
print_normal("\t\\_ $check");
}
}
}
else {
return;
}
}


sub sent_email {
open FILE, "/var/log/exim_mainlog";

print_warning("\nEmails by user: ");
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


print_warning("\nEmail accounts sending out mail:\n\n");


open FILE, "/var/log/exim_mainlog";
while ( $lines_email = <FILE>) {
if ( $lines_email=~/(_login:|_plain:)(.+?)(\sS=)/i) {
my $lines_emails = $2;
push (@email_users, $lines_emails);
}
}
my %email_count;
$email_count{$_}++ foreach @email_users;
while (my ($key, $value) = each(%email_count)) {
	if ($key =~ /^$/) {
		delete($email_count{$key});
}
}

foreach my $value (reverse sort { $email_count{$a} <=> $email_count{$b} }  keys %email_count) {
print " " . $email_count{$value} . " : " . $value . "\n";
}

print "\n";
print colored ['red on_blue'], "Total: " . scalar (@email_users - 1);
print "\n";


## Section for current working directories

print_warning("\nCurrent working directories:\n\n\n");


open FILE, "/var/log/exim_mainlog";
my @dirs;

while ($dirs = <FILE>) {
if ( $dirs=~/(cwd=)(.+?)(\s)/i) {
my $dir = $2;
push (@dirs, $dir);
}
}
my %dirs;
$dirs{$_}++ foreach @dirs;
while (my ($key, $value) = each(%dirs)) {
        if ($key =~ /^$/ ) {
                delete($dirs[$key]);
}
}

while (my ($key, $value) = each(%dirs)) {
        if ($key =~ /^$/) {
                delete($dirs{$key});
}
}

foreach my $value (reverse sort { $dirs{$a} <=> $dirs{$b} }  keys %dirs) {
print " " . $dirs{$value} . " : " . $value . "\n";
}

print "\n";
print colored ['red on_blue'], "Total: " . scalar (@dirs - 1);
print "\n";


print_warning("\nTop 20 Email Titles:\n\n\n");

open FILE, "/var/log/exim_mainlog";
my @titles;

while ($titles = <FILE>) {
if ( $titles=~/((U=|_login:).+)((?<=T=\").+?(?=\"))(.+$)/i) {
my $title = $3;
push (@titles, $title);
}
}
our %titlecount;
$titlecount{$_}++ foreach @titles;
while (my ($key, $value) = each(%titlecount)) {
	if ($key =~ /^$/ ) {
		delete($titlecount[$key]);
}
}

my $limit = 20;
my $loops = 0;
foreach my $value (reverse sort { $titlecount{$a} <=> $titlecount{$b} }  keys %titlecount) {
print " " . $titlecount{$value} . " : " . $value . "\n";
$loops++;
if ($loops >= $limit) {
	last;
}
}
print "\n\n";
print colored ['red on_blue'], "Total: " . scalar (@titles - 1);
print "\n\n";

close FILE;




}
}
}
