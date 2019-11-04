#!/usr/local/cpanel/3rdparty/bin/perl
package MSP;

use strict;
use warnings;

use Getopt::Long;
use Cpanel::AdvConfig::dovecot                      ();
use Cpanel::FileUtils::Dir                          ();
use Cpanel::IONice                                  ();
use Cpanel::IO                                      ();
use Term::ANSIColor                     qw{:constants};

# Variables
our $VERSION = '2.1';

$Term::ANSIColor::AUTORESET = 1;

our $LOGDIR                = q{/var/log/};
our $CPANEL_CONFIG_FILE    = q{/var/cpanel/cpanel.config};
our $EXIM_LOCALOPTS_FILE   = q{/etc/exim.conf.localopts};
our $DOVECOT_CONF          = q{/var/cpanel/conf/dovecot/main};

our $EXIM_MAINLOG          = q{exim_mainlog};
our $MAILLOG               = q{maillog};

our @RBLS                  = qw{ b.barracudacentral.org
                                 bl.spamcop.net
                                 dnsbl.sorbs.net
                                 spam.dnsbl.sorbs.net
                                 ips.backscatterer.org
                                 zen.spamhaus.org
                               };

# Initialize
our $LIMIT = 10;
our $THRESHOLD = 1;
our $ROTATED_LIMIT = 5; # I've seen users with hundreds of rotated logs before, we should safeguard to prevent msp from working against unreasonably large data set
our $OPT_TIMEOUT;

# Options
my %opts;
my ( $all, $auth, $conf, $forwards, $help, $limit, $logdir, $queue, @rbl, $rbllist, $rotated, $rude, $threshold, $verbose );
GetOptions(
    \%opts,
    'all',
    'auth',
    'forwards',
    'help',
    'conf',
    'limit=i{1}',
    'logdir=s{1}',
    'maillog',
    'queue',
    'rbl=s',
    'rbllist',
    'rotated',
    'rude',
    'threshold=i{1}',
    'verbose'
) or die("Please see --help\n");

# Make this a modulino
__PACKAGE__->main(@ARGV) unless caller();
1;

sub print_help {
    print BOLD BRIGHT_BLUE ON_BLACK "[MSP-$VERSION] ";
    print BOLD WHITE ON_BLACK "Mail Status Probe: Mail authentication statistics and configuration checker\n";
    print "Usage: ./msp.pl --auth --rotated --rude\n";
    print "       ./msp.pl --conf --rbl [all|bl.spamcop.net,zen.spamhaus.org]\n\n";
    printf( "\t%-15s %s\n",  "--help", "print this help message");
#    printf( "\t%-15s %s\n", "--all", "run all checks");
    printf( "\t%-15s %s\n",  "--auth", "print mail authentication statistics");
    printf( "\t%-15s %s\n",  "--conf", "print mail configuration info (e.g. require_secure_auth, smtpmailgidonly, etc.)");
#    printf( "\t%-15s %s\n", "--forwards", "print forward relay statistics");
#    printf( "\t%-15s %s\n", "--ignore", "ignore common statistics (e.g. cwd=/var/spool/exim)");
    printf( "\t%-15s %s\n",  "--limit", "limit statistics checks to n results (defaults to 10, set to 0 for no limit)");
    printf( "\t%-15s %s\n",  "--logdir", "specify an alternative logging directory, (defaults to /var/log)");
    printf( "\t%-15s %s\n",  "--maillog", "check maillog for common errors");
    printf( "\t%-15s %s\n",  "--queue", "print exim queue length");
#    printf( "\t%-15s %s\n", "--quiet", "only print alarming information or statistics (requires --threshold)");
    printf( "\t%-15s %s\n",  "--rbl", "check IP's against provided blacklists(comma delimited)");
    printf( "\t%-15s %s\n",  "--rbllist", "list available RBL's");
    printf( "\t%-15s %s\n",  "--rotated", "check rotated exim logs");
    printf( "\t%-15s %s\n",  "--rude", "forgo nice/ionice settings");
    printf( "\t%-15s %s\n",  "--threshold", "limit statistics output to n threshold(defaults to 1)");
    printf( "\t%-15s %s\n",  "--verbose", "display all information");
    print "\n";
    exit;
}    

sub main {
    die "MSP must be run as root\n" if ( $< != 0 );

    print_help() if ( (!%opts) || ($opts{help}) );

    conf_check() if ($opts{conf});

    print_exim_queue() if ($opts{queue});

    auth_check() if ($opts{auth});

    maillog_check() if ($opts{maillog});

    rbl_list() if ($opts{rbllist});

    rbl_check($opts{rbl}) if ($opts{rbl});
    return;
}

sub conf_check {
        # Check Tweak Settings
        print_bold_white("Checking Tweak Settings...\n");
        print "--------------------------\n";
        my %cpconf = get_conf( $CPANEL_CONFIG_FILE );
        if ( $cpconf{'smtpmailgidonly'} ne 1 ) {
            print_warn("Restrict outgoing SMTP to root, exim, and mailman (FKA SMTP Tweak) is disabled!\n"); 
        } elsif ( $opts{verbose} ) {
            print_info("Restrict outgoing SMTP to root, exim, and mailman (FKA SMTP Tweak) is enabled\n");
        }
        if ( $cpconf{'nobodyspam'} ne 1 ) {
            print_warn("Prevent “nobody” from sending mail is disabled!\n"); 
        } elsif ( $opts{verbose} ) {
            print_info("Prevent “nobody” from sending mail is enabled\n");
        }
        if ( $cpconf{'popbeforesmtp'} ne 0 ) {
            print_warn("Pop-before-SMTP is enabled!\n"); 
        } elsif ( $opts{verbose} ) {
            print_info("Pop-before-SMTP is disabled\n");
        }
        if ( $cpconf{'domainowner_mail_pass'} ne 0 ) {
            print_warn("Mail authentication via domain owner password is enabled!\n"); 
        } elsif ( $opts{verbose} ) {
            print_info("Mail authentication via domain owner password is disabled\n");
        }
        print "\n";

        # Check Exim Configuration
        print_bold_white("Checking Exim Configuration...\n");
        print "------------------------------\n";
        my %exim_localopts_conf = get_conf( $EXIM_LOCALOPTS_FILE );
        if ( $exim_localopts_conf{'allowweakciphers'} ne 0 ) {
            print_warn("Allow weak SSL/TLS ciphers is enabled!\n"); 
        } elsif ( $opts{verbose} ) {
            print_info("Allow weak SSL/TLS ciphers is disabled\n");
        }   
        if ( $exim_localopts_conf{'require_secure_auth'} ne 1 ) {
            print_warn("Require clients to connect with SSL or issue the STARTTLS is disabled!\n"); 
        } elsif ( $opts{verbose} ) {
            print_info("Require clients to connect with SSL or issue the STARTTLS is enabled\n");
        }
        if ( $exim_localopts_conf{'systemfilter'} ne q{/etc/cpanel_exim_system_filter} ) {
           print_warn("Custom System Filter File in use: $exim_localopts_conf{'systemfilter'}\n");
        } elsif ( $opts{verbose} ) {
           print_info("System Filter File is set to the default path: $exim_localopts_conf{'systemfilter'}\n");
        }
        print "\n";

        # Check Dovecot Configuration
        print_bold_white("Checking Dovecot Configuration...\n");
        print "---------------------------------\n";
        my $dovecot = Cpanel::AdvConfig::dovecot::get_config();
        if ( $dovecot->{'protocols'} !~ m/imap/ ) {
            print_warn("IMAP Protocol is disabled!\n");
        }
        if ( $dovecot->{'disable_plaintext_auth'} !~ m/no/ ) {
            print_warn("Allow Plaintext Authentication is enabled!\n");
        } elsif ( $opts{verbose} ) {
            print_info("Allow Plaintext Authentication is disabled\n");
        }
        print "\n";
        return;
}
   

sub auth_check {
    my @logfiles;
    my @auth_password_hits;
    my @auth_sendmail_hits;
    my @auth_local_user_hits;
    my @subject_hits;
    my $logcount = 0;

    # Exim regex search strings
    my $auth_password_regex   = qr{\sA=dovecot_(login|plain):([^\s]+)\s};
    my $auth_sendmail_regex   = qr{\scwd=([^\s]+)\s};
    my $auth_local_user_regex = qr{\sU=([^\s]+)\s.*B=authenticated_local_user};
    my $subject_regex         = qr{\s<=\s.*T="([^"]+)"\s};

    print_bold_white("Checking Mail Authentication statistics...\n");
    print "------------------------------------------\n";

    # Set logdir, ensure trailing slash, and bail if the provided logdir doesn't exist:
    my $logdir = ($opts{logdir}) ? ($opts{logdir}) : $LOGDIR;
    $logdir =~ s@/*$@/@;

    if (!-d $logdir) {
        print_warn("$opts{logdir}: No such file or directory. Skipping spam check...\n\n");
        return;
    }
 
    # Collect log files
    for my $file ( grep { m/^exim_mainlog/ } @{ Cpanel::FileUtils::Dir::get_directory_nodes($logdir) } ) {
        if ( $opts{rotated} ) { 
            if ( ( $file =~ m/mainlog-/ ) && ( $logcount ne $ROTATED_LIMIT ) ) {
                push @logfiles, $file;
                $logcount++;
            }
        }
        push @logfiles, $file if ( $file =~ m/mainlog$/ );
    }
    print_warn("Safeguard triggered... --rotated is limited to $ROTATED_LIMIT logs\n") if ( $logcount eq $ROTATED_LIMIT );

    # Bail if we can't find any logs
    return print_warn("Bailing, no exim logs found...\n\n") if (!@logfiles);

    # Set ionice
    my %cpconf = get_conf( $CPANEL_CONFIG_FILE );
    if ( ( !$opts{rude} ) && ( Cpanel::IONice::ionice( 'best-effort', exists $cpconf{'ionice_import_exim_data'} ? $cpconf{'ionice_import_exim_data'} : 6 ) ) ) {
        print("Setting I/O priority to reduce system load: " . Cpanel::IONice::get_ionice() . "\n\n");
        setpriority( 0, 0, 19 );
    }

    my $fh;
    lOG: for my $log ( @logfiles ) {
        if ( $log =~ /[.]gz$/ ) {
            my @cmd = ( qw{ gunzip -c -f }, $logdir . $log );
            if ( !open $fh, '-|', @cmd ) {
                print_warn("Skipping $logdir/$log: Cannot open pipe to read stdout from command '@{ [ join ' ', @cmd ] }' : $!\n");
                next LOG;
            }
        } else {
            if ( !open $fh, '<', $logdir . $log ) {
                print_warn("Skipping $logdir/$log: Cannot open for reading $!\n");
                next LOG;
            }
        }
        while ( my $block = Cpanel::IO::read_bytes_to_end_of_line( $fh, 65_535 ) ) {
            foreach my $line ( split( m{\n}, $block ) ) {
                push @auth_password_hits, $2 if ($line =~ $auth_password_regex);
                push @auth_sendmail_hits, $1 if ($line =~ $auth_sendmail_regex);
                push @auth_local_user_hits, $1 if ($line =~ $auth_local_user_regex);
                push @subject_hits, $1 if ($line =~ $subject_regex);
            }
        }
        close($fh);
    }

    # Print info
    print_bold_white("Emails sent via Password Authentication:\n");
    if (@auth_password_hits) {
        sort_uniq(@auth_password_hits);
    } else {
        print "None\n";
    }
    print "\n";
    print_bold_white("Directories where email was sent via sendmail/script:\n");
    if (@auth_sendmail_hits) {
        sort_uniq(@auth_sendmail_hits);
    } else {
        print "None\n";
    }
    print "\n";
    print_bold_white("Users who sent mail via local SMTP:\n");
    if (@auth_local_user_hits) {
        sort_uniq(@auth_local_user_hits);
    } else {
        print "None\n";
    }
    print "\n";
    print_bold_white("Subjects by commonality:\n");
    sort_uniq(@subject_hits);
    print "\n";
 
    return;
}

sub print_exim_queue {
    # Print exim queue length
    print_bold_white("Exim Queue: ");
    my $queue = get_exim_queue();
    if ($queue >= 1000) {
        print_bold_red("$queue\n");
    } else {
        print_bold_green("$queue\n");
    }
    return;
}

sub get_exim_queue {
    my $queue = timed_run_trap_stderr( 10, 'exim', '-bpc');
    return $queue;
    }

sub rbl_check {
    my $rbls = shift;
    my @rbls = split( /,/, $rbls);
    my @ips;

    # Fetch IP's... should we only check mailips? this is more thorough...
    # could ignore local through bogon regex?
    return unless my $ips = get_ips();

    # Uncomment the following for testing positive hits
    # push @$ips, qw{ 127.0.0.2 };

    # In cPanel 11.84, we switched to the libunbound resolver
    my ($cp_numeric_version, $cp_original_version) = get_cpanel_version();
    my $libunbound = (version_compare($cp_numeric_version, qw( < 11.84))) ? 0 : 1;

    # If "all" is found in the --rbl arg, ignore rest, use default rbl list
    # maybe we should append so that user can specify all and ones which are not included in the list?
    @rbls = @RBLS if (grep { /\ball\b/i } @rbls);
    print_bold_white("Checking IP's against RBL's...\n");
    print "------------------------------\n";

    foreach my $ip (@$ips) {
        print "$ip:\n";
        my $ip_rev = join('.', reverse split('\.', $ip));
        foreach my $rbl (@rbls) {
            printf("\t%-25s ", $rbl);

            my $result;
            if ($libunbound) {
                $result = dns_query("$ip_rev.$rbl", 'A')->[0] || 0;
            } else {
                # This uses libunbound, which will return an aref, but we can always expect just one result here
                $result = dns_query_pre_84("$ip_rev.$rbl", 'A') || 0;
            }

            if ( $result =~ /\A 127\.0\.0\./xms ) {
                 print_bold_red("LISTED\n");
            } else {
                 print_bold_green("GOOD\n");
            }
        }
        print "\n";
    }

    return;
}

sub rbl_list {
    print_bold_white("Available RBL's:\n");
    print "----------------\n";

    foreach my $rbl (@RBLS) {
        print "$rbl\n";
    }
    print "\n";
    return;
}

sub maillog_check {
    my @logfiles;
    my $logcount = 0;

    # General
    my @out_of_memory;
    my $out_of_memory_regex     = qr{lmtp\(([\w\.@]+)\): Fatal: \S+: Out of memory};

    my $time_backwards          = 0;
    my $time_backwards_regex    = qr{Fatal: Time just moved backwards by \d+ \w+\. This might cause a lot of problems, so I'll just kill myself now};

    # Quota errors
    my @quota_failed;
    my $quotactl_failed_regex   = qr{quota-fs: (quotactl\(Q_X?GETQUOTA, [\w/]+\) failed: .+)};
    my $ioctl_failed_regex      = qr{quota-fs: (ioctl\([\w/]+, Q_QUOTACTL\) failed: .+)};
    my $invalid_nfs_regex       = qr{quota-fs: (.+ is not a valid NFS device path)};
    my $unrespponsive_rpc_regex = qr{quota-fs: (could not contact RPC service on .+)};
    my $rquota_remote_regex     = qr{quota-fs: (remote( ext)? rquota call failed: .+)};
    my $rquota_eacces_regex     = qr{quota-fs: (permission denied to( ext)? rquota service)};
    my $rquota_compile_regex    = qr{quota-fs: (rquota not compiled with group support)};
    my $dovecot_compile_regex   = qr{quota-fs: (Dovecot was compiled with Linux quota .+)};
    my $unrec_code_regex        = qr{quota-fs: (unrecognized status code .+)};

    # Spamd error
    my $pyzor_timeout           = 0;
    my $pyzor_timeout_regex     = qr{Timeout: Did not receive a response from the pyzor server public\.pyzor\.org};

    my $pyzor_unreachable       = 0;
    my $pyzor_unreachable_regex = qr{pyzor: check failed: Cannot connect to public.pyzor.org:24441: IO::Socket::INET: connect: Network is unreachable};

    print_bold_white("Checking Maillog for common errors...\n");
    print "-----------------------------------------\n";

    # Set logdir, ensure trailing slash, and bail if the provided logdir doesn't exist:
    my $logdir = ($opts{logdir}) ? ($opts{logdir}) : $LOGDIR;
    $logdir =~ s@/*$@/@;

    if (!-d $logdir) {
        print_warn("$opts{logdir}: No such file or directory. Skipping spam check...\n\n");
        return;
    }

    # Collect log files
    for my $file ( grep { m/^maillog/ } @{ Cpanel::FileUtils::Dir::get_directory_nodes($logdir) } ) {
        if ( $opts{rotated} ) {
            if ( ( $file =~ m/maillog-/ ) && ( $logcount ne $ROTATED_LIMIT ) ) {
                push @logfiles, $file;
                $logcount++;
            }
        }
        push @logfiles, $file if ( $file =~ m/maillog$/ );
    }
    print_warn("Safeguard triggered... --rotated is limited to $ROTATED_LIMIT logs\n") if ( $logcount eq $ROTATED_LIMIT );

    # Bail if we can't find any logs
    return print_warn("Bailing, no maillog found...\n\n") if (!@logfiles);

    # Set ionice
    my %cpconf = get_conf( $CPANEL_CONFIG_FILE );
    if ( ( !$opts{rude} ) && ( Cpanel::IONice::ionice( 'best-effort', exists $cpconf{'ionice_import_exim_data'} ? $cpconf{'ionice_import_exim_data'} : 6 ) ) ) {
        print("Setting I/O priority to reduce system load: " . Cpanel::IONice::get_ionice() . "\n\n");
        setpriority( 0, 0, 19 );
    }

    my $fh;
    lOG: for my $log ( @logfiles ) {
        if ( $log =~ /[.]gz$/ ) {
            my @cmd = ( qw{ gunzip -c -f }, $logdir . $log );
            if ( !open $fh, '-|', @cmd ) {
                print_warn("Skipping $logdir/$log: Cannot open pipe to read stdout from command '@{ [ join ' ', @cmd ] }' : $!\n");
                next LOG;
            }
        } else {
            if ( !open $fh, '<', $logdir . $log ) {
                print_warn("Skipping $logdir/$log: Cannot open for reading $!\n");
                next LOG;
            }
        }
        while ( my $block = Cpanel::IO::read_bytes_to_end_of_line( $fh, 65_535 ) ) {
            foreach my $line ( split( m{\n}, $block ) ) {
                push @out_of_memory, $1 if ($line =~ $out_of_memory_regex);
                push @quota_failed, $1 if ($line =~ $quotactl_failed_regex);
                ++$pyzor_timeout if ($line =~ $pyzor_timeout_regex);
            }
        }
        close($fh);
    }

    # Print info
    print_bold_white("LMTP quota issues:\n");
    if (@quota_failed) {
        sort_uniq(@quota_failed);
    } else {
        print "None\n";
    }
    print "\n";
    print_bold_white("Email accounts triggering LMTP Out of memory:\n");
    if (@out_of_memory) {
        sort_uniq(@out_of_memory);
    } else {
        print "None\n";
    }
    print "\n";
    print_bold_white("Timeouts to public.pyzor.org:24441:\n");
    if ($pyzor_timeout ne 0) {
        print "Pyzor timed out $pyzor_timeout times\n";
    } else {
        print "None\n";
    }
    print "\n";

    return;
}

sub version_compare {
    # example: return if version_compare($ver_string, qw( >= 1.2.3.3 ));
    # Must be no more than four version numbers separated by periods and/or underscores.
    my ( $ver1, $mode, $ver2 ) = @_;
    return if ( !defined($ver1) || ( $ver1 =~ /[^\._0-9]/ ) );
    return if ( !defined($ver2) || ( $ver2 =~ /[^\._0-9]/ ) );

    # Shamelessly copied the comparison logic out of Cpanel::Version::Compare
    my %modes = (
        '>' => sub {
            return if $_[0] eq $_[1];
            return _version_cmp(@_) > 0;
        },
        '<' => sub {
            return if $_[0] eq $_[1];
            return _version_cmp(@_) < 0;
        },
        '==' => sub { return $_[0] eq $_[1] || _version_cmp(@_) == 0; },
        '!=' => sub { return $_[0] ne $_[1] && _version_cmp(@_) != 0; },
        '>=' => sub {
            return 1 if $_[0] eq $_[1];
            return _version_cmp(@_) >= 0;
        },
        '<=' => sub {
            return 1 if $_[0] eq $_[1];
            return _version_cmp(@_) <= 0;
        }
    );
    return if ( !exists $modes{$mode} );
    return $modes{$mode}->( $ver1, $ver2 );
}

sub _version_cmp {
    my ( $first, $second ) = @_;
    my ( $a1, $b1, $c1, $d1 ) = split /[\._]/, $first;
    my ( $a2, $b2, $c2, $d2 ) = split /[\._]/, $second;
    for my $ref ( \$a1, \$b1, \$c1, \$d1, \$a2, \$b2, \$c2, \$d2, ) {    # Fill empties with 0
        $$ref = 0 unless defined $$ref;
    }
    return $a1 <=> $a2 || $b1 <=> $b2 || $c1 <=> $c2 || $d1 <=> $d2;
}

sub get_cpanel_version {
    my $cpanel_version_file = '/usr/local/cpanel/version';
    my $numeric_version;
    my $original_version;

    if ( open my $file_fh, '<', $cpanel_version_file ) {
        $original_version = readline($file_fh);
        close $file_fh;
    }
    return ( 'UNKNOWN', 'UNKNOWN' ) unless defined $original_version;
    chomp $original_version;

    # Parse either 1.2.3.4 or 1.2.3-THING_4 to 1.2.3.4
    $numeric_version = join( '.', split( /\.|-[a-zA-Z]+_/, $original_version ) );
    $numeric_version = 'UNKNOWN' unless $numeric_version =~ /^\d+\.\d+\.\d+\.\d+$/;

    return ( $numeric_version, $original_version );
}

sub get_ips {
    my @ips;
    return if !load_module_with_fallbacks(
        'needed_subs'  => [qw{get_detailed_ip_cfg}],
        'modules'      => [qw{Whostmgr::Ips}],
        'fail_warning' => 'can\'t load Whostmgr::Ips',
    );

    return if !load_module_with_fallbacks(
        'needed_subs'  => [qw{get_public_ip}],
        'modules'      => [qw{Cpanel::NAT}],
        'fail_warning' => 'can\'t load Cpanel::NAT',
    );

    my $ipref = Whostmgr::Ips::get_detailed_ip_cfg();
    foreach my $iphash ( @{$ipref} ) {
        push @ips, Cpanel::NAT::get_public_ip( $iphash->{'ip'} );
    }

    return \@ips;
}

sub dns_query_pre_84 {
    my ($name, $type) = @_;

    return if !load_module_with_fallbacks(
        'needed_subs'  => [qw{new recursive_query}],
        'modules'      => [qw{Cpanel::DnsRoots::Resolver}],
        'fail_warning' => 'can\'t load Cpanel::DnsRoots::Resolver',
    );

    my $dns   = Cpanel::DnsRoots::Resolver->new();
    my ($res) = $dns->recursive_query( $name, $type );
    return $res;
}

sub dns_query {
    my($name, $type) = @_;

    return if !load_module_with_fallbacks(
        'needed_subs'  => [qw{new recursive_queries}],
        'modules'      => [qw{Cpanel::DNS::Unbound}],
        'fail_warning' => 'can\'t load Cpanel::DNS::Unbound',
    );

    my $dns   = Cpanel::DNS::Unbound->new();
    my ($res) = $dns->recursive_queries( [ [ $name, $type ] ] )->[0];
    return $res->{'decoded_data'} || $res->{result}{data};
}

sub sort_uniq {
    my @input = @_;
    my %count;
    my $line = 1;
    $opts{limit} //= $LIMIT;
    $opts{threshold} //= $THRESHOLD;
    foreach ( @input ) { $count{$_}++; }
    for ( sort { $count{$b} <=> $count{$a} } keys %count ) {
        if ( $line ne $opts{limit} ) {
            printf ("%7d %s\n", "$count{$_}", "$_") if ( $count{$_} >= $opts{threshold} );
            $line++;
        } else { 
            printf( "%7d %s\n", "$count{$_}", "$_") if ( $count{$_} >= $opts{threshold} );
            last;
        }
    }
    return;
}

# cpanel.confg and exim.conf.localopts
sub get_conf {
    my $conf = shift;
    my %cpconf;
    if ( open( my $cpconf_fh, '<', $conf ) ) {
        local $/ = undef;
        %cpconf = map { ( split( /=/, $_, 2 ) )[ 0, 1 ] } split( /\n/, readline($cpconf_fh) );
        close $cpconf_fh;
        return %cpconf;
    } else {
        print_warn("Could not open file: $conf\n");
    }
    return;
}

# exec utilities, taken from SSP
sub timed_run_trap_stderr {
    my ( $timer, @PROGA ) = @_;
    return _timedsaferun( $timer, 1, @PROGA );
}

sub _timedsaferun {    # Borrowed from WHM 66 Cpanel::SafeRun::Timed and modified
                       # We need to be sure to never return undef, return an empty string instead.
    my ( $timer, $stderr_to_stdout, @PROGA ) = @_;
    return '' if ( substr( $PROGA[0], 0, 1 ) eq '/' && !-x $PROGA[0] );
    $timer = $timer       ? $timer       : 25;       # A timer value of 0 means use the default, currently 25.
    $timer = $OPT_TIMEOUT ? $OPT_TIMEOUT : $timer;

    my $output;
    my $complete = 0;
    my $pid;
    my $fh;                                          # FB-63723: must declare $fh before eval block in order to avoid unwanted implicit waitpid on die
    eval {
        local $SIG{'__DIE__'} = 'DEFAULT';
        local $SIG{'ALRM'} = sub { $output = ''; print RED ON_BLACK 'Timeout while executing: ' . join( ' ', @PROGA ) . "\n"; die; };
        alarm($timer);
        if ( $pid = open( $fh, '-|' ) ) {            ## no critic (BriefOpen)
            local $/;
            $output = readline($fh);
            close($fh);
        }
        elsif ( defined $pid ) {
            open( STDIN, '<', '/dev/null' );         ## no critic (BriefOpen)
            if ($stderr_to_stdout) {
                open( STDERR, '>&', 'STDOUT' );      ## no critic (BriefOpen)
            }
            else {
                open( STDERR, '>', '/dev/null' );    ## no critic (BriefOpen)
            }
            exec(@PROGA) or exit 1;
        }
        else {
            print RED ON_BLACK 'Error while executing: [ ' . join( ' ', @PROGA ) . ' ]: ' . $! . "\n";
            alarm 0;
            die;
        }
        $complete = 1;
        alarm 0;
    };
    alarm 0;
    if ( !$complete && $pid && $pid > 0 ) {
        kill( 15, $pid );    #TERM
        sleep(2);            # Give the process a chance to die 'nicely'
        kill( 9, $pid );     #KILL
    }
    return defined $output ? $output : '';
}

# SUB load_module_with_fallbacks(
#   'modules'      => [ 'module1', 'module2', ... ],
#   'needed_subs'  => [ 'do_needful', ... ],
#   'fallback'     => sub { *do_needful = sub { ... }; return; },
#   'fail_warning' => "Oops, something went wrong, you may want to do something about this",
#   'fail_fatal'   => 1,
# );
#
# Input is HASH of options:
#   'modules'      => ARRAYREF of SCALAR strings corresponding to module names to attempt to import. These are attempted first.
#   'needed_subs'  => ARRAYREF of SCALAR strings corresponding to subroutine names you need defined from the module(s).
#   'fallback'     => CODEREF which defines the needed subs manually. Only used if all modules passed in above fail to load. Optional.
#   'fail_warning' => SCALAR string that will convey a message to the user if the module(s) fail to load. Optional.
#   'fail_fatal'   => BOOL whether you want to die if you fail to load the needed subs/modules via all available methods. Optional.
#
# Returns the module/namespace that loaded correctly, throws if all available attempts at finding the desired needed_subs subs fail and fail_fatal is passed.
sub load_module_with_fallbacks {
    my %opts = @_;
    my $namespace_loaded;
    foreach my $module2try ( @{ $opts{'modules'} } ) {

        # Don't 'require' it if we already have it.
        my $inc_entry = join( "/", split( "::", $module2try ) ) . ".pm";
        if ( !$INC{$module2try} ) {
            local $@;
            next if !eval "require $module2try; 1";    ## no critic (StringyEval)
        }

        # Check if the imported modules 'can' do the job
        next if ( scalar( grep { $module2try->can($_) } @{ $opts{'needed_subs'} } ) != scalar( @{ $opts{'needed_subs'} } ) );

        # Ok, we're good to go!
        $namespace_loaded = $module2try;
        last;
    }

    # Fallback to coderef, but don't do sanity checking on this, as it is presumed the caller "knows what they are doing" if passing a coderef.
    if ( !$namespace_loaded ) {
        if ( !$opts{'fallback'} || ref $opts{'fallback'} != 'CODE' ) {
            print_warn( 'Missing Perl Module(s): ' . join( ', ', @{ $opts{'modules'} } ) . ' -- ' . $opts{'fail_warning'} . " -- Try using /usr/local/cpanel/3rdparty/bin/perl?\n" ) if $opts{'fail_warning'};
            die "Stopping here." if $opts{'fail_fatal'};
        }
        else {
            $opts{'fallback'}->();

            # call like main::subroutine instead of Name::Space::subroutine
            $namespace_loaded = 'main';
        }
    }
    return $namespace_loaded;
}

# pretty prints
sub print_warn {
    my $text = shift // '';
    return if $text eq '';

    print BOLD RED ON_BLACK '[WARN] * ';
    print WHITE ON_BLACK "$text";
    return;
}

sub print_info {
    my $text = shift // '';
    return if $text eq '';

    print BOLD GREEN ON_BLACK '[INFO] * ';
    print WHITE ON_BLACK "$text";
    return;
}

sub print_std {
    my $text = shift // '';
    return if $text eq '';

    print BOLD BRIGHT_BLUE ON_BLACK '[MSP]  * ';
    print BOLD WHITE ON_BLACK "$text";
    return;
}

sub print_bold_white {
    my $text = shift // '';
    return if $text eq '';

    print BOLD WHITE ON_BLACK "$text";
    return;
}

sub print_bold_red {
    my $text = shift // '';
    return if $text eq '';

    print BOLD RED ON_BLACK "$text";
    return;
}

sub print_bold_green {
    my $text = shift // '';
    return if $text eq '';

    print BOLD GREEN ON_BLACK "$text";
    return;
}
