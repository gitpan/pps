#!
$^W = 1;
use strict;
use threads;
use IO::Socket;
use Getopt::Long;
use Win32::Console;

#Optional Modules#
my $Net_Ping_installed = 0;
eval {require Net::Ping; $Net_Ping_installed = 1;};

#Declarations#
my $VERSION = 0.5;
my (@PORTS, @queue, $target, $scan_type, $st1, $st2,);
my $con = Win32::Console->new(STD_OUTPUT_HANDLE);

#Get Options#
my ($hlp, $sgl, $ful, $wel, @rng);
GetOptions ('h|?' => \$hlp,  's=i' => \$sgl,
            'f'   => \$ful,  'w'   => \$wel,
            'r=s' => \@rng,);
if ($hlp)               { &help(); exit;                      }
if (@rng)               { @rng = split('-', join('-', @rng)); }
if ($target = shift)    { unshift (@ARGV, $target);           }
else                    { &help(); exit;                      }
if    ($sgl)            { $scan_type = "Single"; }
elsif (@rng)            { $scan_type = "Range";  }
elsif ($wel)            { $scan_type = "Normal"; }
elsif ($ful)            { $scan_type = "Full";   }
else                    { $scan_type = "Normal"; }

#Main#
$| = 1;
$con->Cls();
$con->Title("Perl Port Scanner");
print ' ' . localtime() . "\n" . ' ' . '='x78 . "\n";
print "\t\t\t     Perl Port Scanner\n";
print ' ' . '='x78 . "\n\n\n\n\n\n";

if (inet_aton($target)) {
    if ($Net_Ping_installed == 1) { &ping(); }
}else{
    die "Couldn't resolve $target" . "'s address.\n($^E)\n$!";
}

my $ret = &loader($scan_type);
if     ($ret == 32) {
    for (0..31) {
        my $t = threads->new(\&scanner, $_);
        push (@queue, $t);
    }
    &detach(\@queue);
}
elsif ($ret == 8)  {
    for (0..7) {
        my $t = threads->new(\&scanner, $_);
        push (@queue, $t);
    }
    &detach(\@queue);
}
elsif ($ret == 1)  {
    my $t = threads->new(\&scanner, 0);
    push (@queue, $t);
    &detach(\@queue);
}

print "\nScan completed (" . localtime() . ").\n";
exit;

#Subroutines#
sub loader #------------------------------------------------------------
{
    if    ($scan_type eq "Single") {
        $st1 = $st2 = $sgl;
        push (@{$PORTS[0]}, $sgl);
        return(1);
    }
    elsif ($scan_type eq "Range")  {
        $st1 = $rng[0]; $st2 = $rng[1];
        unless ($rng[0] < $rng[1]) { &help(1); }
        @rng = ($st1..$st2);
        while (@rng) {
            for (0..7) { push (@{$PORTS[$_]}, shift @rng); }
        }
        return(8);
    }
    elsif ($scan_type eq "Full") { $st1 = 1; $st2 = 65530; }
    else                         { $st1 = 1; $st2 = 1024;  }
    @rng = ($st1..$st2);
    while (@rng) {
        for (0..31) { push (@{$PORTS[$_]}, shift @rng); }
    }
    return(32);
    #my $c = 0;
    #for my $val(1..$counter_var) {
    #    $val += $c; $c += 31;
    #    for my $idx (0..31) {
    #        #@{$PORTS[0]} 1,33,65,etc.. @{$PORTS[1]} 2,34,66,etc.. etc..
    #        #@PORTS contains: [32 arrays][32 or 2048 items each]
    #        push (@{$PORTS[$idx]}, $val);
    #        $val++;
    #    }
    #}
}
sub scanner #-----------------------------------------------------------
{
    my $index = $_[0]; my $idx = 0;
    
    undef @queue;
    foreach (@PORTS) {
        unless ($idx == $index) { undef $PORTS[$idx]; }
        $idx++;
    }
    while (@{$PORTS[$index]}) {
        my $remote_port = shift @{$PORTS[$index]};
        unless ($remote_port) { next; }
        $con->WriteChar("Scanning Host:  $target", 0, 5);
        $con->WriteChar("Scan Type:      $scan_type ($st1-$st2)",0,7);
        $con->WriteChar("Port:", 63, 7);
        $con->WriteChar("          ", 70, 7);
        $con->WriteChar("$remote_port", 70, 7);
        my $sock = IO::Socket::INET->new(PeerAddr  => $target,
                                         PeerPort  => $remote_port,
                                         Type      => SOCK_STREAM,
                                         Proto     => 'tcp',
                                         Timeout   => 1) or next;
        if ($sock) {
            my $pname = getservbyport($remote_port, 'tcp');
            unless ($pname) { $pname = 'unknown'; }
            print "Port: $remote_port ($pname) is open.\n";
        }
        $sock->shutdown(2); $sock->close;
    }
    return(1);
}
sub ping #--------------------------------------------------------------
{
    my $p = Net::Ping->new("icmp");
    my ($ret, $rtt, $ip) = $p->ping($target);
    print "$target [$ip] is ";
    print "NOT " unless $ret;
    print "reachable via ICMP ping.\n";
    print 'round trip time: ', $rtt, " second(s).\n" if $ret;
    print "\n";
    sleep(1);
    $p->close();
}
sub detach #------------------------------------------------------------
{
    my $q = $_[0];
    foreach (@$q) { eval {my @a = $_->join}; if (@$) { $_->detach; } }
}
sub help #--------------------------------------------------------------
{
    my $opt = shift || 0;
    $con->Title("Perl Port Scanner - Help");
    $con->Cls();
    print <<HELPTEXT;
    Usage:      pps <target> [options]

    Options:    -h  Help.
                -s  Scans a single port.
                -r  Scans a range of ports.
                -w  Scans all ports to 1024.
                -f  Scans all ports to 65530.

    Examples:   pps 127.0.0.1
                pps 127.0.0.1 -f
                pps localhost -r 20-140
                pps www.perl.org -s 80

    Notes:      A valid target is required.
                If no scan options are used then only the
                well-known port range will be scanned (same as -w).

HELPTEXT
    sleep 5;
    if ($opt == 1) {
        die "Error: First range value must be < than the second.\a\n";
    }
}

#POD Section#
=head1 NAME

PPS - Perl Port Scanner

=head1 DESCRIPTION

A Multi-Threaded port scanner.

=head1 README

PPS - Perl Port Scanner (pps_v0_5)
A multi-threaded port scanner, with single scan, range scan, full scan,
and well-known port numbers scan.

=head1 History

0.2 - Initial release.

0.3 - POD fixes, Trapped error if getservbyport fails.

      Improved loader function.  (Thanks Mark D).

0.4 - Changed the subroutine for running the script with no args.

0.5 - Re-structured code, reduced script size.

      Improved memory usage.

=head1 ToDo

      Replace Win32::Console (for portability).

      Make non-threaded version (multiplexed).

      Replace getservbyport.

      Still too much thread overhead...

=head1 Copyright

PPS - Perl Port Scanner.
Copyright (C) 2003-2004 Jason David McManus

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

=head1 PREREQUISITES

Getopt::Long
Win32::Console

=head1 COREQUISITES

Thread Support
optionally requires the Net::Ping module.

=pod OSNAMES

Win32

=pod SCRIPT CATEGORIES

Networking

=cut