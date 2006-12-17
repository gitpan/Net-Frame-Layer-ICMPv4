#!/usr/bin/perl
use strict;
use warnings;

use Net::Frame::Layer::ICMPv4 qw(:consts);

my $icmp = Net::Frame::Layer::ICMPv4->new(
   type     => NF_ICMPv4_TYPE_ECHO_REQUEST,
   code     => NF_ICMPv4_CODE_ZERO,
   checksum => 0,
);

# Build an ICMPv4 echo-request
use Net::Frame::Layer::ICMPv4::Echo;
my $echo = Net::Frame::Layer::ICMPv4::Echo->new(payload => 'echo');
$icmp->icmpType($echo);
$icmp->pack;

print $icmp->print."\n";

# Build an information-request       
use Net::Frame::Layer::ICMPv4::Information;
my $info = Net::Frame::Layer::ICMPv4::Information->new(payload => 'info');
$icmp->type(NF_ICMPv4_TYPE_INFORMATION_REQUEST);
$icmp->icmpType($info);
$icmp->pack;

print $icmp->print."\n";

# Build an address-mask request       
use Net::Frame::Layer::ICMPv4::AddressMask;
my $mask = Net::Frame::Layer::ICMPv4::AddressMask->new(payload => 'mask');
$icmp->type(NF_ICMPv4_TYPE_ADDRESS_MASK_REQUEST);
$icmp->icmpType($mask);
$icmp->pack;

print $icmp->print."\n";

# Build a timestamp request     
use Net::Frame::Layer::ICMPv4::Timestamp;
my $timestamp = Net::Frame::Layer::ICMPv4::Timestamp->new(payload => 'time');
$icmp->type(NF_ICMPv4_TYPE_TIMESTAMP_REQUEST);
$icmp->icmpType($timestamp);
$icmp->pack;

print $icmp->print."\n";
