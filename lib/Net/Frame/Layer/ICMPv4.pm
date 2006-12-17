#
# $Id: ICMPv4.pm,v 1.12 2006/12/17 16:16:51 gomor Exp $
#
package Net::Frame::Layer::ICMPv4;
use strict;
use warnings;

our $VERSION = '1.02';

use Net::Frame::Layer qw(:consts :subs);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NF_ICMPv4_HDR_LEN
      NF_ICMPv4_CODE_ZERO
      NF_ICMPv4_TYPE_DESTUNREACH
      NF_ICMPv4_CODE_NETWORK
      NF_ICMPv4_CODE_HOST
      NF_ICMPv4_CODE_PROTOCOL
      NF_ICMPv4_CODE_PORT
      NF_ICMPv4_CODE_FRAGMENTATION_NEEDED
      NF_ICMPv4_CODE_SOURCE_ROUTE_FAILED
      NF_ICMPv4_TYPE_TIMEEXCEED
      NF_ICMPv4_CODE_TTL_IN_TRANSIT
      NF_ICMPv4_CODE_FRAGMENT_REASSEMBLY
      NF_ICMPv4_TYPE_PARAMETERPROBLEM
      NF_ICMPv4_CODE_POINTER
      NF_ICMPv4_TYPE_SOURCEQUENCH
      NF_ICMPv4_TYPE_REDIRECT
      NF_ICMPv4_CODE_FOR_NETWORK
      NF_ICMPv4_CODE_FOR_HOST
      NF_ICMPv4_CODE_FOR_TOS_AND_NETWORK
      NF_ICMPv4_CODE_FOR_TOS_AND_HOST
      NF_ICMPv4_TYPE_ECHO_REQUEST
      NF_ICMPv4_TYPE_ECHO_REPLY
      NF_ICMPv4_TYPE_TIMESTAMP_REQUEST
      NF_ICMPv4_TYPE_TIMESTAMP_REPLY
      NF_ICMPv4_TYPE_INFORMATION_REQUEST
      NF_ICMPv4_TYPE_INFORMATION_REPLY
      NF_ICMPv4_TYPE_ADDRESS_MASK_REQUEST
      NF_ICMPv4_TYPE_ADDRESS_MASK_REPLY
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NF_ICMPv4_HDR_LEN                      => 8;
use constant NF_ICMPv4_CODE_ZERO                    => 0;
use constant NF_ICMPv4_TYPE_DESTUNREACH             => 3;
use constant NF_ICMPv4_CODE_NETWORK                 => 0;
use constant NF_ICMPv4_CODE_HOST                    => 1;
use constant NF_ICMPv4_CODE_PROTOCOL                => 2;
use constant NF_ICMPv4_CODE_PORT                    => 3;
use constant NF_ICMPv4_CODE_FRAGMENTATION_NEEDED    => 4;
use constant NF_ICMPv4_CODE_SOURCE_ROUTE_FAILED     => 5;
use constant NF_ICMPv4_TYPE_TIMEEXCEED              => 11;
use constant NF_ICMPv4_CODE_TTL_IN_TRANSIT          => 0;
use constant NF_ICMPv4_CODE_FRAGMENT_REASSEMBLY     => 1;
use constant NF_ICMPv4_TYPE_PARAMETERPROBLEM        => 12;
use constant NF_ICMPv4_CODE_POINTER                 => 0;
use constant NF_ICMPv4_TYPE_SOURCEQUENCH            => 4;
use constant NF_ICMPv4_TYPE_REDIRECT                => 5;
use constant NF_ICMPv4_CODE_FOR_NETWORK             => 0;
use constant NF_ICMPv4_CODE_FOR_HOST                => 1;
use constant NF_ICMPv4_CODE_FOR_TOS_AND_NETWORK     => 2;
use constant NF_ICMPv4_CODE_FOR_TOS_AND_HOST        => 3;
use constant NF_ICMPv4_TYPE_ECHO_REQUEST            => 8;
use constant NF_ICMPv4_TYPE_ECHO_REPLY              => 0;
use constant NF_ICMPv4_TYPE_TIMESTAMP_REQUEST       => 13;
use constant NF_ICMPv4_TYPE_TIMESTAMP_REPLY         => 14;
use constant NF_ICMPv4_TYPE_INFORMATION_REQUEST     => 15;
use constant NF_ICMPv4_TYPE_INFORMATION_REPLY       => 16;
use constant NF_ICMPv4_TYPE_ADDRESS_MASK_REQUEST    => 17; # RFC 950
use constant NF_ICMPv4_TYPE_ADDRESS_MASK_REPLY      => 18; # RFC 950

our @AS = qw(
   type
   code
   checksum
   icmpType
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

#no strict 'vars';

use Carp;
require Net::Frame::Layer::ICMPv4::AddressMask;
require Net::Frame::Layer::ICMPv4::DestUnreach;
require Net::Frame::Layer::ICMPv4::Echo;
require Net::Frame::Layer::ICMPv4::Information;
require Net::Frame::Layer::ICMPv4::Redirect;
require Net::Frame::Layer::ICMPv4::TimeExceed;
require Net::Frame::Layer::ICMPv4::Timestamp;

sub new {
   shift->SUPER::new(
      type     => NF_ICMPv4_TYPE_ECHO_REQUEST,
      code     => NF_ICMPv4_CODE_ZERO,
      checksum => 0,
      @_,
   );
}

sub match {
   my $self = shift;
   my ($with) = @_;
   my $sType = $self->type;
   my $wType = $with->type;
   if ($sType eq NF_ICMPv4_TYPE_ECHO_REQUEST
   &&  $wType eq NF_ICMPv4_TYPE_ECHO_REPLY) {
      return 1;
   }
   elsif ($sType eq NF_ICMPv4_TYPE_TIMESTAMP_REQUEST
      &&  $wType eq NF_ICMPv4_TYPE_TIMESTAMP_REPLY) {
      return 1;
   }
   elsif ($sType eq NF_ICMPv4_TYPE_INFORMATION_REQUEST
      &&  $wType eq NF_ICMPv4_TYPE_INFORMATION_REPLY) {
      return 1;
   }
   elsif ($sType eq NF_ICMPv4_TYPE_ADDRESS_MASK_REQUEST
      &&  $wType eq NF_ICMPv4_TYPE_ADDRESS_MASK_REPLY) {
      return 1;
   }
   0;
}

# XXX: may be better, by keying on type also
sub getKey        { shift->layer }
sub getKeyReverse { shift->layer }

sub getLength {
   my $self = shift;
   my $len = 4;
   if ($self->icmpType) {
      $len += $self->icmpType->getLength;
   }
   $len;
}

sub pack {
   my $self = shift;

   my $raw = $self->SUPER::pack('CCn',
      $self->type, $self->code, $self->checksum,
   ) or return undef;

   if ($self->icmpType) {
      $raw .= $self->icmpType->pack
         or return undef;

      $self->payload($self->icmpType->payload);
      $self->icmpType->payload(undef);
   }

   $self->raw($raw);
}

sub unpack {
   my $self = shift;

   my ($type, $code, $checksum, $payload) =
      $self->SUPER::unpack('CCn a*', $self->raw)
         or return undef;

   $self->type($type);
   $self->code($code);
   $self->checksum($checksum);

   if ($payload) {
      if ($type eq NF_ICMPv4_TYPE_ECHO_REQUEST
      ||  $type eq NF_ICMPv4_TYPE_ECHO_REPLY) {
         $self->icmpType(Net::Frame::Layer::ICMPv4::Echo->new(raw => $payload));
      }
      elsif ($type eq NF_ICMPv4_TYPE_TIMESTAMP_REQUEST
         ||  $type eq NF_ICMPv4_TYPE_TIMESTAMP_REPLY) {
         $self->icmpType(Net::Frame::Layer::ICMPv4::Timestamp->new(
            raw => $payload,
         ));
      }
      elsif ($type eq NF_ICMPv4_TYPE_INFORMATION_REQUEST
         ||  $type eq NF_ICMPv4_TYPE_INFORMATION_REPLY) {
         $self->icmpType(Net::Frame::Layer::ICMPv4::Information->new(
            raw => $payload,
         ));
      }
      elsif ($type eq NF_ICMPv4_TYPE_ADDRESS_MASK_REQUEST
         ||  $type eq NF_ICMPv4_TYPE_ADDRESS_MASK_REPLY) {
         $self->icmpType(Net::Frame::Layer::ICMPv4::AddressMask->new(
            raw => $payload,
         ));
      }
      elsif ($type eq NF_ICMPv4_TYPE_DESTUNREACH) {
         $self->icmpType(Net::Frame::Layer::ICMPv4::DestUnreach->new(
            raw => $payload,
         ));
      }
      elsif ($type eq NF_ICMPv4_TYPE_REDIRECT) {
         $self->icmpType(Net::Frame::Layer::ICMPv4::Redirect->new(
            raw => $payload,
         ));
      }
      elsif ($type eq NF_ICMPv4_TYPE_TIMEEXCEED) {
         $self->icmpType(Net::Frame::Layer::ICMPv4::TimeExceed->new(
            raw => $payload,
         ));
      }
      $self->icmpType->unpack;
      if ($self->icmpType->payload) {
         $self->payload($self->icmpType->payload);
         $self->icmpType->payload(undef);
      }
   }

   $self;
}

sub computeChecksums {
   my $self = shift;

   my $packed = $self->SUPER::pack('CCna*',
      $self->type, $self->code, 0, $self->icmpType->pack,
   ) or return undef;

   $self->checksum(inetChecksum($packed));

   1;
}

sub encapsulate {
   my $self = shift;

   return $self->nextLayer if $self->nextLayer;

   if ($self->payload) {
      my $type = $self->type;
      if ($type eq NF_ICMPv4_TYPE_DESTUNREACH
      ||  $type eq NF_ICMPv4_TYPE_REDIRECT
      ||  $type eq NF_ICMPv4_TYPE_TIMEEXCEED) {
         return 'IPv4';
      }
   }

   NF_LAYER_NONE;
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $buf = sprintf "$l: type:%d  code:%d  checksum:0x%04x",
      $self->type, $self->code, $self->checksum;

   if ($self->icmpType) {
      $buf .= "\n".$self->icmpType->print;
   }

   $buf;
}

1;

__END__

=head1 NAME

Net::Frame::Layer::ICMPv4 - Internet Control Message Protocol v4 layer object

=head1 SYNOPSIS

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

   # Read a raw layer
   my $layer = Net::Frame::Layer::ICMPv4->new(raw => $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the ICMPv4 layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc792.txt

See also B<Net::Frame::Layer> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<type>

=item B<code>

Type and code fields. See B<CONSTANTS>.

=item B<checksum>

The checksum of ICMPv4 header.

=item B<icmpType>

A pointer to a B<Net::Frame::Layer::ICMPv4::*> layer.

=back

The following are inherited attributes. See B<Net::Frame::Layer> for more information.

=over 4

=item B<raw>

=item B<payload>

=item B<nextLayer>

=back

=head1 METHODS

=over 4

=item B<new>

=item B<new> (hash)

Object constructor. You can pass attributes that will overwrite default ones. See B<SYNOPSIS> for default values.

=item B<computeChecksums>

Computes the ICMPv4 checksum.

=item B<getKey>

=item B<getKeyReverse>

These two methods are basically used to increase the speed when using B<recv> method from B<Net::Frame::Simple>. Usually, you write them when you need to write B<match> method.

=item B<match> (Net::Frame::Layer::ICMPv4 object)

This method is mostly used internally. You pass a B<Net::Frame::Layer::ICMPv4> layer as a parameter, and it returns true if this is a response corresponding for the request, or returns false if not.

=back

The following are inherited methods. Some of them may be overriden in this layer, and some others may not be meaningful in this layer. See B<Net::Frame::Layer> for more information.

=over 4

=item B<layer>

=item B<computeLengths>

=item B<computeChecksums>

=item B<pack>

=item B<unpack>

=item B<encapsulate>

=item B<getLength>

=item B<getPayloadLength>

=item B<print>

=item B<dump>

=back

=head1 CONSTANTS

Load them: use Net::Frame::Layer::ICMPv4 qw(:consts);

=over 4

=item B<NF_ICMPv4_CODE_ZERO>

ICMP code zero, used by various ICMP messages.

=item B<NF_ICMPv4_TYPE_DESTUNREACH>

=item B<NF_ICMPv4_CODE_NETWORK>

=item B<NF_ICMPv4_CODE_HOST>

=item B<NF_ICMPv4_CODE_PROTOCOL>

=item B<NF_ICMPv4_CODE_PORT>

=item B<NF_ICMPv4_CODE_FRAGMENTATION_NEEDED>

=item B<NF_ICMPv4_CODE_SOURCE_ROUTE_FAILED>

Destination unreachable type, with possible code numbers.

=item B<NF_ICMPv4_TYPE_REDIRECT>

=item B<NF_ICMPv4_CODE_FOR_NETWORK>

=item B<NF_ICMPv4_CODE_FOR_HOST>

=item B<NF_ICMPv4_CODE_FOR_TOS_AND_NETWORK>

=item B<NF_ICMPv4_CODE_FOR_TOS_AND_HOST>

Redirect type message, with possible code numbers.

=item B<NF_ICMPv4_TYPE_TIMEEXCEED>

=item B<NF_ICMPv4_CODE_TTL_IN_TRANSIT>

=item B<NF_ICMPv4_CODE_FRAGMENT_REASSEMBLY>

Time exceeded message, with possible code numbers.

=item B<NF_ICMPv4_TYPE_PARAMETERPROBLEM>

=item B<NF_ICMPv4_CODE_POINTER>

Parameter problem, with possible code numbers.

=item B<NF_ICMPv4_TYPE_SOURCEQUENCH>

Source quench type.

=item B<NF_ICMPv4_TYPE_ECHO_REQUEST>

=item B<NF_ICMPv4_TYPE_ECHO_REPLY>

=item B<NF_ICMPv4_TYPE_TIMESTAMP_REQUEST>

=item B<NF_ICMPv4_TYPE_TIMESTAMP_REPLY>

=item B<NF_ICMPv4_TYPE_INFORMATION_REQUEST>

=item B<NF_ICMPv4_TYPE_INFORMATION_REPLY>

=item B<NF_ICMPv4_TYPE_ADDRESS_MASK_REQUEST>

=item B<NF_ICMPv4_TYPE_ADDRESS_MASK_REPLY>

Other request/reply ICMP messages types.

=back

=head1 SEE ALSO

L<Net::Frame::Layer>

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
