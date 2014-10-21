#
# $Id: AddressMask.pm 49 2009-05-31 13:15:34Z gomor $
#
package Net::Frame::Layer::ICMPv4::AddressMask;
use strict; use warnings;

use Net::Frame::Layer qw(:consts :subs);
our @ISA = qw(Net::Frame::Layer);

our @AS = qw(
   identifier
   sequenceNumber
   addressMask
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

sub new {
   shift->SUPER::new(
      identifier     => getRandom16bitsInt(),
      sequenceNumber => getRandom16bitsInt(),
      addressMask    => '0.0.0.0',
      @_,
   );
}

sub getLength { 8 }

sub pack {
   my $self = shift;

   $self->raw($self->SUPER::pack('nna4',
      $self->identifier, $self->sequenceNumber, inetAton($self->addressMask),
   )) or return;

   return $self->raw;
}

sub unpack {
   my $self = shift;

   my ($identifier, $sequenceNumber, $addressMask, $payload) =
      $self->SUPER::unpack('nna4 a*', $self->raw)
         or return;

   $self->identifier($identifier);
   $self->sequenceNumber($sequenceNumber);
   $self->addressMask(inetNtoa($addressMask));
   $self->payload($payload);

   return $self;
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   sprintf "$l: identifier:%d  sequenceNumber:%d  addressMask:%s",
      $self->identifier, $self->sequenceNumber, $self->addressMask;
}

1;

__END__

=head1 NAME

Net::Frame::Layer::ICMPv4::AddressMask - ICMPv4 AddressMask type object

=head1 SYNOPSIS

   use Net::Frame::Layer::ICMPv4::AddressMask;

   my $layer = Net::Frame::Layer::ICMPv4::AddressMask->new(
      identifier     => getRandom16bitsInt(),
      sequenceNumber => getRandom16bitsInt(),
      addressMask    => '0.0.0.0',
      payload        => '',
   );
   $layer->pack;

   print 'RAW: '.$layer->dump."\n";

   # Read a raw layer
   my $layer = Net::Frame::Layer::ICMPv4::AddressMask->new(raw => $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the ICMPv4 AddressMask object.

See also B<Net::Frame::Layer> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<identifier>

Identification number.

=item B<sequenceNumber>

Sequence number.

=item B<addressMask>

Address mask in dotted format (example: 255.255.255.0).

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

No constants here.

=head1 SEE ALSO

L<Net::Frame::Layer::ICMPv4>, L<Net::Frame::Layer>

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006-2009, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
