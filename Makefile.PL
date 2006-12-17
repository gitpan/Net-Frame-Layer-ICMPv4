#
# $Id: Makefile.PL,v 1.5 2006/12/17 16:16:04 gomor Exp $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame::Layer::ICMPv4',
   VERSION_FROM  => 'lib/Net/Frame/Layer/ICMPv4.pm',
   LICENSE       => 'Artistic',
   ABSTRACT_FROM => 'lib/Net/Frame/Layer/ICMPv4.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
   PREREQ_PM     => {
      Net::Frame => 0,
   },
);
