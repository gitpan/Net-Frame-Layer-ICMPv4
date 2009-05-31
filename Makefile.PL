#
# $Id: Makefile.PL 49 2009-05-31 13:15:34Z gomor $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame::Layer::ICMPv4',
   VERSION_FROM  => 'lib/Net/Frame/Layer/ICMPv4.pm',
   LICENSE       => 'artistic',
   ABSTRACT_FROM => 'lib/Net/Frame/Layer/ICMPv4.pm',
   AUTHOR        => 'GomoR <gomor-cpan_at_gomor.org>',
   PREREQ_PM     => {
      Net::Frame => 0,
   },
);
