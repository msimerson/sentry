require 5.006001;
use ExtUtils::MakeMaker;
WriteMakefile
(
  'PL_FILES' => {},
  'INSTALLDIRS' => 'site',
  'NAME' => 'Sentry',
  'EXE_FILES' => [
                   'sentry.pl',
                 ],
  'VERSION_FROM' => 'sentry.pl',
  'PREREQ_PM' => {
                   'Net::IP' => 1,
                 }
)
;
