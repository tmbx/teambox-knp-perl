use ExtUtils::MakeMaker;

WriteMakefile(
              NAME         => 'Teambox::KNP',
              DISTNAME     => 'teambox-knp',
              AUTHOR       => 'Teambox Packages',
              ABSTRACT     => 'Teambox KNP Perl Modules',
              EXE_FILES    => ['pkgmail',
                               'kosquery',
                               'kpslogin']
             );
