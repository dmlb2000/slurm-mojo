use ExtUtils::MakeMaker;

WriteMakefile(
	NAME              => "Slurm::Mojo",
	VERSION_FROM      => "lib/Slurm/Mojo.pm",
	EXE_FILES         => ['bin/slurm-mojo']
);
