FROM fedora

RUN yum -y clean all
RUN yum -y update
RUN yum -y install perl-Mojolicious perl-ExtUtils-MakeMaker git make

EXPOSE 3000

RUN git clone http://github.com/dmlb2000/slurm-mojo /app/slurm-mojo
RUN cd /app/slurm-mojo && perl Makefile.PL PREFIX=/app
RUN cd /app/slurm-mojo && make install
CMD /app/bin/slurm-mojo daemon
