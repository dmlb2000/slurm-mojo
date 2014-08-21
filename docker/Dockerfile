FROM fedora

RUN yum -y clean all
RUN yum -y update
RUN yum -y install perl-Mojolicious perl-ExtUtils-MakeMaker perl-Authen-Krb5 perl-CPAN perl-HTTP-Tiny git make gcc perl-devel krb5-devel munge

EXPOSE 3000

RUN git clone http://github.com/dmlb2000/slurm-mojo /app/slurm-mojo
RUN cd /app/slurm-mojo && perl Makefile.PL PREFIX=/app
RUN cd /app/slurm-mojo && make install
ENV HOME /root
RUN mkdir -p /root/.cpan/CPAN
COPY MyConfig.pm /root/.cpan/CPAN/MyConfig.pm
RUN echo 'Defaults:root !requiretty' > /etc/sudoers.d/notty
RUN chmod 0400 /etc/sudoers.d/notty
RUN cpan install Authen::Krb5::Simple

ENV PERL5LIB /app/share/perl5
CMD /app/bin/slurm-mojo daemon
