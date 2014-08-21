FROM fedora

RUN yum -y install perl-Mojolicious
RUN cpan install Mojolicious::Plugin::SslAuth

EXPOSE 443

RUN git clone http://github.com/dmlb2000/slurm-mojo
RUN perl Makefile.PL
RUN make install
CMD ["slurm-mojo", "daemon"]
