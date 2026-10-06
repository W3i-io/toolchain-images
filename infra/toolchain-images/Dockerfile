ARG BASE
FROM ${BASE}
ARG PERL_VERSION=5.36.0-7+deb12u4
RUN apt-get update \
 && apt-get install -y --no-install-recommends --only-upgrade perl-base=${PERL_VERSION} \
 && test "$(dpkg-query -W -f='${Version}' perl-base)" = "${PERL_VERSION}" \
 && rm -rf /var/lib/apt/lists/*
