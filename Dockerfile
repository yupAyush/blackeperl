# syntax=docker/dockerfile:1
FROM ubuntu:22.04
ARG tz_buildtime=Europe/Rome
ENV TZ=$tz_buildtime
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Make sure that all updates are in place
RUN apt-get clean && apt-get update -y && apt-get upgrade -y \
        && apt-get dist-upgrade -y && apt-get autoremove -y

# Install needed packages (tor: reach .onion targets over SOCKS for live scans)
RUN apt-get install git python3-dev build-essential \
       libffi-dev libssl-dev libfuzzy-dev wget sudo tor -y

# Adding sudo command
RUN useradd -m docker && echo "docker:docker" | chpasswd && adduser docker sudo
RUN echo "root ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Installing AIL dependencies
RUN mkdir /opt/AIL
# install_virtualenv.sh and requirements.txt are copied in separately, below,
# right before the layer that consumes them. Keeping them out of this big
# COPY means tweaking Python deps later doesn't bust the cache on everything
# above it -- in particular the very slow (single-threaded, to avoid OOM)
# from-source Kvrocks build.
COPY --exclude=install_virtualenv.sh --exclude=requirements.txt . /opt/AIL
WORKDIR /opt/AIL
RUN bash ./installing_deps_part1.sh
RUN bash ./installing_deps_kvrocks.sh
COPY install_virtualenv.sh requirements.txt /opt/AIL/
RUN bash ./installing_deps_part3.sh
WORKDIR /opt/AIL

# Default to UTF-8 file.encoding
ENV LANG C.UTF-8
ENV AIL_HOME /opt/AIL
ENV AIL_BIN ${AIL_HOME}/bin
ENV AIL_FLASK ${AIL_HOME}/var/www
ENV AIL_REDIS ${AIL_HOME}/redis/src
ENV AIL_ARDB ${AIL_HOME}/ardb/src
ENV AIL_KVROCKS ${AIL_HOME}/kvrocks/build
ENV AIL_VENV ${AIL_HOME}/AILENV

ENV PATH ${AIL_VENV}/bin:${AIL_HOME}:${AIL_REDIS}:${AIL_ARDB}:${AIL_KVROCKS}:${AIL_BIN}:${AIL_FLASK}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

EXPOSE 7000

COPY docker_start.sh /docker_start.sh
ENTRYPOINT ["/bin/bash", "docker_start.sh"]
