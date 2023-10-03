FROM docker.io/library/python:3.12

ENV UNAME=user
ARG UID=1000
ARG GID=1000
RUN groupadd -g $GID -o $UNAME && \
  useradd -m -u $UID -g $GID -o -d /home/$UNAME -s /bin/bash $UNAME && \
  echo $UNAME:password | chpasswd && \
  adduser $UNAME sudo

WORKDIR /home/$UNAME/src
COPY --chown=$UNAME:$GID ./ .

RUN pip install --upgrade pip setuptools ipython && \ 
  pip install -e .[tests]
