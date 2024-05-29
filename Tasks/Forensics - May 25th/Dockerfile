FROM python:2

RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apt-utils \
    atomicparsley \
    automake \
    autotools-dev \
    binwalk \
    bsdmainutils \
    build-essential \
    cewl \
    crunch \
    exiftool \
    ffmpeg \
    foremost \
    forensics-all \
    git \
    hexedit \
    libevent-dev \
    libffi-dev \
    libfuzzy-dev \
    libssl-dev \
    neovim \
    outguess \
    pngcheck \
    pngtools \
    python-dev \
    python-pip \
    python3-pip \
    sonic-visualiser \
    stegosuite \
    vim \
    xxd \
    zlib1g-dev && \
        pip3 install python-magic && \
        pip3 install tqdm

RUN pip install pycrypto distorm3

RUN git clone https://github.com/volatilityfoundation/volatility.git /root/vol
RUN git clone https://github.com/superponible/volatility-plugins /root/vol-plugins
RUN git clone https://github.com/volatilityfoundation/community /root/vol-community

WORKDIR /root

ENTRYPOINT ["/bin/bash"]

