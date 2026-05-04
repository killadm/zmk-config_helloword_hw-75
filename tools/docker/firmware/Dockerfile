FROM zmkfirmware/zmk-build-arm:3.2

ENV DEBIAN_FRONTEND=noninteractive
ENV PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python

COPY requirements*.txt /tmp/zephyr-requirements/

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        python3-pip \
        protobuf-compiler \
    && curl -fsSL https://deb.nodesource.com/setup_16.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && sed -i 's/clang-format>=1.13x/clang-format>=1.13/g' /tmp/zephyr-requirements/requirements-extras.txt \
    && pip install --no-cache-dir --upgrade pip packaging setuptools wheel \
    && pip install --no-cache-dir \
        -r /tmp/zephyr-requirements/requirements.txt \
        fonttools \
    && pip install --no-cache-dir --force-reinstall "protobuf<4.0.0" \
    && npm install -g lv_font_conv \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/zephyr-requirements
