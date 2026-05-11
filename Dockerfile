# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

FROM debian:testing-slim AS build

SHELL ["/bin/bash", "-c"]

RUN apt-get clean && apt update \
 && apt -y install build-essential git-lfs

RUN ldd --version ldd

ADD . /root/nimbos

RUN cd /root/nimbos \
 && make -j$(nproc) update \
 && make -j$(nproc) V=1 NIMFLAGS="-d:disableMarchNative" LOG_LEVEL=TRACE logos_chain_node


# --------------------------------- #
# Starting new image to reduce size #
# --------------------------------- #
FROM debian:testing-slim as deploy

SHELL ["/bin/bash", "-c"]
RUN apt-get clean && apt update \
 && apt -y install build-essential
RUN apt update && apt -y upgrade

RUN ldd --version ldd

RUN rm -rf /home/user/nimbos/build/logos_chain_node

# "COPY" creates new image layers, so we cram all we can into one command
COPY --from=build /root/nimbos/build/logos_chain_node /home/user/nimbos/build/logos_chain_node

ENV PATH="/home/user/nimbos/build:${PATH}"
ENTRYPOINT ["logos_chain_node"]
WORKDIR /home/user/nimbos/build

STOPSIGNAL SIGINT
