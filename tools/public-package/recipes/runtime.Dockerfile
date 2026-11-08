FROM docker.io/library/python@sha256:05a994d2344eb364cc186910f4fc8786a38215f39f00d0acc25bff33a08f4177
LABEL org.opencontainers.image.title="PAO verified preparation and audit runtime"
LABEL org.opencontainers.image.source="https://github.com/sSOFTINn/ProjectAuditOrchestrator"
# The setup recipe fixes every .deb filename and hash. No apt repository or
# package resolver is contacted during this build.
COPY runtime-debs/ /pao-build/
RUN dpkg -i /pao-build/*.deb && rm -rf /pao-build
ENV PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1
