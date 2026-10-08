FROM debian:stable-slim@sha256:04634311a8d5fc442b6eb06d792293c4f3e2268652ca7634e00ce8ef5cc0a28a

LABEL org.opencontainers.image.title="PAO minimal audit runtime"
LABEL org.opencontainers.image.description="PAO-controlled minimal Debian Slim base; scanner tools are mounted read-only"
LABEL org.opencontainers.image.source="https://github.com/sSOFTINn/ProjectAuditOrchestrator"

# Only the runtime library required by the dynamically linked zizmor binary is retained. The other
# Go-based tools are statically linked; scanner binaries remain read-only mounts.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

# DockerHost mounts tools and the owned supervisor read-only and sets the supervisor entrypoint
# for each audit run. Building a new image requires separate preparation and exact approval.
