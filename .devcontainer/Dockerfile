# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.238.0/containers/debian/.devcontainer/base.Dockerfile

ARG VARIANT="buster"
ARG HUGOVERSION='0.80.0'
FROM mcr.microsoft.com/vscode/devcontainers/base:0-${VARIANT}

ARG HUGOVERSION

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends curl \
    #
    # Add Hugo
    && curl -sk "https://github.com/gohugoio/hugo/releases/download/v${HUGOVERSION}/hugo_${HUGOVERSION}_Linux-64bit.tar.gz" -L -o /tmp/hugo.tar.gz \
    && tar -zxf /tmp/hugo.tar.gz -C /tmp/ \
    && mv /tmp/hugo /usr/local/bin/hugo \
    && rm -rf /tmp/* \
    #
    # Clean up
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/* /go/src
