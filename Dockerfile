
ARG BUILDPLATFORM=amd64

FROM --platform=$BUILDPLATFORM hub.yzw.cn/infra/apisix-official-base:3.2.1.1
USER root

COPY apisix /usr/local/apisix/apisix

COPY apisix-java-plugin-runner-exec.jar /usr/local/plugin-runner/




