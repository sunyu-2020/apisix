
VERSION=2.0.7
cp /Users/sunyu/Documents/code/java/APISIX_PLUGIN/yzw-apisix-java-runner/target/apisix-java-plugin-runner-exec.jar .

docker buildx build -t hub.yzw.cn/infra/apisix-yzw:${VERSION} .

docker push hub.yzw.cn/infra/apisix-yzw:${VERSION}

rm -rf apisix-java-plugin-runner-exec.jar

