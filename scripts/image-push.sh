#!/usr/bin/env bash
#
# 构建并推送 LocalCA 镜像到 Harbor。
#
#   scripts/image-push.sh              # 用版本号 + latest 推送
#   scripts/image-push.sh 2.0.1        # 指定 tag
#   HARBOR_PROJECT=other scripts/image-push.sh
#
# 默认推到 **crequency** 项目：
#   registry.services.nimatattic.net/crequency/local-ca
#
# 前置：
#   1. 已登录：docker login registry.services.nimatattic.net
#   2. 账号对该项目有推送权限（本机 ~/.docker/config.json 里已有登录记录时不必重复登录）
#
# 说明：这个镜像只含**应用**（Django + gunicorn + 构建好的 SPA），它监听 8000，
# 不提供静态文件；静态文件由同卷的 nginx 提供，所以部署还需要 nginx 镜像
# （本仓库 Dockerfile.nginx，以 nginx:alpine + nginx.conf 为基础，几十 KB）。
# 对外的 80 端口由 nginx 暴露，见 docker-compose-from-registry.yml。

set -euo pipefail

HARBOR_HOST="${HARBOR_HOST:-registry.services.nimatattic.net}"
HARBOR_PROJECT="${HARBOR_PROJECT:-crequency}"
IMAGE_NAME="${IMAGE_NAME:-local-ca}"
PUSH_LATEST="${PUSH_LATEST:-1}"

cd "$(dirname "$0")/.."

# frontend/package.json 是仓库里唯一的版本号来源；读不到时退回 git 短修订号。
VERSION="$(node -p "require('./frontend/package.json').version" 2>/dev/null \
	|| git rev-parse --short HEAD)"
TAG="${1:-$VERSION}"
LOCAL_IMAGE="${IMAGE_NAME}:local"
REMOTE_IMAGE="${HARBOR_HOST}/${HARBOR_PROJECT}/${IMAGE_NAME}"

echo ">>> 构建 ${LOCAL_IMAGE}（多阶段：Node 构建 SPA → Python 运行阶段）"
docker build -t "$LOCAL_IMAGE" .

echo ">>> 打标签 ${REMOTE_IMAGE}:${TAG}"
docker tag "$LOCAL_IMAGE" "${REMOTE_IMAGE}:${TAG}"

# Harbor 前面是 openresty，它先收完整个请求体再转发，于是 ~85MB 以上的层偶发
# "timeout awaiting response headers"（实测：41MB 稳定通过，86MB 时好时坏）。
# 已经上传成功的层在重试时会被跳过，所以重试确实有效，而且越试越轻。
push_with_retries() {
	local ref="$1" attempts="${PUSH_RETRIES:-4}" attempt=0
	while ! docker push "$ref"; do
		attempt=$((attempt + 1))
		if [ "$attempt" -ge "$attempts" ]; then
			echo "!!! 推送 $ref 连续失败 $attempts 次，放弃" >&2
			return 1
		fi
		echo "!!! 推送失败（第 $attempt 次），5 秒后重试；已上传的层会被跳过"
		sleep 5
	done
}

echo ">>> 推送 ${REMOTE_IMAGE}:${TAG}"
push_with_retries "${REMOTE_IMAGE}:${TAG}"

if [ "$PUSH_LATEST" = "1" ] && [ "$TAG" != "latest" ]; then
	echo ">>> 推送 ${REMOTE_IMAGE}:latest"
	docker tag "$LOCAL_IMAGE" "${REMOTE_IMAGE}:latest"
	push_with_retries "${REMOTE_IMAGE}:latest"
fi

echo
echo ">>> 完成。本机跑起来（含 nginx，按仓库里的 compose）："
echo "    docker compose -f docker-compose-from-registry.yml up -d"
echo "    或只跑应用容器（需自行提供静态文件服务）："
echo "    docker run --rm -p 8000:8000 \\"
echo "      -e DJANGO_SECRET_KEY=\$(python3 -c 'import secrets;print(secrets.token_urlsafe(50))') \\"
echo "      -e DJANGO_ALLOWED_HOSTS=127.0.0.1 \\"
echo "      ${REMOTE_IMAGE}:${TAG}"
