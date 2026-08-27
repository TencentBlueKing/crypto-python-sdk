UV ?= uv
# 3.6.12
# 3.7.12
# 3.8.12
# 3.9.13
# 3.10.5
# 3.11.10
# 3.12.7
# 3.13.5
# 3.14.0
PYTHON_VERSION ?= 3.12.7
UV_VERSION ?= 0.11.21
IMAGE_VERSION ?= "dev"
IMAGE_REPO ?= "mirrors.tencent.com/bk-crypto-python-sdk"

install:
	$(UV) sync --all-extras --group dev

lint:
	$(UV) run ruff format --check .
	$(UV) run ruff check .
	$(UV) run mypy bkcrypto tests
	$(UV) run pyright

# 打包的目标
build:
	$(UV) build

# 上传到 PyPI 的目标
upload:
	$(UV) publish

# 上传到 PyPI 测试环境的目标
upload_test:
	$(UV) publish --publish-url https://test.pypi.org/legacy/

# 设置默认目标：安装依赖、构建并上传到 PyPI
.PHONY: default
default: install build upload

docker-build-local:
	docker build -t ${IMAGE_REPO}:${IMAGE_VERSION}-${PYTHON_VERSION} \
	--build-arg PYTHON_VERSION=${PYTHON_VERSION} \
	--build-arg UV_VERSION=${UV_VERSION} .
