BUILD_CGO_ENABLED  := 1
SERVICE_NAME       := lmd-ng
REBASE_URL         := "github.com/dimaskiddo/lmd-ng"
COMMIT_MSG         := "update improvement"

VERSION_GIT := $(shell git describe --tags --always 2>/dev/null | sed -e 's|^v||g')
VERSION     := $(if $(VERSION_GIT),$(VERSION_GIT),dev)

COMMIT_GIT  := $(shell git rev-parse --short HEAD 2>/dev/null)
COMMIT      := $(if $(COMMIT_GIT),$(COMMIT_GIT),none)

.PHONY:

.SILENT:

init:
	make clean
	GO111MODULE=on go mod init

init-dist:
	mkdir -p dist

vendor:
	make clean
	GO111MODULE=on go mod tidy
	GO111MODULE=on go mod vendor

release:
	make vendor
	make clean-dist
	goreleaser release --parallelism 1 --rm-dist --snapshot --skip-publish
	rm -f ./*.o
	echo "Release '$(SERVICE_NAME)' complete, please check dist directory."

publish:
	make vendor
	make clean-dist
	GITHUB_TOKEN=$(GITHUB_TOKEN) goreleaser release --parallelism 1 --rm-dist
	rm -f ./*.o
	echo "Publish '$(SERVICE_NAME)' complete, please check your repository releases."

build:
	make vendor
	make init-dist
	CC="\"$(PWD)/hack/zcc.sh\"" CXX="\"$(PWD)/hack/zcxx.sh\"" CGO_ENABLED=$(BUILD_CGO_ENABLED) go build -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)" -trimpath -a -o dist/$(SERVICE_NAME) ./cmd/lmd-ng
	rm -f ./*.o
	echo "Build '$(SERVICE_NAME)' complete."

docker-build:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t dimaskiddo/lmd-ng:v$(VERSION) .
	echo "Docker Build '$(SERVICE_NAME)' complete."

run:
	make vendor
	go run *.go

clean-dist:
	rm -rf dist

clean-build:
	rm -rf logs
	rm -rf certs
	rm -rf quarantine
	rm -rf clamav
	rm -rf sigs
	rm -f config.yaml
	rm -f $(SERVICE_NAME).sock
	rm -f $(SERVICE_NAME)

clean:
	make clean-dist
	make clean-build
	rm -rf vendor
	rm -f ./*.o

commit:
	make vendor
	make clean
	git add .
	git commit -am $(COMMIT_MSG)

rebase:
	rm -rf .git
	find . -type f -iname "*.go*" -exec sed -i '' -e "s%github.com/dimaskiddo/lmd-ng%$(REBASE_URL)%g" {} \;
	git init
	git remote add origin https://$(REBASE_URL).git

push:
	git push origin master

pull:
	git pull origin master
