TEST_TIMEOUT?=30s

.PHONY: lint
lint:
	golint ./...

.PHONY: release
release:
	curl -sL https://raw.githubusercontent.com/radekg/git-release/master/git-release --output /tmp/git-release
	chmod +x /tmp/git-release
	/tmp/git-release --repository-path=${GOPATH}/src/github.com/combust-labs/firebuild-embedded-ca
	rm -rf /tmp/git-release

.PHONY: test-verbose
test-verbose:
	go clean -testcache
	go test -timeout ${TEST_TIMEOUT} -cover -v ./...