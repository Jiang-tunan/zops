## Process this file with automake to produce Makefile.in

EXTRA_DIST = .

BUILD_TIME=`date +%H:%M:%S`
BUILD_DATE=`date +"%b %_d %Y"`
GOOS=`go env GOOS`
GOARCH=`go env GOARCH`
PKG=zeroops.cn/pkg/version
NEW_FROM_REV=""

GOLDFLAGS = -X '${PKG}.compileDate=${BUILD_DATE}'
GOLDFLAGS += -X ${PKG}.compileTime=${BUILD_TIME}
GOLDFLAGS += -X ${PKG}.compileOs=${GOOS}
GOLDFLAGS += -X ${PKG}.compileArch=${GOARCH}

AGENT_GOLDFLAGS = ${GOLDFLAGS}
AGENT_GOLDFLAGS += -X main.confDefault=${AGENT2_CONFIG_FILE}
AGENT_GOLDFLAGS += -X main.applicationName=zops_agent2

WEBSERVICE_GOLDFLAGS = ${GOLDFLAGS}
WEBSERVICE_GOLDFLAGS += -X main.applicationName=zops_web_service

if HAVE_PCRE
AGENT_GOTAGS = pcre
endif

if HAVE_PCRE2
AGENT_GOTAGS = pcre2
endif

dist_sysconf_DATA =
TARGETS =
INSTALL_TARGETS =

if AGENT2
TARGETS += zeroops.cn/cmd/zops_agent2
INSTALL_TARGETS += install-zeroops.cn/cmd/zops_agent2
DBGTARGETS = zeroops.cn/cmd/mock_server
dist_sysconf_DATA += conf/zops_agent2.conf
endif

if WEBSERVICE
TARGETS += zeroops.cn/cmd/zops_web_service
INSTALL_TARGETS += install-zeroops.cn/cmd/zops_web_service
dist_sysconf_DATA += conf/zops_web_service.conf
endif

all: build

zeroops.cn/cmd/zops_agent2:
	CGO_CFLAGS="${CGO_CFLAGS}" CGO_LDFLAGS="${CGO_LDFLAGS}" go build -tags="${AGENT_GOTAGS}" -ldflags="${AGENT_GOLDFLAGS}" -o bin zeroops.cn/cmd/zops_agent2

zeroops.cn/cmd/zops_web_service:
	go build -ldflags="${WEBSERVICE_GOLDFLAGS}" -o bin zeroops.cn/cmd/zops_web_service

build: ${TARGETS}

clean:
	go clean ./...
	rm -f bin/zops_agent2 bin/mock_server

install-zeroops.cn/cmd/zops_agent2:
	CGO_CFLAGS="${CGO_CFLAGS}" CGO_LDFLAGS="${CGO_LDFLAGS}" GOBIN=${GOBIN} \
		go install -ldflags="${AGENT_GOLDFLAGS}" ${TARGETS}
	$(MKDIR_P) "$(DESTDIR)$(AGENT2_CONFIG_PLUGINS_PATH)"
	test -f "$(DESTDIR)$(AGENT2_CONFIG_FILE)" || cp "conf/zops_agent2.conf" "$(DESTDIR)$(AGENT2_CONFIG_FILE)"
	for cfg in conf/zops_agent2.d/plugins.d/*.conf; do \
		test -f "$(DESTDIR)$(AGENT2_CONFIG_PLUGINS_PATH)/"`basename $$cfg` || \
		cp "$$cfg" "$(DESTDIR)$(AGENT2_CONFIG_PLUGINS_PATH)/"`basename $$cfg`; \
	done

install-zeroops.cn/cmd/zops_web_service:
	GOBIN=${GOBIN} go install -ldflags="${WEBSERVICE_GOLDFLAGS}" zeroops.cn/cmd/zops_web_service

install-exec-local: ${INSTALL_TARGETS}

check:
	CGO_CFLAGS="${CGO_CFLAGS}" CGO_LDFLAGS="${CGO_LDFLAGS}" go test ./...
style:
	CGO_CFLAGS="${CGO_CFLAGS}" CGO_LDFLAGS="${CGO_LDFLAGS}" golangci-lint run --new-from-rev=$(NEW_FROM_REV)  ./...
format:
	CGO_CFLAGS="${CGO_CFLAGS}" CGO_LDFLAGS="${CGO_LDFLAGS}" go fmt ./... 
