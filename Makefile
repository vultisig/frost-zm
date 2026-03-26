.PHONY: build-frobt build-froeth build-frosst build-fromt build-frozt build-rust \
       build-go-frobt build-go-froeth build-go-frosst build-go-fromt build-go-frozt build-go \
       build-frozt-linux-amd64 build-frozt-linux-arm64 build-fromt-linux-amd64 build-fromt-linux-arm64 \
       build-wasm-frozt build-wasm-fromt build-wasm-frosst \
       test-rust test-go-frozt test-go-fromt test-go test test-all test-wasm \
       docker-keygen docker-sign clean

# --- Rust builds ---

build-frobt:
	cargo build --release -p frobt

build-froeth:
	cargo build --release -p froeth

build-frosst:
	cargo build --release -p frosst

build-fromt:
	cargo build --release -p fromt

build-frozt:
	cargo build --release -p frozt

build-rust: build-frobt build-froeth build-frosst build-fromt build-frozt

# --- Go builds ---

build-go-frobt: build-frobt
	mkdir -p go/frobt/includes/darwin go/frobt/includes/linux-amd64 go/frobt/includes/linux-arm64
	@if [ "$$(uname)" = "Darwin" ]; then \
		cp target/release/libfrobtlib.dylib go/frobt/includes/darwin/; \
	else \
		ARCH=$$(uname -m); \
		if [ "$$ARCH" = "x86_64" ]; then \
			cp target/release/libfrobtlib.so go/frobt/includes/linux-amd64/; \
		elif [ "$$ARCH" = "aarch64" ]; then \
			cp target/release/libfrobtlib.so go/frobt/includes/linux-arm64/; \
		fi; \
	fi
	cp crates/frobt/include/frobt-lib.h go/frobt/includes/ 2>/dev/null || true
	cd go && go build ./frobt/...

build-go-froeth: build-froeth
	mkdir -p go/froeth/includes/darwin go/froeth/includes/linux-amd64 go/froeth/includes/linux-arm64
	@if [ "$$(uname)" = "Darwin" ]; then \
		cp target/release/libfroethlib.dylib go/froeth/includes/darwin/; \
	else \
		ARCH=$$(uname -m); \
		if [ "$$ARCH" = "x86_64" ]; then \
			cp target/release/libfroethlib.so go/froeth/includes/linux-amd64/; \
		elif [ "$$ARCH" = "aarch64" ]; then \
			cp target/release/libfroethlib.so go/froeth/includes/linux-arm64/; \
		fi; \
	fi
	cd go && go build ./froeth/...

build-go-frosst: build-frosst
	mkdir -p go/frosst/includes/darwin go/frosst/includes/linux-amd64 go/frosst/includes/linux-arm64
	@if [ "$$(uname)" = "Darwin" ]; then \
		cp target/release/libfrosstlib.dylib go/frosst/includes/darwin/; \
	else \
		ARCH=$$(uname -m); \
		if [ "$$ARCH" = "x86_64" ]; then \
			cp target/release/libfrosstlib.so go/frosst/includes/linux-amd64/; \
		elif [ "$$ARCH" = "aarch64" ]; then \
			cp target/release/libfrosstlib.so go/frosst/includes/linux-arm64/; \
		fi; \
	fi
	cd go && go build ./frosst/...

build-go-fromt: build-fromt
	mkdir -p go/fromt/includes/darwin go/fromt/includes/linux-amd64 go/fromt/includes/linux-arm64
	@if [ "$$(uname)" = "Darwin" ]; then \
		cp target/release/libfromtlib.dylib go/fromt/includes/darwin/; \
	else \
		ARCH=$$(uname -m); \
		if [ "$$ARCH" = "x86_64" ]; then \
			cp target/release/libfromtlib.so go/fromt/includes/linux-amd64/; \
		elif [ "$$ARCH" = "aarch64" ]; then \
			cp target/release/libfromtlib.so go/fromt/includes/linux-arm64/; \
		fi; \
	fi
	cp crates/fromt/include/fromt-lib.h go/fromt/includes/ 2>/dev/null || true
	cd go && go build ./fromt/...

build-go-frozt: build-frozt
	mkdir -p go/frozt/includes/darwin go/frozt/includes/linux-amd64 go/frozt/includes/linux-arm64
	@if [ "$$(uname)" = "Darwin" ]; then \
		cp target/release/libfroztlib.dylib go/frozt/includes/darwin/; \
	else \
		ARCH=$$(uname -m); \
		if [ "$$ARCH" = "x86_64" ]; then \
			cp target/release/libfroztlib.so go/frozt/includes/linux-amd64/; \
		elif [ "$$ARCH" = "aarch64" ]; then \
			cp target/release/libfroztlib.so go/frozt/includes/linux-arm64/; \
		fi; \
	fi
	cp crates/frozt/include/frozt-lib.h go/frozt/includes/
	cd go && go build ./frozt/...

build-go: build-go-frobt build-go-froeth build-go-frosst build-go-fromt build-go-frozt

# --- Cross-compilation ---

build-frozt-linux-amd64:
	cargo build --release -p frozt --target x86_64-unknown-linux-gnu
	mkdir -p go/frozt/includes/linux-amd64
	cp target/x86_64-unknown-linux-gnu/release/libfroztlib.so go/frozt/includes/linux-amd64/
	cp crates/frozt/include/frozt-lib.h go/frozt/includes/

build-frozt-linux-arm64:
	cargo build --release -p frozt --target aarch64-unknown-linux-gnu
	mkdir -p go/frozt/includes/linux-arm64
	cp target/aarch64-unknown-linux-gnu/release/libfroztlib.so go/frozt/includes/linux-arm64/
	cp crates/frozt/include/frozt-lib.h go/frozt/includes/

build-fromt-linux-amd64:
	cargo build --release -p fromt --target x86_64-unknown-linux-gnu
	mkdir -p go/fromt/includes/linux-amd64
	cp target/x86_64-unknown-linux-gnu/release/libfromtlib.so go/fromt/includes/linux-amd64/
	cp crates/fromt/include/fromt-lib.h go/fromt/includes/ 2>/dev/null || true

build-fromt-linux-arm64:
	cargo build --release -p fromt --target aarch64-unknown-linux-gnu
	mkdir -p go/fromt/includes/linux-arm64
	cp target/aarch64-unknown-linux-gnu/release/libfromtlib.so go/fromt/includes/linux-arm64/
	cp crates/fromt/include/fromt-lib.h go/fromt/includes/ 2>/dev/null || true

# --- WASM builds ---

build-wasm-frozt:
	cd crates/frozt-wasm && wasm-pack test --node

build-wasm-fromt:
	wasm-pack build crates/fromt-wasm --target web --out-dir ../../pkg/fromt

build-wasm-frosst:
	wasm-pack build crates/frosst-wasm --target web --out-dir ../../pkg/frosst

# --- Tests ---

test-rust:
	cargo test --workspace

test-go-frozt: build-go-frozt
	cd go && go test -v ./frozt/...

test-go-fromt: build-go-fromt
	cd go && go test -v ./fromt/...

test-go: test-go-frozt test-go-fromt

test: test-rust test-go

test-all: test-rust test-go build-wasm-frozt build-wasm-fromt build-wasm-frosst

# --- Client ---

docker-keygen:
	cd client/frozt && ./scripts/run-keygen.sh $(SESSION)

docker-sign:
	cd client/frozt && ./scripts/run-sign.sh $(SESSION) "$(MESSAGE)" "$(SIGNERS)"

# --- Clean ---

clean:
	cargo clean
	rm -f go/frobt/includes/darwin/libfrobtlib.dylib
	rm -f go/froeth/includes/darwin/libfroethlib.dylib
	rm -f go/frosst/includes/darwin/libfrosstlib.dylib
	rm -f go/frozt/includes/darwin/libfroztlib.dylib
	rm -f go/frozt/includes/linux-amd64/libfroztlib.so
	rm -f go/frozt/includes/linux-arm64/libfroztlib.so
	rm -f go/fromt/includes/darwin/libfromtlib.dylib
	rm -f go/fromt/includes/linux-amd64/libfromtlib.so
	rm -f go/fromt/includes/linux-arm64/libfromtlib.so
