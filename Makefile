.PHONY: build-frozt build-fromt build-rust build-go-frozt build-go-fromt build-go \
       build-frozt-linux-amd64 build-frozt-linux-arm64 build-fromt-linux-amd64 build-fromt-linux-arm64 \
       build-wasm-frozt build-wasm-fromt \
       test-rust test-go-frozt test-go-fromt test-go test test-all test-wasm \
       docker-keygen docker-sign clean

# --- Rust builds ---

build-frozt:
	cargo build --release -p frozt-lib

build-fromt:
	cargo build --release -p fromt-lib

build-rust: build-frozt build-fromt

# --- Go builds ---

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
	cp crates/frozt-lib/include/frozt-lib.h go/frozt/includes/
	cd go && go build ./frozt/...

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
	cp crates/fromt-lib/include/fromt-lib.h go/fromt/includes/
	cd go && go build ./fromt/...

build-go: build-go-frozt build-go-fromt

# --- Cross-compilation ---

build-frozt-linux-amd64:
	cargo build --release -p frozt-lib --target x86_64-unknown-linux-gnu
	mkdir -p go/frozt/includes/linux-amd64
	cp target/x86_64-unknown-linux-gnu/release/libfroztlib.so go/frozt/includes/linux-amd64/
	cp crates/frozt-lib/include/frozt-lib.h go/frozt/includes/

build-frozt-linux-arm64:
	cargo build --release -p frozt-lib --target aarch64-unknown-linux-gnu
	mkdir -p go/frozt/includes/linux-arm64
	cp target/aarch64-unknown-linux-gnu/release/libfroztlib.so go/frozt/includes/linux-arm64/
	cp crates/frozt-lib/include/frozt-lib.h go/frozt/includes/

build-fromt-linux-amd64:
	cargo build --release -p fromt-lib --target x86_64-unknown-linux-gnu
	mkdir -p go/fromt/includes/linux-amd64
	cp target/x86_64-unknown-linux-gnu/release/libfromtlib.so go/fromt/includes/linux-amd64/
	cp crates/fromt-lib/include/fromt-lib.h go/fromt/includes/

build-fromt-linux-arm64:
	cargo build --release -p fromt-lib --target aarch64-unknown-linux-gnu
	mkdir -p go/fromt/includes/linux-arm64
	cp target/aarch64-unknown-linux-gnu/release/libfromtlib.so go/fromt/includes/linux-arm64/
	cp crates/fromt-lib/include/fromt-lib.h go/fromt/includes/

# --- WASM builds ---

build-wasm-frozt:
	cd crates/frozt-wasm && wasm-pack test --node

build-wasm-fromt:
	wasm-pack build crates/fromt-wasm --target web --out-dir ../../pkg/fromt

# --- Tests ---

test-rust:
	cargo test --workspace

test-go-frozt: build-go-frozt
	cd go && go test -v ./frozt/...

test-go-fromt: build-go-fromt
	cd go && go test -v ./fromt/...

test-go: test-go-frozt test-go-fromt

test: test-rust test-go

test-all: test-rust test-go build-wasm-frozt build-wasm-fromt

# --- Client ---

docker-keygen:
	cd client/frozt && ./scripts/run-keygen.sh $(SESSION)

docker-sign:
	cd client/frozt && ./scripts/run-sign.sh $(SESSION) "$(MESSAGE)" "$(SIGNERS)"

# --- Clean ---

clean:
	cargo clean
	rm -f go/frozt/includes/darwin/libfroztlib.dylib
	rm -f go/frozt/includes/linux-amd64/libfroztlib.so
	rm -f go/frozt/includes/linux-arm64/libfroztlib.so
	rm -f go/fromt/includes/darwin/libfromtlib.dylib
	rm -f go/fromt/includes/linux-amd64/libfromtlib.so
	rm -f go/fromt/includes/linux-arm64/libfromtlib.so
