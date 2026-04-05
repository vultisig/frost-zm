.PHONY: build-frozts build-fromt build-rust build-go-frozts build-go-fromt build-go \
       build-frozts-linux-amd64 build-frozts-linux-arm64 build-fromt-linux-amd64 build-fromt-linux-arm64 \
       build-wasm-frozts build-wasm-fromt \
       test-rust test-go-frozts test-go-fromt test-go test test-all \
       docker-keygen docker-sign clean

# --- Rust builds ---

build-frozts:
	cargo build --release -p frozts-lib

build-fromt:
	cargo build --release -p fromt-lib

build-rust: build-frozts build-fromt

# --- Go builds ---

build-go-frozts: build-frozts
	mkdir -p go/frozts/includes/darwin go/frozts/includes/linux-amd64 go/frozts/includes/linux-arm64
	@if [ "$$(uname)" = "Darwin" ]; then \
		cp target/release/libfroztslib.dylib go/frozts/includes/darwin/; \
	else \
		ARCH=$$(uname -m); \
		if [ "$$ARCH" = "x86_64" ]; then \
			cp target/release/libfroztslib.so go/frozts/includes/linux-amd64/; \
		elif [ "$$ARCH" = "aarch64" ]; then \
			cp target/release/libfroztslib.so go/frozts/includes/linux-arm64/; \
		fi; \
	fi
	cp crates/frozts-lib/include/frozts-lib.h go/frozts/includes/
	cd go && go build ./frozts/...

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

build-go: build-go-frozts build-go-fromt

# --- Cross-compilation ---

build-frozts-linux-amd64:
	cargo build --release -p frozts-lib --target x86_64-unknown-linux-gnu
	mkdir -p go/frozts/includes/linux-amd64
	cp target/x86_64-unknown-linux-gnu/release/libfroztslib.so go/frozts/includes/linux-amd64/
	cp crates/frozts-lib/include/frozts-lib.h go/frozts/includes/

build-frozts-linux-arm64:
	cargo build --release -p frozts-lib --target aarch64-unknown-linux-gnu
	mkdir -p go/frozts/includes/linux-arm64
	cp target/aarch64-unknown-linux-gnu/release/libfroztslib.so go/frozts/includes/linux-arm64/
	cp crates/frozts-lib/include/frozts-lib.h go/frozts/includes/

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

build-wasm-frozts:
	cd crates/frozts-wasm && wasm-pack test --node

build-wasm-fromt:
	wasm-pack build crates/fromt-wasm --target web --out-dir ../../pkg/fromt

# --- Tests ---

test-rust:
	cargo test --workspace

test-go-frozts: build-go-frozts
	cd go && go test -v ./frozts/...

test-go-fromt: build-go-fromt
	cd go && go test -v ./fromt/...

test-go: test-go-frozts test-go-fromt

test: test-rust test-go

test-all: test-rust test-go build-wasm-frozts build-wasm-fromt

# --- Client ---

docker-keygen:
	cd client/frozts && ./scripts/run-keygen.sh $(SESSION)

docker-sign:
	cd client/frozts && ./scripts/run-sign.sh $(SESSION) "$(MESSAGE)" "$(SIGNERS)"

# --- Clean ---

clean:
	cargo clean
	rm -f go/frozts/includes/darwin/libfroztslib.dylib
	rm -f go/frozts/includes/linux-amd64/libfroztslib.so
	rm -f go/frozts/includes/linux-arm64/libfroztslib.so
	rm -f go/fromt/includes/darwin/libfromtlib.dylib
	rm -f go/fromt/includes/linux-amd64/libfromtlib.so
	rm -f go/fromt/includes/linux-arm64/libfromtlib.so
