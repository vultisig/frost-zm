/*
 * frosty-lib CI Pipeline
 *
 * GitHub repo: https://github.com/Rotwang9000/frosty-lib
 *
 * The local Jenkins job checks out this repo from /home/rotwang/wbdev/frosty-lib
 * (origin points at the GitHub repo). Orchard/main builds validate the Rust,
 * Go and WASM surfaces, archive the native libraries, then trigger WebZjs'
 * staging branch so the consumer chain can continue through Jenkins.
 */

pipeline {
	agent any

	environment {
		PATH = "/home/rotwang/.cargo/bin:/usr/local/go/bin:/usr/local/bin:${env.PATH}"
		RUSTUP_HOME = '/home/rotwang/.rustup'
		CARGO_HOME = '/home/rotwang/.cargo'
		CARGO_TARGET_DIR = "${env.WORKSPACE}/target"
	}

	options {
		buildDiscarder(logRotator(numToKeepStr: '10', artifactNumToKeepStr: '5'))
		timeout(time: 60, unit: 'MINUTES')
		timestamps()
		disableConcurrentBuilds()
	}

	stages {
		stage('Toolchain Check') {
			steps {
				sh '''
					echo "Branch:    ${BRANCH_NAME:-$GIT_BRANCH}"
					echo "Commit:    $(git rev-parse --short HEAD || echo n/a)"
					echo "Go:        $(go version 2>/dev/null || echo NOT_FOUND)"
					echo "wasm-pack: $(wasm-pack --version 2>/dev/null || echo NOT_FOUND)"

					for cmd in rustup cargo go wasm-pack make; do
						if ! command -v "$cmd" >/dev/null 2>&1; then
							echo "ERROR: required toolchain component '$cmd' is missing"
							exit 1
						fi
					done

					# Make sure the toolchain pinned in rust-toolchain.toml is
					# actually installed BEFORE the first cargo invocation, so
					# the build does not race rustup auto-install (which can
					# silently fall back to "stable" if the network blip and
					# leave us on the wrong rustc).
					PINNED=$(awk -F\\" "/^channel/ {print \\$2}" rust-toolchain.toml)
					if [ -z "$PINNED" ]; then
						echo "ERROR: could not read pinned channel from rust-toolchain.toml"
						exit 1
					fi
					echo "Pinned:    $PINNED"
					rustup toolchain install "$PINNED" \
						--profile minimal \
						--component rustfmt --component clippy \
						--target wasm32-unknown-unknown \
						--no-self-update
					echo "Rust:      $(rustc --version)"
					echo "Cargo:     $(cargo --version)"
				'''
			}
		}

		stage('Rust Quality Gates') {
			parallel {
				stage('Format') {
					steps {
						sh 'cargo fmt --all -- --check'
					}
				}
				stage('Clippy') {
					steps {
						sh 'cargo clippy --workspace --all-targets -- -D warnings'
					}
				}
			}
		}

		stage('Rust Tests') {
			steps {
				sh 'cargo test --workspace'
			}
		}

		stage('Go Bindings') {
			steps {
				sh 'make build-go'
			}
		}

		stage('WASM Checks') {
			when {
				anyOf { branch 'Orchard'; branch 'main' }
			}
			steps {
				sh '''
					make build-wasm-frozt
					make build-wasm-fromt
				'''
			}
		}

		stage('Archive Native Artefacts') {
			when {
				anyOf { branch 'Orchard'; branch 'main' }
			}
			steps {
				archiveArtifacts artifacts: [
					'target/release/libfroztlib.*',
					'target/release/libfromtlib.*',
					'go/frozt/includes/**/*',
					'go/fromt/includes/**/*',
					'packages/**/*'
				].join(','),
				fingerprint: true,
				onlyIfSuccessful: true,
				allowEmptyArchive: true
			}
		}

		stage('Trigger WebZjs Staging') {
			when {
				anyOf { branch 'Orchard'; branch 'main' }
			}
			steps {
				script {
					try {
						build job: 'WebZjs-transparent-fix', wait: false, propagate: false
						echo 'Triggered WebZjs-transparent-fix'
					} catch (err) {
						echo "Could not trigger WebZjs-transparent-fix (job not configured?): ${err}"
					}
				}
			}
		}
	}

	post {
		failure {
			echo "frosty-lib build FAILED — ${env.BRANCH_NAME ?: env.GIT_BRANCH} #${env.BUILD_NUMBER}"
		}
		success {
			echo "frosty-lib build succeeded — ${env.BRANCH_NAME ?: env.GIT_BRANCH} #${env.BUILD_NUMBER}"
		}
	}
}
