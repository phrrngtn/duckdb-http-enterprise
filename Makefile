.PHONY: clean clean_all

PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Main extension configuration
EXTENSION_NAME=http_client

# Set to 1 to enable Unstable API (binaries will only work on TARGET_DUCKDB_VERSION, forwards compatibility will be broken)
USE_UNSTABLE_C_API=0

# The DuckDB version to target
TARGET_DUCKDB_VERSION=v1.2.0

# Use uv instead of configure/venv for all Python invocations
PYTHON_VENV_BIN=uv run python

all: configure release

# Include makefiles from DuckDB
include extension-ci-tools/makefiles/c_api_extensions/base.Makefile
include extension-ci-tools/makefiles/c_api_extensions/c_cpp.Makefile

configure: venv platform extension_version

# Override the upstream venv target — uv sync manages the virtualenv
venv:
	uv sync --python 3.12
	@mkdir -p configure/venv

# Override check_configure — no configure/venv needed with uv
check_configure:
	@$(PYTHON_BIN) -c "import os; assert os.path.exists('configure/platform.txt'), 'Run make configure first'"

debug: build_extension_library_debug build_extension_with_metadata_debug
release: build_extension_library_release build_extension_with_metadata_release

test: test_debug
test_debug: test_extension_debug
test_release: test_extension_release

clean: clean_build clean_cmake
clean_all: clean clean_configure
