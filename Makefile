# Copyright 2017 Sergey Berezin

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

all:
	@echo "Nothing to do. Pick a specific target."

test:
	./runtests

build: build_proto
build_proto:
	protoc acme_tiny_cron/protos/domains.proto --python_out .

init:
	./bootstrap
	@./bootstrap_done.sh

clean:
	find . -name "*.pyc" -delete
	rm -rf htmlcov2 htmlcov3 .coverage

pristine: clean pristine-python
	@echo "Everything is pristine clean."

pristine-python:
	rm -rf python/env2 python/env3
