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

# Common bash functions for running and listing tests.

declare -a skip_dirs=("env2" "env3" "htmlcov2" "htmlcov3" "build" "dist")

function dirs_to_search {
    local __retval="$1"
    eval "$__retval=()"
    for d in $(\ls); do
	if [ ! -d "$d" ]; then continue; fi
	local __skip_dir=0
	for sd in "${skip_dirs[@]}"; do
	    if [ "$sd" == "$d" ]; then __skip_dir=1; break; fi
	done
	if [ $__skip_dir -eq 1 ]; then continue; fi
	eval $__retval="( \"\${$__retval[@]}\" \"$d\" )"
    done
}
