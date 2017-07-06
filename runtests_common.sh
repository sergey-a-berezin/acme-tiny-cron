# Copyright 2016 Sergey Berezin, sergey@sergeyberezin.com

# Common bash functions for running and listing tests.

declare -a skip_dirs=("env2" "env3" "htmlcov2" "htmlcov3" "experimental" "luci-py")

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
