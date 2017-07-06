#!/bin/bash
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

cat <<EOF

Bootstrap is complete!

To activate Python2.7 environment, run:      source env2/bin/activate
To activate Python3.x environment, run:      source env3/bin/activate
To deactivate the current environment, run:  deactivate

Note: nested environments are NOT supported.
EOF
