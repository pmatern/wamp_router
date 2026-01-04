#!/bin/bash
# Script to add Apache 2.0 license headers to all source files

set -e

LICENSE_HEADER="// Copyright 2026 Patrick Matern
//
// Licensed under the Apache License, Version 2.0 (the \"License\");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an \"AS IS\" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

"

# Find all .cpp and .hpp files, excluding build directories
find . -name "*.cpp" -o -name "*.hpp" | \
  grep -v "/build" | \
  grep -v "/vcpkg" | \
  grep -v "/cmake-build" | \
while read -r file; do
  # Check if file already has Apache license header
  if ! head -n 1 "$file" | grep -q "Copyright.*Patrick Matern"; then
    echo "Adding license header to: $file"
    # Create temp file with header + original content
    echo "$LICENSE_HEADER" > "$file.tmp"
    cat "$file" >> "$file.tmp"
    mv "$file.tmp" "$file"
  else
    echo "Skipping (already has header): $file"
  fi
done

echo "Done! License headers added to all source files."
