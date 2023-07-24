#!/bin/bash

# needs: imagemagick, librsvg2-bin

set -e

pushd "$(dirname "$0")" > /dev/null
cd target/criterion

mkdir -p png

for svg_path in `find . | grep report/violin.svg`
do
    bench_group_name="$(echo "$svg_path" | sed 's|.\/|| ; s|\/report\/violin.svg||')"
    sed "s|$bench_group_name\/|| ; s|Input||" "$svg_path" > temp.svg
    flat_png_name=png/"$(echo $svg_path | sed 's|.\/|| ; s|\/report\/violin|| ; s|\/|-|g ; s|svg|png|')"
    rsvg-convert -h 1000 temp.svg > "$flat_png_name"
    convert "$flat_png_name" -trim "$flat_png_name"
done

popd