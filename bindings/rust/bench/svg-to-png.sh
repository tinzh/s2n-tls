#!/bin/bash

set -e

if [ $# -eq 0 ]
then
    echo "need filepath"
    exit 1
fi


pushd "$1" > /dev/null

mkdir -p png

for svg_path in `find . | grep report/violin.svg`
do
    flat_png_name=png/"$(echo $svg_path | sed 's|.\/|| ; s|\/report\/violin|| ; s|\/|-|g ; s|svg|png|')"
    rsvg-convert -h 1000 $svg_path > $flat_png_name
    convert $flat_png_name -crop 3550x760+1700+140 $flat_png_name
    convert $flat_png_name -trim $flat_png_name
done