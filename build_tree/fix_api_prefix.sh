#!/bin/bash

# path
SEARCH_DIR=$(pwd)

# Check if NEW_LIB_PREFIX is provided as an argument
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: please security lib prefix and your app name"
    echo "Ex: ./fix_api_prefix commonsec commonapp"
    exit 1
fi

function fChangeLibName()
{
    OLD_LIB_PREFIX=$1_
    NEW_LIB_PREFIX=$2_

    OLD_LIB_PREFIX_UP=$(echo "$OLD_LIB_PREFIX" | tr '[:lower:]' '[:upper:]')
    NEW_LIB_PREFIX_UP=$(echo "$NEW_LIB_PREFIX" | tr '[:lower:]' '[:upper:]')

    # step1: sed (.c, .h, Makefile)
    find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_LIB_PREFIX/$NEW_LIB_PREFIX/g" {} +
    find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_LIB_PREFIX_UP/$NEW_LIB_PREFIX_UP/g" {} +

    # step2: fix file name
    find "$SEARCH_DIR" -type f -name "*$OLD_LIB_PREFIX*" | while read FILE; do
        RENAMED_FILE=$(echo "$FILE" | sed "s/$OLD_LIB_PREFIX/$NEW_LIB_PREFIX/g")
        mv "$FILE" "$RENAMED_FILE"
    done
}


function fChangeAppInterfaceName()
{
    OLD_TAG=$1
    NEW_TAG=$2

    NEW_APP_PREFIX=$1_
    OLD_APP_PREFIX=${OLD_TAG}_

    NEW_APP_PREFIX_UP=$(echo "$NEW_APP_PREFIX" | tr '[:lower:]' '[:upper:]')
    OLD_APP_PREFIX_UP=$(echo "$OLD_APP_PREFIX" | tr '[:lower:]' '[:upper:]')

    NEW_APP_PREFIX_HEAD=$(echo "$NEW_TAG" | sed 's/.*/\L&/; s/[a-z]*/\u&/g')
    OLD_APP_PREFIX_HEAD=$(echo "$OLD_TAG" | sed 's/.*/\L&/; s/[a-z]*/\u&/g')

    # step1: sed (.c, .h, Makefile)
    find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "*.mk" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_TAG/$NEW_TAG/g" {} +
    find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "*.mk" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_APP_PREFIX/$NEW_APP_PREFIX/g" {} +
    find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "*.mk" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_APP_PREFIX_UP/$NEW_APP_PREFIX_UP/g" {} +
    find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "*.mk" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_APP_PREFIX_HEAD/$NEW_APP_PREFIX_HEAD/g" {} +

    # step2: fix file name
    find "$SEARCH_DIR" -type f -name "*$OLD_TAG*" | while read FILE; do
        RENAMED_FILE=$(echo "$FILE" | sed "s/$OLD_TAG/$NEW_TAG/g")
        mv "$FILE" "$RENAMED_FILE"
    done
}

fChangeLibName customization $1
fChangeAppInterfaceName custapp $2


