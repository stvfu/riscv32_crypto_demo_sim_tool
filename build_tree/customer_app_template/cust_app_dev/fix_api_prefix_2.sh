#!/bin/bash

# path
SEARCH_DIR=$(pwd)

OLD_TAG="custapp"
# Check if NEW_TAG is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 new_name_prefix"
    exit 1
fi
NEW_TAG=$1

NEW_NAME=$1_
OLD_NAME=${OLD_TAG}_

NEW_NAME_UP=$(echo "$NEW_NAME" | tr '[:lower:]' '[:upper:]')
OLD_NAME_UP=$(echo "$OLD_NAME" | tr '[:lower:]' '[:upper:]')

NEW_NAME_HEAD=$(echo "$NEW_TAG" | sed 's/.*/\L&/; s/[a-z]*/\u&/g')
OLD_NAME_HEAD=$(echo "$OLD_TAG" | sed 's/.*/\L&/; s/[a-z]*/\u&/g')

# step1: sed (.c, .h, Makefile)
find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "*.mk" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_TAG/$NEW_TAG/g" {} +
find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "*.mk" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_NAME/$NEW_NAME/g" {} +
find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "*.mk" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_NAME_UP/$NEW_NAME_UP/g" {} +
find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "*.mk" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_NAME_HEAD/$NEW_NAME_HEAD/g" {} +

# step2: fix file name
find "$SEARCH_DIR" -type f -name "*$OLD_TAG*" | while read FILE; do
    RENAMED_FILE=$(echo "$FILE" | sed "s/$OLD_TAG/$NEW_TAG/g")
    mv "$FILE" "$RENAMED_FILE"
done
