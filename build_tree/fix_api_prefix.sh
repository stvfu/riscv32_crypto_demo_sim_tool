#!/bin/bash

# path
SEARCH_DIR=$(pwd)

OLD_NAME="customization_"
# Check if NEW_NAME is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 new_name_prefix"
    exit 1
fi
NEW_NAME=$1_


NEW_NAME_UP=$(echo "$NEW_NAME" | tr '[:lower:]' '[:upper:]')
OLD_NAME_UP=$(echo "$OLD_NAME" | tr '[:lower:]' '[:upper:]')

# step1: sed (.c, .h, Makefile)
find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_NAME/$NEW_NAME/g" {} +
find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_NAME_UP/$NEW_NAME_UP/g" {} +

# step2: fix file name
find "$SEARCH_DIR" -type f -name "*$OLD_NAME*" | while read FILE; do
    RENAMED_FILE=$(echo "$FILE" | sed "s/$OLD_NAME/$NEW_NAME/g")
    mv "$FILE" "$RENAMED_FILE"
done
