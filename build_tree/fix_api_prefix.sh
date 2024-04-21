#!/bin/bash

# path
SEARCH_DIR=$(pwd)

# Check if NEW_LIB_PREFIX is provided as an argument
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: please security lib prefix and your app name"
    echo "Ex: ./fix_api_prefix commonsec commonapp"
    exit 1
fi

LIB_PRIFIX=$1
APP_PRIFIX=$2

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

    OLD_APP_PREFIX=${OLD_TAG}_
    NEW_APP_PREFIX=${NEW_TAG}_

    OLD_APP_PREFIX_UP=$(echo "$OLD_APP_PREFIX" | tr '[:lower:]' '[:upper:]')
    NEW_APP_PREFIX_UP=$(echo "$NEW_APP_PREFIX" | tr '[:lower:]' '[:upper:]')

    OLD_APP_PREFIX_HEAD=$(echo "$OLD_TAG" | sed 's/.*/\L&/; s/[a-z]*/\u&/g')
    NEW_APP_PREFIX_HEAD=$(echo "$NEW_TAG" | sed 's/.*/\L&/; s/[a-z]*/\u&/g')

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


function fChangeAppInterfaceName()
{
    OLD_TAG=$1
    NEW_TAG=$2

    OLD_APP_PREFIX=${OLD_TAG}_
    NEW_APP_PREFIX=${NEW_TAG}_

    OLD_APP_PREFIX_UP=$(echo "$OLD_APP_PREFIX" | tr '[:lower:]' '[:upper:]')
    NEW_APP_PREFIX_UP=$(echo "$NEW_APP_PREFIX" | tr '[:lower:]' '[:upper:]')

    OLD_APP_PREFIX_HEAD=$(echo "$OLD_TAG" | sed 's/.*/\L&/; s/[a-z]*/\u&/g')
    NEW_APP_PREFIX_HEAD=$(echo "$NEW_TAG" | sed 's/.*/\L&/; s/[a-z]*/\u&/g')

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

function fChangeModuleName()
{
    OLD_TAG=$1
    NEW_TAG=$2

    OLD_APP_PREFIX=${OLD_TAG}_
    NEW_APP_PREFIX=${NEW_TAG}_

    OLD_APP_PREFIX_UP=$(echo "$OLD_TAG" | tr '[:lower:]' '[:upper:]')
    NEW_APP_PREFIX_UP=$(echo "$NEW_TAG" | tr '[:lower:]' '[:upper:]')

    OLD_APP_PREFIX_HEAD=$(echo "$OLD_TAG" | sed 's/.*/\L&/; s/[a-z]*/\u&/g')
    NEW_APP_PREFIX_HEAD=$(echo "$NEW_TAG" | sed 's/.*/\L&/; s/[a-z]*/\u&/g')

    # step1: sed (.c, .h, Makefile)
    find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "*.mk" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_TAG/$NEW_TAG/g" {} +
    find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "*.mk" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_APP_PREFIX/$NEW_APP_PREFIX/g" {} +
    find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "*.mk" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_APP_PREFIX_UP/$NEW_APP_PREFIX_UP/g" {} +
    find "$SEARCH_DIR" \( -name "*.c" -o -name "*.h" -o -name "*.mk" -o -name "Makefile" \) -type f -exec sed -i "s/$OLD_APP_PREFIX_HEAD/$NEW_APP_PREFIX_HEAD/g" {} +
}

fChangeLibName customization $LIB_PRIFIX
fChangeAppInterfaceName custapp $APP_PRIFIX

# clean temp module
rm -rf $SEARCH_DIR/customer_app_template/cust_app_dev/module/module_test*

fChangeModuleName test1 $3
fChangeModuleName test2 $4
fChangeModuleName test3 $5
fChangeModuleName test4 $6
fChangeModuleName test5 $7
fChangeModuleName test6 $8
cd $SEARCH_DIR/customer_app_template/cust_app_dev/module && ./copy_sample_to_new_module.sh

mv $SEARCH_DIR/customer_app_template/cust_app_dev $SEARCH_DIR/customer_app_template/${APP_PRIFIX}_app_dev
sed -i "s/cust_/${APP_PRIFIX}_/g" $SEARCH_DIR/build_and_test.sh
sed -i "s/cust_/${APP_PRIFIX}_/g" $SEARCH_DIR/Makefile
