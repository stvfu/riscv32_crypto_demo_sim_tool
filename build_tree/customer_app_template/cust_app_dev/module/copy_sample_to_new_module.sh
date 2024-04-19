MOUDLE_ROOT_PATH=`pwd`

SERVICE=$(grep "SERVICE_NAME" setting.mk | awk -F= '{print $2}')
MODULE_LIST=$(grep "MODULE_LIST" setting.mk | awk -F= '{print $2}')
echo "SERVICE: $SERVICE"
echo "MODULE_LIST: $MODULE_LIST"

fGenModule()
{
    OLD_TAG="sample"
    NEW_TAG=$1

    OLD_STRING=$(echo "$OLD_TAG" | tr '[:lower:]' '[:upper:]')
    NEW_STRING=$(echo "$NEW_TAG" | tr '[:lower:]' '[:upper:]')

    OLD_STRING_HEAD=$(echo "$OLD_TAG" | sed 's/.*/\L&/; s/[a-z]*/\u&/g')
    NEW_STRING_HEAD=$(echo "$NEW_TAG" | sed 's/.*/\L&/; s/[a-z]*/\u&/g')

    rm -rf $MOUDLE_ROOT_PATH/module_${NEW_TAG}
    cp -r $MOUDLE_ROOT_PATH/module_${OLD_TAG} $MOUDLE_ROOT_PATH/module_${NEW_TAG}

    cd $MOUDLE_ROOT_PATH/module_${NEW_TAG}
    cp ${SERVICE}_module_${OLD_TAG}.h       ${SERVICE}_module_${NEW_TAG}.h
    cp ${SERVICE}_module_${OLD_TAG}_entry.c ${SERVICE}_module_${NEW_TAG}_entry.c
    cp ${SERVICE}_module_${OLD_TAG}_test.c  ${SERVICE}_module_${NEW_TAG}_test.c

    sed -i "s/$OLD_TAG/$NEW_TAG/g" ${SERVICE}_module_${NEW_TAG}.h
    sed -i "s/$OLD_TAG/$NEW_TAG/g" ${SERVICE}_module_${NEW_TAG}_entry.c
    sed -i "s/$OLD_TAG/$NEW_TAG/g" ${SERVICE}_module_${NEW_TAG}_test.c
    sed -i "s/$OLD_TAG/$NEW_TAG/g" sub.mk

    sed -i "s/$OLD_STRING/$NEW_STRING/g" ${SERVICE}_module_${NEW_TAG}.h
    sed -i "s/$OLD_STRING/$NEW_STRING/g" ${SERVICE}_module_${NEW_TAG}_entry.c
    sed -i "s/$OLD_STRING/$NEW_STRING/g" ${SERVICE}_module_${NEW_TAG}_test.c

    sed -i "s/$OLD_STRING_HEAD/$NEW_STRING_HEAD/g" ${SERVICE}_module_${NEW_TAG}.h
    sed -i "s/$OLD_STRING_HEAD/$NEW_STRING_HEAD/g" ${SERVICE}_module_${NEW_TAG}_entry.c
    sed -i "s/$OLD_STRING_HEAD/$NEW_STRING_HEAD/g" ${SERVICE}_module_${NEW_TAG}_test.c

    rm -rf ${SERVICE}_module_${OLD_TAG}.h       
    rm -rf ${SERVICE}_module_${OLD_TAG}_entry.c 
    rm -rf ${SERVICE}_module_${OLD_TAG}_test.c  
    cd $MOUDLE_ROOT_PATH
}

IFS=' ' read -r -a modules <<< "$MODULE_LIST"

# for each module
for module in "${modules[@]}"
do
    fGenModule "$module"
done
