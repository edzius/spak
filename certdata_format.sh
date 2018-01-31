#!/bin/sh

OUTPUT_FILE=
KEY_FILE=
CRT_FILE=

usage() {
        echo -e "Usage: certdata_format.sh [options] <output-file>"
                echo -e "\t -k private key file"
                echo -e "\t -c certificate file"
                echo -e "\t -h usage"
}

while getopts k:c:h o
        do case "$o" in
                k) KEY_FILE=$OPTARG;;
                c) CRT_FILE=$OPTARG;;
                h) usage; exit 0;;
                \?) usage; exit 0;;
        esac
done
shift $(($OPTIND - 1))

OUTPUT_FILE=$1

if [ -z "$OUTPUT_FILE" ]; then
	usage;
	exit 1;
fi

echo -e "// Autogenerate static key/crt data source." > $OUTPUT_FILE

echo -e "static char spak_key_data[] = " >> $OUTPUT_FILE
if [ -n "$KEY_FILE" -a -f "$KEY_FILE" ]; then
sed 's/\(.*\)/"\1\\n"/g' $KEY_FILE >> $OUTPUT_FILE
else
echo -e "\"\"" >> $OUTPUT_FILE
fi
echo -e ";\n" >> $OUTPUT_FILE

echo -e "static char spak_crt_data[] = " >> $OUTPUT_FILE
if [ -n "$CRT_FILE" -a -f "$CRT_FILE" ]; then
sed 's/\(.*\)/"\1\\n"/g' $CRT_FILE >> $OUTPUT_FILE
else
echo -e "\"\"" >> $OUTPUT_FILE
fi
echo -e ";\n" >> $OUTPUT_FILE
