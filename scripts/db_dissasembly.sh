#!/bin/bash

file=/pipass/users/*/db.pipass

echo "Version:  " $(xxd -l 2 -ps $file)

LENGTH=$(xxd -s 2 -l 4 -ps $file)
echo "Length:   " $LENGTH    "( $((0x$(xxd -s 2 -l 1 -ps $file))) )"

PIN_HASH=$(xxd -s 6 -l 32 -ps -c 32 $file)
PIN_SALT=$(xxd -s 38 -l 64 -ps -c 64 $file)
echo "Pin hash: " $PIN_HASH
echo "Pin salt: " $PIN_SALT

FP_KEY=$(xxd -s 102 -l 32 -ps -c 32 $file)
FP_MAC=$(xxd -s 134 -l 16 -ps -c 16 $file)
FP_IV=$(xxd -s 150 -l 16 -ps -c 16 $file)
echo "Fp key:   " $FP_KEY
echo "Fp mac:   " $FP_MAC
echo "Fp iv:    " $FP_IV
echo

CRED_COUNT=$(xxd -s 166 -l 4 -ps -c 4 $file)
CRED_COUNT_INT=$((0x$(xxd -s 166 -l 1 -ps $file)))
echo "Cred cnt: " $CRED_COUNT  "( $CRED_COUNT_INT )"

if [ $CRED_COUNT_INT -gt 0 ]
then
    echo
fi

SEEK=170

for (( i=0; i<$CRED_COUNT_INT; i++ ))
do
    echo "--- Credential $i ---"
    echo "Length:   " $(xxd -s $SEEK -l 4 -ps -c 4 $file)  "( $((0x$(xxd -s $SEEK -l 1 -ps $file))) )"
    SEEK=$(($SEEK+4))
    echo "Type:     " $(xxd -s $SEEK -l 1 -ps -c 1 $file)  "      ( $((0x$(xxd -s $SEEK -l 1 -ps $file))) )"
    SEEK=$(($SEEK+1))
    FIELD_COUNT_INT=$((0x$(xxd -s $SEEK -l 1 -ps $file)))
    echo "Field cnt:" $(xxd -s $SEEK -l 2 -ps -c 2 $file) "    ( $FIELD_COUNT_INT )" 
    SEEK=$(($SEEK+2))

    NAMES_LEN=()
    DATA_LEN=()
    ENCRYPTED=()

    echo -n "Names len: "
    for (( j=0; j<$FIELD_COUNT_INT; j++))
    do
        echo -n "$(xxd -s $SEEK -l 2 -ps -c 2 $file)  "
        NAMES_LEN+=( $((0x$(xxd -s $SEEK -l 1 -ps $file))) )
        SEEK=$(($SEEK+2))
    done
    echo

    echo -n "Names:     "
    for (( j=0; j<$FIELD_COUNT_INT; j++))
    do
        NAME=$(xxd -s $SEEK -l ${NAMES_LEN[$j]} -ps -c ${NAMES_LEN[$j]} $file)
        echo -n "$(echo ${NAME} | xxd -r -ps)  "
        SEEK=$(($SEEK+${NAMES_LEN[$j]}))
    done
    echo

    echo -n "Data len:  "
    for (( j=0; j<$FIELD_COUNT_INT; j++))
    do
        echo -n "$(xxd -s $SEEK -l 2 -ps -c 2 $file)  "
        DATA_LEN+=( $((0x$(xxd -s $SEEK -l 1 -ps $file))) )
        SEEK=$(($SEEK+2))
    done
    echo

    echo -n "Encrypted: "
    for (( j=0; j<$FIELD_COUNT_INT; j++))
    do
        echo -n "$(xxd -s $SEEK -l 1 -ps -c 1 $file)  "
        ENCRYPTED+=( $((0x$(xxd -s $SEEK -l 1 -ps $file))) )
        SEEK=$(($SEEK+1))
    done
    echo

    for (( j=0; j<$FIELD_COUNT_INT; j++))
    do  
        echo "Data Field $j:"
        
        if [ ${ENCRYPTED[$j]} -eq 0 ]
        then
            DATA=$(xxd -s $SEEK -l ${DATA_LEN[$j]} -ps -c ${DATA_LEN[$j]} $file)
            echo "   Data: $(echo $DATA | xxd -r -ps)"

            SEEK=$(($SEEK+${DATA_LEN[$j]}))
        else
            DATA=$(xxd -s $SEEK -l ${DATA_LEN[$j]} -ps -c ${DATA_LEN[$j]} $file)
            SEEK=$(($SEEK+${DATA_LEN[$j]}))
            MAC=$(xxd -s $SEEK -l 16 -ps -c 16 $file)
            SEEK=$(($SEEK+16))
            IV=$(xxd -s $SEEK -l 16 -ps -c 16 $file)
            SEEK=$(($SEEK+16))

            echo "   Data: $DATA"
            echo "   mac:  $MAC"
            echo "   iv:   $IV"
        fi
    done
    echo
done

DEK_KEY=$(xxd -s $SEEK -l 32 -ps -c 32 $file)
SEEK=$(($SEEK+32))
DEK_MAC=$(xxd -s $SEEK -l 16 -ps -c 16 $file)
SEEK=$(($SEEK+16))
DEK_IV=$(xxd -s $SEEK -l 16 -ps -c 16 $file)
SEEK=$(($SEEK+16))

echo "Dek key:   $DEK_KEY"
echo "Dek mac:   $DEK_MAC"
echo "Dek iv:    $DEK_IV"


