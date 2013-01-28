# ==========================================
#	Variable Declarations
# ==========================================
source='text.test'
cipher="$source.uo"
dest='decrypt.test'
passwd="test"

# ==========================================
# 	Test Case 1: Local Enc/Dec
# ==========================================
echo "[TEST1] Local Encryption/Decryption"
echo "[TEST1] Starting uoenc..."
echo $passwd | ./uoenc $source
echo -e "\n[TEST1] Starting uodec..."
echo $passwd | ./uodec $cipher
echo -n -e "\n[TEST1] Diff results: "
diff $source $dest
echo -e "\n[TEST1] Cleaning up..."
rm -f $cipher $dest
