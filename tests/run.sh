#!/usr/bin/env bash
#
# ShadowVault regression suite
#
#   ./tests/run.sh              run against ../shadowvault (built if missing)
#   SV=/path/to/shadowvault ./tests/run.sh
#   SV_ASAN=1 ./tests/run.sh    rebuild with ASan/UBSan and run core subset
#
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
BIN="${SV:-$ROOT/shadowvault}"
CC="${CC:-gcc}"

PASS=0; FAIL=0; SKIP=0
T="$(mktemp -d /tmp/svtest.XXXXXX)"
trap 'rm -rf "$T"' EXIT

ok()   { PASS=$((PASS+1)); echo "  ok  - $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL- $1"; }
skip() { SKIP=$((SKIP+1)); echo "  skip- $1"; }
chk()  { if [ "$1" = 0 ]; then ok "$2"; else bad "$2"; fi; }

build_asan() {
    echo "== building ASan/UBSan binary =="
    $CC -O1 -g -fsanitize=address,undefined -o "$T/sv_asan" "$ROOT/shadowvault.c" -lsodium -lz || {
        $CC -O1 -g -fsanitize=address -o "$T/sv_asan" "$ROOT/shadowvault.c" -lsodium -lz || return 1
    }
    BIN="$T/sv_asan"
}

[ "${SV_ASAN:-0}" = "1" ] && { build_asan || { echo "asan build failed"; exit 1; }; }
[ -x "$BIN" ] || $CC -O2 -Wall -Wextra -o "$BIN" "$ROOT/shadowvault.c" -lsodium -lz
[ -x "$BIN" ] || { echo "no binary at $BIN"; exit 1; }
# rebuild when the default binary is older than the source
if [ -z "${SV:-}" ] && [ -x "$BIN" ] && [ "$ROOT/shadowvault.c" -nt "$BIN" ]; then
    echo "== source newer than binary; rebuilding =="
    $CC -O2 -Wall -Wextra -o "$BIN" "$ROOT/shadowvault.c" -lsodium -lz || { echo "rebuild failed"; exit 1; }
fi

sv()  { "$BIN" "$@"; }
enc() { sv enc "$@"; }          # password via stdin by caller
dec() { sv dec "$@"; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

section() { echo; echo "== $1 =="; }

cd "$T"

############################################
section "CLI basics"
############################################
sv -h >/dev/null 2>&1;                 chk $? "-h exits 0"
sv frobnicate x >/dev/null 2>&1;       [ $? -ne 0 ]; chk $? "unknown action rejected"
sv enc >/dev/null 2>&1;                [ $? -ne 0 ]; chk $? "missing target rejected"
echo -n p | enc nosuchfile -o /dev/null >/dev/null 2>&1; [ $? -ne 0 ]; chk $? "nonexistent input rejected"

############################################
section "single-file roundtrips"
############################################
roundtrip() { # name size bytes-source compress-flag
    local name=$1 size=$2 src=$3 cflag=${4:-}
    rm -f f.bin f.vault f.out
    head -c "$size" "$src" > f.bin
    local h1=$(sha f.bin)
    echo -n pw1 | enc f.bin -o f.vault $cflag 2>/dev/null || { bad "$name (enc)"; return; }
    dec f.vault -p pw1 -o f.out 2>/dev/null        || { bad "$name (dec)"; return; }
    [ "$(sha f.out)" = "$h1" ]; chk $? "$name"
}
roundtrip "empty file"                    0 /dev/zero
roundtrip "tiny (7B)"                     7  /dev/urandom
roundtrip "CHUNK-1 (1048575)"             1048575 /dev/urandom
roundtrip "CHUNK   (1048576)"             1048576 /dev/urandom
roundtrip "CHUNK+1 (1048577)"             1048577 /dev/urandom
roundtrip "3 MiB uncompressed"            3145728 /dev/urandom
roundtrip "3 MiB compressed (regression)" 3145728 /dev/urandom -c
head -c 2097152 /dev/zero > f.bin
roundtrip "2 MiB zeros compressed"        2097152 /dev/zero -c

############################################
section "authentication failures"
############################################
head -c 100000 /dev/urandom > a.bin
echo -n pw | enc a.bin -o a.vault 2>/dev/null
dec a.vault -p wrong -o /dev/null 2>/dev/null;               [ $? -ne 0 ]; chk $? "wrong password rejected"
cp a.vault t1.vault; printf X | dd of=t1.vault bs=1 seek=50 conv=notrunc 2>/dev/null
dec t1.vault -p pw -o /dev/null 2>/dev/null;                 [ $? -ne 0 ]; chk $? "header tamper detected"
cp a.vault t2.vault; printf X | dd of=t2.vault bs=1 seek=50000 conv=notrunc 2>/dev/null
dec t2.vault -p pw -o /dev/null 2>/dev/null;                 [ $? -ne 0 ]; chk $? "payload tamper detected"
head -c 300 a.vault > t3.vault
dec t3.vault -p pw -o /dev/null 2>/dev/null;                 [ $? -ne 0 ]; chk $? "truncated vault rejected"
cat a.vault > t4.vault; head -c 99 /dev/urandom >> t4.vault
dec t4.vault -p pw -o t4.out 2>/dev/null && [ "$(sha t4.out)" = "$(sha a.bin)" ]
                                                             chk $? "trailing junk tolerated"
sv verify a.vault -p pw >/dev/null 2>&1;                     chk $? "verify OK"
sv verify a.vault -p wrong >/dev/null 2>&1;                  [ $? -ne 0 ]; chk $? "verify wrong pw fails"

############################################
section "pipes, naming, overwrite guards"
############################################
head -c 200000 /dev/urandom > p.bin
sv enc - -o p.vault -p pw < p.bin 2>/dev/null && \
  sv dec p.vault -o p.out -p pw 2>/dev/null && [ "$(sha p.out)" = "$(sha p.bin)" ]
                                                             chk $? "stdin/stdout roundtrip"
rm -f st.bin st.bin.vault st.orig
head -c 10 /dev/urandom > st.bin
echo -n pw | enc st.bin 2>/dev/null && [ -f st.bin.vault ]; chk $? "default .vault output"
mv st.bin st.orig
echo -n pw | dec st.bin.vault 2>/dev/null && cmp -s st.bin st.orig; chk $? "default strips .vault"
echo -n pw | enc st.bin -o st.bin.vault >/dev/null 2>&1;     [ $? -ne 0 ]; chk $? "overwrite refused w/o -f"
echo -n pw | enc st.bin -o st.bin.vault -f 2>/dev/null;      chk $? "overwrite allowed with -f"

############################################
section "directory bundles"
############################################
rm -rf tree tree.vault tree_out
mkdir -p tree/a/b/c tree/empty_dir tree/'uni dir'
echo hello     > tree/f1.txt
chmod 750 tree/a; chmod 600 tree/f1.txt
touch -d '2024-03-15 10:30:00' tree/f1.txt
head -c 1500000 /dev/urandom > tree/a/b/big.bin
echo unicode > "tree/uni dir/héllo-wörld.txt"
# deep nesting (iterative stack)
D=tree/deep; for i in $(seq 1 40); do D="$D/lvl$i"; done
mkdir -p "$D"; echo deep > "$D/deep.txt"
# many entries
mkdir -p tree/many; for i in $(seq 1 120); do echo $i > tree/many/file$i.txt; done
ln -s /etc/hostname tree/link.txt

echo -n pw | enc tree 2>/dev/null;                           chk $? "bundle encrypt"
dec tree.vault -p pw -o tree_out 2>/dev/null;                chk $? "bundle decrypt"
[ -d tree_out/empty_dir ];                                   chk $? "empty dir preserved"
[ "$(sha tree_out/a/b/big.bin)" = "$(sha tree/a/b/big.bin)" ]; chk $? "big file content"
[ "$(stat -c%a tree_out/a)" = "750" ] && [ "$(stat -c%a tree_out/f1.txt)" = "600" ]
                                                             chk $? "permissions restored"
[ "$(stat -c%Y tree_out/f1.txt)" = "$(stat -c%Y tree/f1.txt)" ]; chk $? "mtime restored"
[ -f "tree_out/uni dir/héllo-wörld.txt" ];                   chk $? "unicode names"
[ -f tree_out/deep/lvl1/lvl2/lvl3/lvl4/lvl5/lvl6/lvl7/lvl8/lvl9/lvl10/lvl11/lvl12/lvl13/lvl14/lvl15/lvl16/lvl17/lvl18/lvl19/lvl20/lvl21/lvl22/lvl23/lvl24/lvl25/lvl26/lvl27/lvl28/lvl29/lvl30/lvl31/lvl32/lvl33/lvl34/lvl35/lvl36/lvl37/lvl38/lvl39/lvl40/deep.txt ]
                                                             chk $? "deep nesting"
[ "$(ls tree_out/many | wc -l)" = "120" ];                   chk $? "many entries"
[ ! -e tree_out/link.txt ];                                  chk $? "symlinks skipped"
diff -r --brief tree tree_out >/dev/null 2>&1 || true   # diff would flag symlink+excluded? just informational
sv verify tree.vault -p pw >/dev/null 2>&1;                  chk $? "bundle verify"
cp tree.vault tb.vault; printf Y | dd of=tb.vault bs=1 seek=1000 conv=notrunc 2>/dev/null
dec tb.vault -p pw -o /dev/null 2>/dev/null;                 [ $? -ne 0 ]; chk $? "bundle tamper detected"
dec tree.vault -p nope -o /dev/null 2>/dev/null;             [ $? -ne 0 ]; chk $? "bundle wrong pw"
dec tree.vault -p pw -o tree_out 2>/dev/null;                [ $? -ne 0 ]; chk $? "extract over existing refused"

############################################
section "exclude patterns"
############################################
rm -rf ex ex.vault ex_out
mkdir -p ex/sub
echo k > ex/keep.txt;    echo j > ex/skip.tmp
echo j > ex/sub/x.log;   echo k > ex/sub/keep2.txt
echo -n pw | enc ex --exclude '*.tmp' --exclude 'sub/*.log' 2>/dev/null
dec ex.vault -p pw -o ex_out 2>/dev/null
[ ! -e ex_out/skip.tmp ] && [ ! -e ex_out/sub/x.log ] && \
  [ -f ex_out/keep.txt ] && [ -f ex_out/sub/keep2.txt ];     chk $? "--exclude prunes matches"

############################################
section "keyfiles + KDF params"
############################################
sv keygen -o k.key --size 64 2>/dev/null;                    chk $? "keygen default action"
[ "$(stat -c%s k.key)" = "64" ] && [ "$(stat -c%a k.key)" = "600" ]; chk $? "keygen size/mode"
sv keygen -o k.key 2>/dev/null;                              [ $? -ne 0 ]; chk $? "keygen refuses overwrite"
sv keygen -o k.key -f 2>/dev/null;                           chk $? "keygen -f overwrites"
head -c 10 /dev/urandom > kf_target.bin
echo -n pw | enc kf_target.bin -k k.key -o kf.vault 2>/dev/null
if echo -n pw | dec kf.vault -o /dev/null -f 2>/dev/null; then bad "missing keyfile accepted"; else ok "keyfile required"; fi
echo -n pw | dec kf.vault -k k.key -o kf.out 2>/dev/null && [ "$(sha kf.out)" = "$(sha kf_target.bin)" ]
                                                             chk $? "keyfile roundtrip"
dd if=/dev/urandom of=bigkf bs=1024 count=$((4*1024+1)) 2>/dev/null
echo -n pw | enc kf_target.bin -k bigkf -o /dev/null >/dev/null 2>&1
                                                             [ $? -ne 0 ]; chk $? "oversized keyfile rejected"
rm -f kf2.vault kf2.out
echo -n pw | enc kf_target.bin -k bigkf --keyfile-max-size 8388608 -o kf2.vault 2>/dev/null
echo -n pw | dec kf2.vault -k bigkf --keyfile-max-size 8388608 -o kf2.out -f 2>/dev/null && [ "$(sha kf2.out)" = "$(sha kf_target.bin)" ]
                                                             chk $? "--keyfile-max-size override works"
echo -n pw | enc kf_target.bin -t 2 -m 33554432 -o ct.vault 2>/dev/null
echo -n pw | dec ct.vault -o ct.out 2>/dev/null && [ "$(sha ct.out)" = "$(sha kf_target.bin)" ]
                                                             chk $? "custom KDF params persisted"
for badarg in "-t abc" "-t 0" "-m xyz" "-m 0" "--keyfile-max-size foo" "--keyfile-max-size 0" "--size 8"; do
    echo -n pw | enc kf_target.bin $badarg -o /dev/null >/dev/null 2>&1
    [ $? -ne 0 ]; chk $? "rejects '$badarg'"
done

############################################
section "password policy & pass-fd"
############################################
: > tiny.txt
enc tiny.txt -p '' -o tp.vault >/dev/null 2>&1;              [ $? -ne 0 ]; chk $? "empty password rejected"
enc tiny.txt -p '' --allow-empty-pass -o tp.vault 2>/dev/null; chk $? "--allow-empty-pass allows enc"
dec tp.vault -p '' -o tp.out >/dev/null 2>&1;                [ $? -ne 0 ]; chk $? "dec also requires ack"
dec tp.vault -p '' --allow-empty-pass -o tp.out 2>/dev/null && cmp -s tiny.txt tp.out
                                                             chk $? "empty-pw roundtrip"
exec 3<<<'fdsecret'
enc kf_target.bin --pass-fd 3 -o fd.vault 2>/dev/null; exec 3<&-
                                                             chk $? "--pass-fd encrypt"
exec 3<<<'fdsecret'
dec fd.vault --pass-fd 3 -o fd.out 2>/dev/null; exec 3<&-
cmp -s kf_target.bin fd.out;                                 chk $? "--pass-fd roundtrip"
enc kf_target.bin -p x --pass-fd 0 -o /dev/null >/dev/null 2>&1
                                                             [ $? -ne 0 ]; chk $? "-p and --pass-fd mutually exclusive"

############################################
section "list + manifest trailer"
############################################
rm -f lm.bin lm.vault
head -c 2500000 /dev/urandom | base64 > lm.bin          # compressible, multi-chunk
echo -n pw | enc lm.bin -c -o lm.vault 2>/dev/null
out=$(sv list lm.vault -p pw 2>/dev/null)
echo "$out" | grep -q "lm.bin";                          chk $? "list shows original filename"
[ "$(echo "$out" | awk '/^f /{print $2}')" = "$(stat -c%s lm.bin)" ]
                                                         chk $? "list shows TRUE size (compressed)"
rm -f lmb.vault
mkdir -p lmd/sub; echo 1 > lmd/x.txt; head -c 9000 /dev/urandom > lmd/sub/y.bin; mkdir lmd/emptydir
echo -n pw | enc lmd -o lmd.vault 2>/dev/null
out=$(sv list lmd.vault -p pw 2>/dev/null)
echo "$out" | grep -qE '^d ';                            chk $? "list shows dirs"
echo "$out" | grep -q "sub/y.bin";                       chk $? "list shows nested paths"
nf=$(find lmd -type f | wc -l)
[ "$(echo "$out" | grep -c '^f ')" = "$nf" ];            chk $? "file count matches tree"
sv list lmd.vault -p wrong >/dev/null 2>&1;              [ $? -ne 0 ]; chk $? "list wrong password rejected"
cp lmd.vault lt.vault; SZ=$(stat -c%s lt.vault)
printf '\xff' | dd of=lt.vault bs=1 seek=$((SZ-3)) conv=notrunc 2>/dev/null
sv list lt.vault -p pw >/dev/null 2>&1;                  [ $? -ne 0 ]; chk $? "tampered trailer rejected"
OFF=$(grep -abo 'SVM1' lmd.vault | head -1 | cut -d: -f1)
head -c "$OFF" lmd.vault > legacy.vault
dec legacy.vault -o legacy_out -p pw 2>/dev/null && diff -r --brief lmd legacy_out >/dev/null
                                                         chk $? "trailer-stripped vault still decrypts"
sv list legacy.vault -p pw 2>&1 | grep -q 'no manifest'; chk $? "legacy vault reported"
cat lmd.vault | sv list - -p pw 2>/dev/null | grep -q 'x.txt'; chk $? "list via stdin pipe"
# dec must ignore the trailer (backward-compat of reader)
rm -rf lmd_out; dec lmd.vault -o lmd_out -p pw 2>/dev/null && diff -r --brief lmd lmd_out >/dev/null
                                                         chk $? "dec ignores trailer"

############################################
section "progress, shred, path safety"
############################################
head -c 400000 /dev/urandom > pr.bin
stderr=$(echo -n pw | enc pr.bin -o pr.vault -P 2>&1 >/dev/null)
echo "$stderr" | grep -q 'bytes';                            chk $? "-P prints progress"
[ -f pr.vault ];                                             chk $? "-P still produces vault"

rm -f sh.bin sh.vault
head -c 100000 /dev/urandom > sh.bin
echo -n pw | enc sh.bin -s -o sh.vault 2>/dev/null
[ ! -e sh.bin ] && sv verify sh.vault -p pw >/dev/null 2>&1; chk $? "shred removes original, vault valid"

rm -rf ps ps.vault; mkdir ps
echo x > ps/in.txt
echo -n pw | enc ps -o ps/inside.vault >/dev/null 2>&1;      [ $? -ne 0 ]; chk $? "output inside input dir rejected"

############################################
section "v7 key slots"
############################################
rm -f sl.bin sl.vault k2.key
head -c 50000 /dev/urandom > sl.bin
echo -n pw0 | enc sl.bin -o sl.vault 2>/dev/null
[ "$(head -c4 sl.vault)" = "SV07" ];                       chk $? "fresh vault is SV07"
printf 'pw1\n' | sv addkey sl.vault -p pw0 >/dev/null 2>&1; chk $? "addkey second password"
sv keygen -o k2.key 2>/dev/null
sv addkey sl.vault -p pw0 --new-keyfile k2.key --allow-empty-pass >/dev/null 2>&1; chk $? "addkey keyfile-only slot"
ok=0
for p in pw0 pw1; do echo -n $p | sv verify sl.vault >/dev/null 2>&1 && ok=$((ok+1)); done
[ "$ok" = 2 ];                                             chk $? "both passwords verify"
sv dec sl.vault -k k2.key -p '' -f -o sl_k.out 2>/dev/null && cmp -s sl.bin sl_k.out
                                                           chk $? "keyfile-only slot decrypts"
if echo -n nope | sv addkey sl.vault >/dev/null 2>&1; then bad "addkey wrong cred accepted"; else ok "addkey wrong cred rejected"; fi
printf 'pwr\n' | sv passwd sl.vault -p pw0 >/dev/null 2>&1; chk $? "passwd rotates slot"
if echo -n pw0 | sv verify sl.vault >/dev/null 2>&1; then bad "old password survives rotation"; else ok "old password rejected after rotate"; fi
echo -n pwr | sv verify sl.vault >/dev/null 2>&1;          chk $? "rotated credential verifies"
sv delkey sl.vault --slot 9 -p pwr >/dev/null 2>&1;        [ $? -ne 0 ]; chk $? "delkey rejects bad index"
# fill remaining slots then expect refusal
for i in 3 4 5 6 7 8; do printf "sp$i\n" | sv addkey sl.vault -p pwr >/dev/null 2>&1; done
printf 'overflow\n' | sv addkey sl.vault -p pwr >/dev/null 2>&1
                                                           [ $? -ne 0 ]; chk $? "9th slot refused"
sv delkey sl.vault --slot 1 -p pw1 >/dev/null 2>&1;        chk $? "delkey removes slot"
if echo -n pw1 | sv verify sl.vault -p pw1 >/dev/null 2>&1; then bad "deleted slot still opens"; else ok "deleted slot dead"; fi
# data integrity across all churn
echo -n pwr | sv dec sl.vault -f -o sl_final.out 2>/dev/null && cmp -s sl.bin sl_final.out
                                                           chk $? "data intact after slot churn"
# splice attack: transplant a foreign slot over slot 1, attacker's DEK must not authenticate
rm -f va.vault vb.vault
echo -n pa | enc sl.bin -o va.vault 2>/dev/null
head -c 100 /dev/urandom > vb.bin; echo -n pb | enc vb.bin -o vb.vault 2>/dev/null
dd if=vb.vault of=va.vault bs=1 skip=64 seek=$((64+96)) count=96 conv=notrunc 2>/dev/null
echo -n pb | sv dec va.vault -f -o /dev/null >/dev/null 2>&1
                                                           [ $? -ne 0 ]; chk $? "transplanted slot cannot decrypt foreign stream"
echo -n pa | sv verify va.vault >/dev/null 2>&1;           chk $? "owner's remaining slot still works"

############################################
section "rekey (v6 -> v7 migration)"
############################################
base64 -d "$HERE/v6fixture.b64" > v6.vault
[ "$(head -c4 v6.vault)" = "SV06" ];                       chk $? "v6 fixture loads"
sv verify v6.vault -p v6fixpass >/dev/null 2>&1;           chk $? "legacy v6 vault verifies"
sv rekey v6.vault -p v6fixpass >/dev/null 2>&1;            chk $? "rekey migrates"
[ "$(head -c4 v6.v7.vault)" = "SV07" ];                    chk $? "migrated vault is SV07"
echo -n v6fixpass | sv verify v6.v7.vault >/dev/null 2>&1; chk $? "migrated vault verifies"
printf 'extra\n' | sv addkey v6.v7.vault -p v6fixpass >/dev/null 2>&1; chk $? "slots work on migrated vault"
sv list v6.v7.vault -p v6fixpass >/dev/null 2>&1;          chk $? "list works on migrated vault"

############################################
section "single-file metadata restore"
############################################
rm -f md.bin md.vault md.out
head -c 5000 /dev/urandom > md.bin
chmod 640 md.bin
touch -d '2023-08-09 12:34:56' md.bin
echo -n pw | enc md.bin -o md.vault 2>/dev/null
dec md.vault -p pw -o md.out 2>/dev/null;                  chk $? "dec runs"
[ "$(stat -c%a md.out)" = "640" ];                         chk $? "dec restores mode"
[ "$(stat -c%Y md.out)" = "$(stat -c%Y md.bin)" ];         chk $? "dec restores mtime"
rm -f si.vault si.out
sv enc - -o si.vault -p pw < md.bin 2>/dev/null
dec si.vault -p pw -o si.out 2>/dev/null && cmp -s md.bin si.out
                                                           chk $? "stdin vault roundtrip (no metadata restore)"

############################################
section "read-only directory extraction"
############################################
rm -rf ro ro.vault ro_out
mkdir -p ro/sub
echo data > ro/rofile.txt
echo deep > ro/sub/deep.txt
chmod 555 ro; chmod 555 ro/sub; chmod 644 ro/rofile.txt
echo -n pw | enc ro 2>/dev/null;                           chk $? "enc dir with read-only dirs"
dec ro.vault -p pw -o ro_out 2>/dev/null;                  chk $? "dec with read-only dir modes"
[ "$(stat -c%a ro_out)" = "555" ] && [ "$(cat ro_out/rofile.txt)" = "data" ] \
  && [ "$(stat -c%a ro_out/sub)" = "555" ] && [ "$(cat ro_out/sub/deep.txt)" = "deep" ]
                                                           chk $? "read-only dir modes + contents restored"
chmod -R u+w ro

############################################
section "atomic outputs & -f safety"
############################################
rm -f at.bin at.vault at.out at_bad.vault
head -c 10000 /dev/urandom > at.bin
echo -n pw | enc at.bin -o at.vault 2>/dev/null
echo OLDDATA > at.out
cp at.vault at_bad.vault; printf X | dd of=at_bad.vault bs=1 seek=1000 conv=notrunc 2>/dev/null
dec at_bad.vault -p pw -f -o at.out 2>/dev/null;           [ $? -ne 0 ]; chk $? "dec -f of tampered vault fails"
[ "$(cat at.out)" = "OLDDATA" ];                           chk $? "failed dec -f keeps old output"
echo -n pw | dec at.vault -f -o at.out 2>/dev/null;        chk $? "successful dec -f replaces output"
cmp -s at.bin at.out;                                      chk $? "replaced output is correct"
ls at.out.svtmp.* >/dev/null 2>&1;                         [ $? -ne 0 ]; chk $? "no temp files left behind"
rm -rf btree btree.vault btree_out bb.vault
mkdir btree; echo v1 > btree/f.txt
echo -n pw | enc btree 2>/dev/null
dec btree.vault -p pw -o btree_out 2>/dev/null;            chk $? "bundle dec"
echo OLD > btree_out/f.txt
cp btree.vault bb.vault; printf Y | dd of=bb.vault bs=1 seek=900 conv=notrunc 2>/dev/null
cmp -s btree.vault bb.vault;                               [ $? -ne 0 ]; chk $? "bundle tamper applied"
dec bb.vault -p pw -f -o btree_out 2>/dev/null;            [ $? -ne 0 ]; chk $? "bundle dec -f tamper fails"
[ "$(cat btree_out/f.txt)" = "OLD" ];                      chk $? "failed bundle dec -f keeps old tree"
dec btree.vault -p pw -f -o btree_out 2>/dev/null;         chk $? "successful bundle dec -f replaces"
[ "$(cat btree_out/f.txt)" = "v1" ];                       chk $? "replaced bundle tree correct"

############################################
section "rekey metadata preservation"
############################################
rm -f rk.bin rk.vault rk.v7.vault rk_dec
head -c 300000 /dev/urandom | base64 > rk.bin
chmod 640 rk.bin; touch -d '2021-01-02 03:04:05' rk.bin
echo -n pw | enc rk.bin -c -o rk.vault 2>/dev/null
sv rekey rk.vault -p pw 2>/dev/null;                       chk $? "rekey runs"
[ "$(head -c4 rk.v7.vault)" = "SV07" ];                    chk $? "rekey output is v7"
[ "$(dd if=rk.v7.vault bs=1 skip=5 count=1 2>/dev/null | od -An -tu1 | tr -d ' ')" = "1" ]
                                                           chk $? "rekey preserves compress flag"
out=$(sv list rk.v7.vault -p pw 2>/dev/null)
echo "$out" | grep -q "rk.bin";                            chk $? "rekey keeps original filename"
[ "$(echo "$out" | awk '/^f /{print $2}')" = "$(stat -c%s rk.bin)" ]
                                                           chk $? "rekey keeps true size"
echo "$out" | grep -q "2021-01-02";                        chk $? "rekey keeps mtime"
echo -n pw | dec rk.v7.vault -o rk_dec -f 2>/dev/null
cmp -s rk.bin rk_dec;                                      chk $? "rekey data intact"

############################################
section "stdin needs explicit password"
############################################
head -c 100 /dev/urandom > np.bin
cat np.bin | sv enc - -o /dev/null 2>/dev/null;            [ $? -ne 0 ]; chk $? "stdin enc without -p rejected"
cat np.bin | sv dec - -o /dev/null 2>/dev/null;            [ $? -ne 0 ]; chk $? "stdin dec without -p rejected"

############################################
section "password length handling"
############################################
LONGPW=$(printf 'x%.0s' $(seq 1 300))
rm -f lp.bin lp.vault lp.out lp2.vault
head -c 100 /dev/urandom > lp.bin
echo -n "$LONGPW" | enc lp.bin -o lp.vault 2>/dev/null;    chk $? "300-byte password enc"
echo -n "$LONGPW" | dec lp.vault -o lp.out -f 2>/dev/null; chk $? "300-byte password dec"
cmp -s lp.bin lp.out;                                      chk $? "long password roundtrip"
BIGPW=$(printf 'y%.0s' $(seq 1 5000))
echo -n "$BIGPW" | enc lp.bin -o lp2.vault -f 2>/dev/null; [ $? -ne 0 ]; chk $? "overlong password rejected"

############################################
section "slots subcommand"
############################################
rm -f sl2.bin sl2.vault
head -c 1000 /dev/urandom > sl2.bin
echo -n pw0 | enc sl2.bin -o sl2.vault 2>/dev/null
printf 'pw1\n' | sv addkey sl2.vault -p pw0 >/dev/null 2>&1
out=$(sv slots sl2.vault 2>/dev/null)
echo "$out" | grep -q "passphrase";                        chk $? "slots lists without password"
[ "$(echo "$out" | grep -c passphrase)" = "2" ];           chk $? "slots shows both slots"
sv slots sl2.vault -p pw1 2>/dev/null | grep -q "matches slot 1"
                                                           chk $? "slots matches a credential"
sv slots sl2.vault -p nope >/dev/null 2>&1;                [ $? -ne 0 ]; chk $? "slots wrong credential fails"

############################################
section "per-slot KDF params (type-2 slots)"
############################################
rm -f ps2.bin ps2.vault ps2.out
head -c 2000 /dev/urandom > ps2.bin
echo -n pw0 | enc ps2.bin -o ps2.vault 2>/dev/null
printf 'pws\n' | sv addkey ps2.vault -p pw0 -t 2 -m 8388608 >/dev/null 2>&1
                                                           chk $? "addkey with per-slot params"
sv slots ps2.vault 2>/dev/null | grep -q "ops=2, mem=8192 KiB"
                                                           chk $? "slots shows per-slot params"
sv verify ps2.vault -p pws >/dev/null 2>&1;                chk $? "per-slot credential verifies"
sv verify ps2.vault -p pw0 >/dev/null 2>&1;                chk $? "global credential still works"
echo -n pws | sv dec ps2.vault -f -o ps2.out 2>/dev/null && cmp -s ps2.bin ps2.out
                                                           chk $? "per-slot decrypt works"
printf 'pwr\n' | sv passwd ps2.vault -p pws -t 4 -m 8388608 >/dev/null 2>&1
                                                           chk $? "passwd with per-slot params"
sv verify ps2.vault -p pwr >/dev/null 2>&1;                chk $? "rotated per-slot credential verifies"

############################################
section "compression probe (incompressible data)"
############################################
flagbyte() { dd if="$1" bs=1 skip=5 count=1 2>/dev/null | od -An -tu1 | tr -d ' '; }
rm -f cp1.bin cp1.vault cp1.out
head -c 2000000 /dev/urandom > cp1.bin
echo -n pw | enc cp1.bin -c -o cp1.vault 2>/dev/null
[ "$(flagbyte cp1.vault)" = "0" ];                         chk $? "random data stored raw despite -c"
dec cp1.vault -p pw -o cp1.out -f 2>/dev/null
cmp -s cp1.bin cp1.out;                                    chk $? "probed-skip roundtrip"
rm -f cp2.bin cp2.vault cp2.out
head -c 2000000 /dev/zero > cp2.bin
echo -n pw | enc cp2.bin -c -o cp2.vault 2>/dev/null
[ "$(flagbyte cp2.vault)" = "1" ];                         chk $? "compressible data still compressed"
dec cp2.vault -p pw -o cp2.out -f 2>/dev/null
cmp -s cp2.bin cp2.out;                                    chk $? "compressed roundtrip"
rm -f cp3.vault cp3.out
cat cp1.bin | sv enc - -c -p pw -o cp3.vault 2>/dev/null
[ "$(flagbyte cp3.vault)" = "0" ];                         chk $? "stdin probe skips compression"
dec cp3.vault -p pw -o cp3.out -f 2>/dev/null
cmp -s cp1.bin cp3.out;                                    chk $? "stdin probed-skip roundtrip"
: > cp4.bin
echo -n pw | enc cp4.bin -c -o cp4.vault -f 2>/dev/null;   chk $? "empty file with -c enc"
dec cp4.vault -p pw -o cp4.out -f 2>/dev/null && [ ! -s cp4.out ]
                                                           chk $? "empty file with -c dec (regression)"

############################################
section "version flag"
############################################
sv -V 2>/dev/null | grep -q "v7";                          chk $? "-V prints version"
sv --version 2>/dev/null | grep -q "v7";                   chk $? "--version works"

############################################
section "hidden-echo password prompt (pty)"
############################################
if command -v python3 >/dev/null 2>&1; then
    rm -f tty.bin tty.vault tty.out pty_test.py
    head -c 200 /dev/urandom > tty.bin
    cat > pty_test.py <<'PYEOF'
import os, pty, select, sys

def run(args, password):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(args[0], args)
        os._exit(127)
    sent = False
    out = b""
    while True:
        r, _, _ = select.select([fd], [], [], 10)
        if not r:
            break
        try:
            d = os.read(fd, 4096)
        except OSError:
            break
        if not d:
            break
        out += d
        if not sent and b"Password:" in out:
            os.write(fd, password)
            sent = True
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), out

rc, out = run([sys.argv[1], "enc", "tty.bin", "-o", "tty.vault"], b"pwtty\n")
assert rc == 0, f"enc rc={rc}: {out!r}"
assert b"pwtty" not in out, "password was echoed to the terminal!"
rc, out = run([sys.argv[1], "dec", "tty.vault", "-o", "tty.out", "-f"], b"pwtty\n")
assert rc == 0, f"dec rc={rc}: {out!r}"
print("PTY-OK")
PYEOF
    python3 pty_test.py "$BIN" >/dev/null 2>&1;               chk $? "pty prompt enc+dec, password not echoed"
    cmp -s tty.bin tty.out;                                   chk $? "pty roundtrip content"
    rm -f pty_test.py
else
    skip "pty prompt test (python3 not available)"
fi

############################################
section "ASan subset"
############################################
if [ "${SV_ASAN:-0}" = "1" ]; then
    roundtrip "asan: multi-chunk compressed" 3145728 /dev/urandom -c
    echo -n pw | enc tree -f 2>/dev/null && dec tree.vault -p pw -o asan_out 2>/dev/null
    [ -z "$(diff -r --brief tree asan_out 2>/dev/null | grep -v 'link.txt')" ]
                                                             chk $? "asan: bundle roundtrip"
else
    skip "ASan subset (run with SV_ASAN=1)"
fi

############################################
echo
echo "=============================="
echo " PASS: $PASS   FAIL: $FAIL   SKIP: $SKIP"
echo "=============================="
[ "$FAIL" = 0 ]
