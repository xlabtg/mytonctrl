dest="mytonctrl_backup_$(hostname)_$(date +%s).tar.gz"
mtc_dir="$HOME/.local/share/mytoncore"
user=${SUDO_USER:-$(logname)}
ton_dir="/var/ton-work"
keys_dir="/var/ton-work/keys"
# Get arguments
while getopts d:m:t:k:u: flag
do
	case "${flag}" in
		d) dest=${OPTARG};;
    m) mtc_dir=${OPTARG};;
    t) ton_dir=${OPTARG};;
    k) keys_dir=${OPTARG};;
    u) user=${OPTARG};;
    *)
        echo "Flag -${flag} is not recognized. Aborting"
        exit 1 ;;
	esac
done

COLOR='\033[92m'
ENDC='\033[0m'

# The archive bundles validator/wallet PRIVATE KEYS. Restrict the umask so the
# staging directory and every copied file is owner-only, and use an
# unpredictable mktemp path instead of a fixed, world-traversable location to
# avoid symlink/pre-creation attacks by other local users.
umask 077
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/mytoncore_backup.XXXXXXXX") || exit 1
mkdir "$tmp_dir/db"

cp "$ton_dir/db/config.json" "${tmp_dir}/db"
cp -r "$ton_dir/db/keyring" "${tmp_dir}/db"
cp -r "$keys_dir" "${tmp_dir}"
cp -r "$mtc_dir" "$tmp_dir"

python3 -c "import json;f=open('${tmp_dir}/db/config.json');json.load(f);f.close()" || exit 1  # Check if config.json is copied correctly
python3 -c "import json;f=open('${tmp_dir}/mytoncore/mytoncore.db');json.load(f);f.close()" || exit 2  # Check if mytoncore.db is copied correctly

echo -e "${COLOR}[1/2]${ENDC} Copied files to ${tmp_dir}"

tar -zcf "$dest" -C "$tmp_dir" .

# Keep the archive readable only by its owner before handing it to the user.
chmod 600 "$dest"
chown "$user:$user" "$dest"

echo -e "${COLOR}[2/2]${ENDC} Backup successfully created in ${dest}!"

rm -rf "$tmp_dir"

echo -e "If you wish to use archive package to migrate node to different machine please make sure to stop validator and mytoncore on donor (this) host prior to migration."
