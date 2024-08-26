apt update
apt install wget unzip -y

# Install Python 3.12.3 from source since Ubuntu 18.04 packages do not include this Python version
echo '\nCompiling Python 3.12.3 from source code, it can take some time.\n'
sleep 2
sudo apt install build-essential python3-dev python3-setuptools libncursesw5-dev libgdbm-dev zlib1g-dev libsqlite3-dev tk-dev libssl-dev openssl libffi-dev libncurses5-dev libreadline-dev python3-tk uuid-dev lzma-dev liblzma-dev libgdbm-compat-dev libbz2-dev tk-dev -y
# Compile OpenSSL
wget https://www.openssl.org/source/openssl-1.1.1w.tar.gz -O /tmp/openssl-1.1.1w.tar.gz
tar -xzf /tmp/openssl-1.1.1w.tar.gz -C /tmp/
cd /tmp/openssl-1.1.1w
./config --prefix=/usr/local/temp_openssl --openssldir=/usr/local/temp_openssl
make -j8
make test
make install
# Compile Python 3.12.3
wget https://www.python.org/ftp/python/3.12.3/Python-3.12.3.tgz -O /tmp/Python-3.12.3.tgz
tar -xzf /tmp/Python-3.12.3.tgz -C /tmp/
cd /tmp/Python-3.12.3
./configure --enable-optimizations --with-ensurepip=install --with-openssl=/usr/local/temp_openssl
make -j8
make altinstall

# Download AirBugCatcher source code
mkdir /home/user/wdissector/modules/airbugcatcher
wget https://anonymous.4open.science/api/repo/air-bug-catcher-E5C2/zip -O /tmp/airbugcatcher.zip
unzip /tmp/airbugcatcher.zip -d /home/user/wdissector/modules/airbugcatcher
cd /home/user/wdissector/modules/airbugcatcher
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

echo '\nSetup for AirBugCatcher is now complete!'
