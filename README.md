# nuspy
## Python NUS script

This is still a massive work-in-progress.

Originally written by OnionKnight, then forked by ajd4096.

Any messy bits are his, any broken bits are mine. :)

-----

# Requirements:
## Python 3
No, it won't work with Python 2.
Python 3 was released in 2008, it is time to move on.

## pycrypto
This isn't installed by default.
Without this, the crypto takes forever.

## BeautifulSoup4
This isn't installed by default, and isn't in most distro's package lists.
You will probably have to use pip.

## sqlite3
Probably installed when you installed Python 3.

### Centos 6
```
# The easiest way to install Python 3 is from the ius repo at http://ius.io
sudo yum install https://centos6.iuscommunity.org/ius-release.rpm
sudo yum install python35u python35u-setuptools python35u-tkinter
sudo ln -sf python3.5 /usr/bin/python3

# Install direct dependencies
# (You only need sqlite if you want to use the database files in external scripts.)
sudo yum install sqlite

# Install build dependencies
sudo yum install python35u-devel gmp-devel

# Install nuspy using:
sudo python3.5 setup.py install
```
-----

# For the lazy:

Download and extract TITLEID ready for loadiine:

nuspy.py -e --ekey=KEY TITLEID

Download and package UPDATEID ready for WUP installer:

nuspy.py -w UPDATEID

-----
# Warning:

This now stashes info in a few sqlite3 DBs.
* I make *zero* promises to keep it the same across updates.
* If I remember, I might check in a new one.
* If it doesn't work, remove the .db files and build your own.
