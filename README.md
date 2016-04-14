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
