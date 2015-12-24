#!/bin/sh -e

# Fetch the version list version
wget -N --no-check-certificate https://tagaya.wup.shop.nintendo.net/tagaya/versionlist/EUR/EU/latest_version

# Reformat the XML so each tag is on a single line
tidy -i -xml latest_version > latest_version.tidy 2>/dev/null

VER=$(grep '<version>' latest_version.tidy | sed 's/ *<[^>]*>//g')

# Fetch the list of title versions
wget -N --no-check-certificate https://tagaya.wup.shop.nintendo.net/tagaya/versionlist/EUR/EU/list/$VER.versionlist

# Reformat the XML so each tag is on a single line
tidy -i -xml $VER.versionlist > $VER.versionlist.tidy 2>/dev/null

# Get the list of update title ids
grep '<id>' $VER.versionlist.tidy |
sed 's/ *<[^>]*>//g' |
grep -i '0005000E' |
while read TID; do
	# Fetch/extract the meta.xml
	./nuspy.py -q --meta $TID
done
