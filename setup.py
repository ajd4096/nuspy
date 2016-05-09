from setuptools import setup

setup(
	name		= 'nuspy',
	version		= '0.1',
	description	= 'Download/decrypt/extract files from Nintendo Update Service',
	url		= 'http://github.com/ajd4096/nuspy',
	author		= 'Andrew Dalgleish',
	author_email	= 'ajd4096@github.com',
	license		= 'BSD',
	packages	= ['nuspy'],
	entry_points	= {
		"console_scripts": [
			'nuspy			= nuspy.nuspy:main',
			'nuspy-samurai		= nuspy.samurai:main',
			'nuspy-tagaya		= nuspy.tagaya:main',
			'nuspy-titlekeys	= nuspy.titlekeys:main',
			'nuspy-wiiubrew		= nuspy.wiiubrew:main',
		],
	},
	install_requires	= [
		'bs4',
		'pycrypto',
		'requests',
	],
	zip_safe	= True)
