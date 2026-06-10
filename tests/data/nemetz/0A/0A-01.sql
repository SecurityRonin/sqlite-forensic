PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE users (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'codeA' INT NULL,
	'codeB' FLOAT NULL
);

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(20001, 'Emil', 'Becker', 522823523, 1653469962.37220),
	(20002, 'Marie', 'Günther', -902131171, 863019295.90433),
	(20003, 'Frank', 'Hartmann', -428159782, 4935652487.88132),
	(20004, 'Mathilda', 'Maier', 88862114, 3882445007.97356),
	(20005, 'Gustav', 'Schröder', -1080780961, -3585207680.51278),
	(20006, 'Finja', 'Koch', -458894918, 3383637828.93104),
	(20007, 'Susanne', 'Albrecht', 1012277068, -2279000984.16908),
	(20008, 'Lia', 'Berger', -886371193, 3240637261.53254),
	(20009, 'Anton', 'Franke', -1144592913, 3981085745.14328),
	(20010, 'Anni', 'Hoffmann', -144963492, 1463235703.51267),
	(20011, 'Fritz', 'Schumacher', 35528043, -1419794180.62595),
	(20012, 'Laura', 'Pohl', 1324756411, -840692005.97736),
	(20013, 'Lia', 'Arnold', -60961932, -626682716.24794),
	(20014, 'Max', 'Albrecht', 685805273, 4080436718.22196),
	(20015, 'Hans', 'Heinrich', -678305697, 3551747416.40303),
	(20016, 'Walter', 'Lang', -532345559, 4281071470.71560),
	(20017, 'Nils', 'Schmidt', 1190878564, -4631356121.80054),
	(20018, 'Anton', 'Schmidt', -289514416, 2831034137.78871),
	(20019, 'Anton', 'Klein', 652175877, 3015545847.83295),
	(20020, 'Erich', 'Graf', 158480544, -1283453780.35840);

PRAGMA secure_delete=0;
PRAGMA secure_delete;

DROP TABLE users;
