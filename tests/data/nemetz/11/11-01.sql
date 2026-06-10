PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=0;

CREATE TABLE 'users' (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'plz' INTEGER NULL
);

INSERT INTO 'users' 
	(id, name, surname, plz)
	VALUES
	(20001, 'Friedrich', 'Schwarz', '55569'),
	(20002, 'Bianca', 'Günther', '26835'),
	(20003, 'Julius', 'Dietrich', '33604'),
	(20004, 'Martina', 'Maier', '94496'),
	(20005, 'Thomas', 'Schmidt', '3246'),
	(20006, 'Josephine', 'Voigt', '25821'),
	(20007, 'Julian', 'Dietrich', '21376'),
	(20008, 'Finja', 'Friedrich', '56598'),
	(20009, 'Georg', 'Hahn', '29640'),
	(20010, 'Luca', 'Herrmann', '71554');

CREATE TABLE 'members' (
	'mid' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'plz' INTEGER NULL
);

INSERT INTO 'members' 
	(mid, name, surname, plz)
	VALUES
	(30001, 'Tom', 'Möller', '49770'),
	(30002, 'Jakob', 'Schäfer', '72813'),
	(30003, 'Leonie', 'Busch', '83236'),
	(30004, 'Noah', 'Schumacher', '32584'),
	(30005, 'Melina', 'Scholz', '9376'),
	(30006, 'Tim', 'Frank', '86653'),
	(30007, 'Benjamin', 'Pohl', '94086'),
	(30008, 'Elisa', 'Vogt', '21337'),
	(30009, 'Marc', 'Franke', '42551'),
	(30010, 'Pia', 'Schulte', '72160');

