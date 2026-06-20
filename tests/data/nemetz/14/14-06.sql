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
	(20001, 'Else', 'Lange', '89182'),
	(20002, 'Daniel', 'Jung', '9573'),
	(20003, 'Timo', 'Heinrich', '84066'),
	(20004, 'Sonja', 'Peters', '80796'),
	(20005, 'Jannik', 'Meyer', '79725'),
	(20006, 'Marc', 'Roth', '93349'),
	(20007, 'Melanie', 'Schmid', '26632'),
	(20008, 'Marlene', 'Köhler', '59269'),
	(20009, 'Sonja', 'Vogel', '65520'),
	(20010, 'Emilia', 'Frank', '14828');

CREATE TABLE 'members' (
	'mid' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'plz' INTEGER NULL
);

INSERT INTO 'members' 
	(mid, name, surname, plz)
	VALUES
	(30001, 'Vincent', 'Klein', '64342'),
	(30002, 'Otto', 'Ludwig', '88634'),
	(30003, 'Minna', 'Kühn', '21382'),
	(30004, 'Katja', 'Kaiser', '79189'),
	(30005, 'Elli', 'Schröder', '32312'),
	(30006, 'Simone', 'Klein', '91550'),
	(30007, 'Nina', 'Becker', '66953'),
	(30008, 'Tobias', 'Scholz', '94142'),
	(30009, 'Johann', 'Pfeiffer', '85465'),
	(30010, 'Theo', 'Seidel', '94569');

