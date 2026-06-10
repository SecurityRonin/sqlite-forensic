PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=0;

CREATE TABLE 'users' (
	'id' INT UNSIGNED NOT NULL,
	'plz' INTEGER NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL
);

INSERT INTO 'users' 
	(id, plz, name, surname)
	VALUES
	(20001, '39171', 'August', 'Fischer'),
	(20002, '94491', 'Torsten', 'Engel'),
	(20003, '45478', 'Paula', 'Schumacher'),
	(20004, '97456', 'Matteo', 'Schmid'),
	(20005, '73333', 'Martina', 'Schröder'),
	(20006, '21397', 'Hermann', 'Vogt'),
	(20007, '85764', 'Alexandra', 'Braun'),
	(20008, '1454', 'Walter', 'Bergmann'),
	(20009, '35638', 'Franz', 'Wolff'),
	(20010, '54689', 'Alina', 'Dietrich');

CREATE TABLE 'members' (
	'mid' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'plz' INTEGER NULL
);

INSERT INTO 'members' 
	(mid, name, surname, plz)
	VALUES
	(30001, 'Simone', 'Jung', '30655'),
	(30002, 'Amelie', 'Hartmann', '26723'),
	(30003, 'Dirk', 'Otto', '97788'),
	(30004, 'Tom', 'Möller', '77887'),
	(30005, 'Maja', 'Franke', '44625'),
	(30006, 'Herbert', 'Hartmann', '7957'),
	(30007, 'Eric', 'Bauer', '81549'),
	(30008, 'Heinrich', 'Becker', '79117'),
	(30009, 'Jens', 'Jäger', '96479'),
	(30010, 'Isabella', 'Schröder', '97903');

