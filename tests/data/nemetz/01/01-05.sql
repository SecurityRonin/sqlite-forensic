PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE '' (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO '' 
	(id, name, surname, zip)
	VALUES
	(20001, 'Susanne', 'Engel', '21397'),
	(20002, 'Pia', 'Pohl', '22949'),
	(20003, 'Maja', 'Peters', '82290'),
	(20004, 'Jana', 'Krause', '35625'),
	(20005, 'Matthias', 'Jung', '86343'),
	(20006, 'Rudolf', 'Weber', '24869'),
	(20007, 'Marlene', 'Müller', '67125'),
	(20008, 'Sarah', 'Fuchs', '24354'),
	(20009, 'Henry', 'Berger', '99734'),
	(20010, 'Leni', 'Bauer', '35466');

