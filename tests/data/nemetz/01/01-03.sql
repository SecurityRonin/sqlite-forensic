PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE '[' (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO '[' 
	(id, name, surname, zip)
	VALUES
	(20001, 'Niklas', 'Heinrich', '40217'),
	(20002, 'Marlon', 'Krüger', '14055'),
	(20003, 'Tanja', 'Jäger', '63849'),
	(20004, 'Ben', 'Peters', '29468'),
	(20005, 'Elfriede', 'Bergmann', '27568'),
	(20006, 'Niklas', 'Thomas', '67459'),
	(20007, 'Margarethe', 'Schäfer', '84066'),
	(20008, 'Daniel', 'Baumann', '30974'),
	(20009, 'Karl', 'Walter', '89195'),
	(20010, 'Jannik', 'Möller', '21398');

