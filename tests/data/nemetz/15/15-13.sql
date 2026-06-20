PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=0;

CREATE TABLE 'users' (
	'hiddenColumn' INTEGER NULL,
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL
);

INSERT INTO 'users' 
	(id, name, surname)
	VALUES
	(20001, 'Walter', 'Stein'),
	(20002, 'Johannes', 'Wolff'),
	(20003, 'Luca', 'Busch'),
	(20004, 'Frida', 'Köhler'),
	(20005, 'Ida', 'Mayer'),
	(20006, 'Irma', 'Graf'),
	(20007, 'Andreas', 'Schubert'),
	(20008, 'Paul', 'Hofmann'),
	(20009, 'Andreas', 'Bergmann'),
	(20010, 'Nadine', 'Richter');

