PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'users' (
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
	);

CREATE INDEX surnameZip ON users (surname, zip);

INSERT INTO 'users' 
	(name, surname, zip)
	VALUES
	('Maximilian', 'Klein', '35719'),
	('Stefanie', 'Busch', '83071'),
	('Irma', 'Schröder', '1979'),
	('Robert', 'Jäger', '34628'),
	('Alina', 'Neumann', '75337'),
	('Mathilda', 'Krämer', '44869'),
	('Fabian', 'Busch', '24635'),
	('Silke', 'Fuchs', '6847'),
	('Mike', 'Günther', '64572'),
	('Matthias', 'Herrmann', '7330');

