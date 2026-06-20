PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'users' (
	'name' [INTEGER, 'abc' TEXT,],
	'surname' TEXT
);

INSERT INTO 'users' 
	(name, surname)
	VALUES
	('Wilhelm', 'Müller'),
	('Heinrich', 'Maier'),
	('Julius', 'Neumann'),
	('Nils', 'Lehmann'),
	('Daniel', 'Brandt'),
	('Andreas', 'Berger'),
	('Elisa', 'Engel'),
	('Matthias', 'Krüger'),
	('Julian', 'Brandt'),
	('Philipp', 'Schneider');

