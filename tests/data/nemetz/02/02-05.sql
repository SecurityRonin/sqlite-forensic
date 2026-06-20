PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'users' (
	'name' '[TEXT, ", abc" );',
	'surname' TEXT
);

INSERT INTO 'users' 
	(name, surname)
	VALUES
	('Paul', 'Schulze'),
	('Julian', 'Schuster'),
	('Clara', 'Huber'),
	('Minna', 'Kraus'),
	('Frank', 'Horn'),
	('Felix', 'Simon'),
	('Melanie', 'Huber'),
	('Christian', 'Walter'),
	('David', 'Schulze'),
	('Paula', 'Jäger');

