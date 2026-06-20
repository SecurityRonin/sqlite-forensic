PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'users' ("name"TEXT,surname'TEXT');

INSERT INTO 'users' 
	(name, surname)
	VALUES
	('Lukas', 'Krämer'),
	('Wilhelm', 'Heinrich'),
	('August', 'Vogt'),
	('Jessica', 'Graf'),
	('Matthias', 'Herrmann'),
	('Rudolf', 'Krämer'),
	('Ella', 'Lange'),
	('Mats', 'Günther'),
	('Artur', 'Seidel'),
	('Michaela', 'Winter');

