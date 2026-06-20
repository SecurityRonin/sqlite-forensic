PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'users' (
	'name' TEXT"abc,",
	'surname' TEXT
);

INSERT INTO 'users' 
	(name, surname)
	VALUES
	('Gustav', 'Kaiser'),
	('Werner', 'Winter'),
	('Philipp', 'Richter'),
	('Andreas', 'Hartmann'),
	('Gustav', 'Schulz'),
	('Nina', 'Jäger'),
	('Fritz', 'Schmitt'),
	('Andre', 'Herrmann'),
	('Linus', 'Hahn'),
	('Berta', 'Jung');

