PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE VIRTUAL TABLE 'users' using fts4(
	'name' TEXT,
	'surname' TEXT
);

INSERT INTO 'users' 
	(name, surname)
	VALUES
	('Helena', 'Seidel'),
	('Mia', 'Lorenz'),
	('Robert', 'Hahn'),
	('August', 'Winkler'),
	('Christian', 'Meier'),
	('Hanna', 'Simon'),
	('Sophie', 'Schulze'),
	('Claudia', 'Krämer'),
	('Irma', 'Thomas'),
	('Sandra', 'Roth');

