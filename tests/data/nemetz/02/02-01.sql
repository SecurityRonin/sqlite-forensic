PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'users' (
	["name" NOT NULL,] TEXT,
	'surname' TEXT
);

INSERT INTO 'users' 
	(["name" NOT NULL,], surname)
	VALUES
	('Marco', 'Albrecht'),
	('Alexander', 'Hofmann'),
	('Raphael', 'Pohl'),
	('Hedwig', 'Fuchs'),
	('Mike', 'Schröder'),
	('Vincent', 'Wolf'),
	('Noah', 'Kaiser'),
	('Jakob', 'Schmidt'),
	('Theo', 'Arnold'),
	('Julius', 'Meyer');

