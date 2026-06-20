PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'users' (
	'id' INTEGER,
	'name' TEXT,
	'surname' TEXT,
	'zip' INTEGER,
	PRIMARY KEY (id)
) WITHOUT ROWID;

INSERT INTO 'users' 
	(id, name, surname, zip)
	VALUES
	(20001, 'Michael', 'Hofmann', '60594'),
	(20002, 'Franz', 'Lehmann', '84137'),
	(20003, 'Lea', 'Pfeiffer', '71292'),
	(20004, 'Lotta', 'Kraus', '86674'),
	(20005, 'Hanna', 'Haas', '82398'),
	(20006, 'Daniel', 'Kaiser', '79280'),
	(20007, 'Stefan', 'Schumacher', '94143'),
	(20008, 'Franz', 'Neumann', '38895'),
	(20009, 'Anton', 'Albrecht', '51371'),
	(20010, 'Helene', 'Albrecht', '54455');
