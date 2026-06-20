PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=0;

CREATE TABLE 'users' (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'plz' INTEGER NULL
);

INSERT INTO 'users' 
	(id, name, surname, plz)
	VALUES
	(20001, 'Lotta', 'Voigt', '1683'),
	(20002, 'Max', 'Dietrich', '74747'),
	(20003, 'Julian', 'Müller', '91090'),
	(20004, 'Till', 'Beck', '64754'),
	(20005, 'Jannik', 'Huber', '53721'),
	(20006, 'Anton', 'Sauer', '72359'),
	(20007, 'Jan', 'König', '89297'),
	(20008, 'Emilia', 'Kraus', '35321'),
	(20009, 'Alina', 'Schäfer', '4107'),
	(20010, 'Meike', 'Kühn', '46397');

