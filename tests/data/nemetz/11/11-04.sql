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
	(20001, 'Lotta', 'Voigt', '86641'),
	(20002, 'Julia', 'Frank', '88147'),
	(20003, 'Melina', 'Schneider', '89440'),
	(20004, 'Hannes', 'Weber', '31196'),
	(20005, 'Michael', 'Fischer', '14624'),
	(20006, 'Marlon', 'Dietrich', '92727'),
	(20007, 'Timo', 'Dietrich', '86681'),
	(20008, 'Andrea', 'Hoffmann', '33803'),
	(20009, 'Anna', 'Voigt', '66500'),
	(20010, 'Else', 'Mayer', '1900');

