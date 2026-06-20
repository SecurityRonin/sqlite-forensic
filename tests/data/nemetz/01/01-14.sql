PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE ")" (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO ")" 
	(id, name, surname, zip)
	VALUES
	(20001, 'Isabella', 'Fischer', '84543'),
	(20002, 'Heinrich', 'Schulz', '88317'),
	(20003, 'Linus', 'Pohl', '73642'),
	(20004, 'Walter', 'Hofmann', '24891'),
	(20005, 'Claudia', 'Engel', '83339'),
	(20006, 'Leon', 'Hoffmann', '86447'),
	(20007, 'Werner', 'Bergmann', '6642'),
	(20008, 'Fritz', 'Engel', '38465'),
	(20009, 'Hanna', 'Frank', '65396'),
	(20010, 'Amelie', 'Schmidt', '54636');

