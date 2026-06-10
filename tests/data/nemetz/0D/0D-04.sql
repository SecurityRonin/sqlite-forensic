PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE users (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'codeA' INT NULL,
	'codeB' FLOAT NULL
);

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(20001, 'Maja', 'Walter', 415700842, -106146999.21857),
	(20002, 'Erich', 'Simon', -781936359, 2219003731.02119),
	(20003, 'Annika', 'Maier', -430291980, -4161149588.95424),
	(20004, 'Silke', 'Sommer', -95968798, 9350546.17438),
	(20005, 'Vincent', 'Zimmermann', -379434507, 226975937.94529),
	(20006, 'Lisa', 'Arnold', 307818773, 4119462179.54134),
	(20007, 'Elfriede', 'Roth', 1526902782, -1169769692.31375),
	(20008, 'Gustav', 'Keller', -1420315149, -2332453703.19693),
	(20009, 'Theo', 'Werner', 1101065816, -266782024.53385),
	(20010, 'Sascha', 'Engel', 549176368, -1270120947.74755);

PRAGMA secure_delete=0;
PRAGMA secure_delete;

DELETE FROM users where id == 20005;
DELETE FROM users where id == 20006;
DELETE FROM users where id == 20007;
DELETE FROM users where id == 20008;
DELETE FROM users where id == 20009;

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(20005, 'Jörg', 'Vogel', -1421734211, 2001605237.36924),
	(20006, 'Johanna', 'Simon', -1670655446, 528326763.55183),
	(20007, 'Luca', 'Engel', 1091415796, 826134065.08515);

