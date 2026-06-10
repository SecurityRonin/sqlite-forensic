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
	(20001, 'Anja', 'Hartmann', 496460508, -505080388.62845),
	(20002, 'Leni', 'König', 84374705, 3611121228.24933),
	(20003, 'Charlotte', 'Koch', -274631635, 3314351392.12494),
	(20004, 'Simon', 'Schulte', -1248176992, -3143906052.29135),
	(20005, 'Eric', 'Schumacher', -915976262, -611483233.79992),
	(20006, 'Elisabeth', 'Beck', 229635902, 32060386.16228),
	(20007, 'Leni', 'Schreiber', 1314199476, -4059448823.82613),
	(20008, 'Elsa', 'Schmid', -1077188344, -870435482.76203),
	(20009, 'Helena', 'Brandt', -63458245, 1880819977.67129),
	(20010, 'Lukas', 'Schmitt', -421308061, -1994595232.88281);

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
	(20005, 'Silke', 'Scholz', -1417811130, 3564912485.22183),
	(20006, 'Jörg', 'Peters', 333744532, -1720403394.06599),
	(20007, 'David', 'Schreiber', 52043592, 2783723002.19895),
	(20008, 'Daniel', 'Schröder', 420768372, 2164912511.20573),
	(20009, 'Hertha', 'Kuhn', -701406907, -3539776633.74496);

