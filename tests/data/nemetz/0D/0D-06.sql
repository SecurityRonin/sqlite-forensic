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
	(20001, 'Johann', 'Hoffmann', -144913111, -3293129186.28246),
	(20002, 'Michael', 'Kraus', -134346374, -2797182196.65679),
	(20003, 'Annika', 'Schmitz', 1184946766, -1502135142.91781),
	(20004, 'Irma', 'Baumann', 985155245, -4908664510.54284),
	(20005, 'Otto', 'Heinrich', 1155076104, -1594597751.55159),
	(20006, 'Lara', 'Horn', -384834918, -4829283044.59401),
	(20007, 'Oskar', 'Bergmann', -1167773723, -3232399634.19382),
	(20008, 'Julian', 'Möller', 692693150, -857419271.88701),
	(20009, 'Oskar', 'Jung', -1321280146, 2012170072.18495),
	(20010, 'Julius', 'Braun', 941308350, -252645646.80524);


PRAGMA secure_delete=0;
PRAGMA secure_delete;

DELETE FROM users where id == 20005;
DELETE FROM users where id == 20006;
DELETE FROM users where id == 20007;
DELETE FROM users where id == 20008;
DELETE FROM users where id == 20009;
DELETE FROM users where id == 20001;
DELETE FROM users where id == 20002;
DELETE FROM users where id == 20003;
DELETE FROM users where id == 20004;
DELETE FROM users where id == 20010;

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(20003, 'Nadine', 'Mayer', -309512131, -2625089393.75407),
	(20004, 'Emil', 'Jäger', 870402720, -26202949.24183),
	(20005, 'Helene', 'Hoffmann', 880365148, 1517503883.93062),
	(20006, 'Katrin', 'Seidel', 1470639698, -58175728.21778),
	(20007, 'Noah', 'Vogel', 408529756, -3108021606.74148);

