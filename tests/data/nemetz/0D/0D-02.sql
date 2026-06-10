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
	(20001, 'Dennis', 'Hahn', 558234892, -1571165154.02271),
	(20002, 'Isabella', 'Wagner', -411303758, 201765510.81322),
	(20003, 'Moritz', 'Krämer', -1548008490, -1054287155.18410),
	(20004, 'Pia', 'Neumann', -641747950, -4810827621.17070),
	(20005, 'Daniela', 'Mayer', 1170605963, 2562280780.43194),
	(20006, 'Jan', 'Meyer', -988550846, -2216051349.98264),
	(20007, 'Hermann', 'Wolff', -662126031, -3181684575.12822),
	(20008, 'Sarah', 'Graf', -661790941, 4231336190.93864),
	(20009, 'Luisa', 'Engel', -881064946, 4863772862.52741),
	(20010, 'Melanie', 'Meyer', -512750394, 4368689600.08430);

PRAGMA secure_delete=0;
PRAGMA secure_delete;

DELETE FROM users where id == 20005;
DELETE FROM users where id == 20001;
DELETE FROM users where id == 20008;
DELETE FROM users where id == 20009;
DELETE FROM users where id == 20010;

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(20011, 'Jonas', 'Richter', 554633827, -1683865160.06843),
	(20012, 'Kurt', 'Günther', -1345080015, 1954596530.15928),
	(20013, 'Wilhelm', 'Krämer', 885425942, -4820290370.76062),
	(20014, 'Nina', 'Schmitz', -1051574944, -575443774.26405),
	(20015, 'Friedrich', 'Kaiser', 66578515, -4138718475.18660);

