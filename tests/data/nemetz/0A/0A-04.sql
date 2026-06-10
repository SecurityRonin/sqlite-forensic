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

CREATE TABLE members (
	'mid' INT UNSIGNED NOT NULL,
	'mname' TEXT NOT NULL,
	'msurname' TEXT NULL,
	'mcodeA' INT NULL,
	'mcodeB' FLOAT NULL
);

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(50001, 'Willi', 'Schmid', -816479468, -4312754557.14797),
	(50002, 'Elisabeth', 'Maier', 1948668931, -1571122615.86409),
	(50003, 'Wilhelm', 'Winkler', 633964045, -3841587840.04002),
	(50004, 'Jonas', 'Pfeiffer', 362920855, 1260197561.35540),
	(50005, 'Erich', 'Winter', 1405645818, -2494216718.47544),
	(50006, 'Benjamin', 'Schäfer', -217632058, 4032270824.08605),
	(50007, 'Matthias', 'Winter', 980959116, 2535435523.62148),
	(50008, 'Maria', 'Horn', -766387937, -1372460064.65166),
	(50009, 'Luisa', 'Peters', -397507038, -3015542928.13667),
	(50010, 'Jonas', 'Weiß', -391947008, -1830983686.64784);

INSERT INTO members 
	(mid, mname, msurname, mcodeA, mcodeB)
	VALUES
	(20001, 'Jonas', 'Haas', -123930712, -303276248.88312),
	(20002, 'Lea', 'Krüger', -561919370, -1127155309.60222),
	(20003, 'Amelie', 'Bergmann', -556040042, -3122846962.94127),
	(20004, 'Benjamin', 'Hahn', 278759972, 3487245509.62786),
	(20005, 'Rudolf', 'Winter', 624210223, -516637603.52723),
	(20006, 'Marie', 'Otto', -150129718, 687925119.73899),
	(20007, 'Max', 'Vogt', -384562075, -2915923622.39767),
	(20008, 'Finja', 'Ludwig', 529038696, 3817676063.07644),
	(20009, 'Alfred', 'Krause', 1290572517, -4879181855.30192),
	(20010, 'Daniel', 'Kühn', -815614413, 2991500775.32581);


PRAGMA secure_delete=0;
PRAGMA secure_delete;

DELETE FROM members where mid == 20001;
DELETE FROM members where mid == 20006;
DELETE FROM members where mid == 20004;
DELETE FROM members where mid == 20002;
DELETE FROM members where mid == 20007;
DELETE FROM members where mid == 20003;
DELETE FROM members where mid == 20010;
DELETE FROM members where mid == 20005;
DELETE FROM members where mid == 20009;
DELETE FROM members where mid == 20008;

DROP TABLE users;
DROP TABLE members;
