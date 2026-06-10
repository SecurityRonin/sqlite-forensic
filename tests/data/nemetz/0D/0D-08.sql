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
	(50001, 'Dennis', 'Scholz', 987951571, 1206500710.08434),
	(50002, 'Christine', 'Bauer', -24769137, 4924588967.07957);

INSERT INTO members 
	(mid, mname, msurname, mcodeA, mcodeB)
	VALUES
	(20001, 'Fritz', 'Schuster', -283884189, 1264954794.32165),
	(20002, 'Tom', 'König', 729714994, 2343303890.59303);

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(50003, 'Simone', 'Schmitz', -1786537610, -3575526600.97160),
	(50004, 'Laura', 'Berger', 956436705, -1820925379.55424);

INSERT INTO members 
	(mid, mname, msurname, mcodeA, mcodeB)
	VALUES
	(20003, 'Jörg', 'Groß', -2031336654, -2184103455.94590),
	(20004, 'Marlene', 'Braun', 589507511, -71455922.47669);

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(50005, 'Gertrud', 'Jung', -494564309, 1714232087.46791),
	(50006, 'Susanne', 'Lange', -608600536, 629345646.88678);

INSERT INTO members 
	(mid, mname, msurname, mcodeA, mcodeB)
	VALUES
	(20005, 'Oliver', 'Haas', -1271963255, -3830944597.17672),
	(20006, 'Jens', 'Köhler', -1537558649, -792729368.33684);

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(50007, 'Katrin', 'Kaiser', 208800656, -1911035960.96441),
	(50008, 'Stefanie', 'Friedrich', 422288726, -2903737364.29202);

INSERT INTO members 
	(mid, mname, msurname, mcodeA, mcodeB)
	VALUES
	(20007, 'Stefan', 'Martin', 747524512, -4747404903.05582),
	(20008, 'Emelie', 'Brandt', 490693088, -601240287.34921);

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(50009, 'Anne', 'Berger', 748655134, 4138660179.05002),
	(50010, 'Nina', 'Schreiber', -1448626403, 1164898800.74044);

INSERT INTO members 
	(mid, mname, msurname, mcodeA, mcodeB)
	VALUES
	(20009, 'Melanie', 'Lang', 1323504028, 4868485173.14926),
	(20010, 'Finja', 'Hahn', -1079668710, -486361792.07189);

PRAGMA secure_delete=0;
PRAGMA secure_delete;

DELETE FROM members where mid == 20005;
DELETE FROM members where mid == 20007;
DELETE FROM members where mid == 20003;
DELETE FROM members where mid == 20004;
DELETE FROM members where mid == 20009;

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(50011, 'Albert', 'Becker', -134628787, -2169588616.66247),
	(50012, 'Emma', 'Heinrich', 160378337, -4126225872.48973),
	(50013, 'Sophie', 'Mayer', 42058894, -3689085845.22507),
	(50014, 'Dirk', 'Meyer', -214877161, 4105965359.65147),
	(50015, 'Sabine', 'Werner', -481222987, -4741576318.50875);

