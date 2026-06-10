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

CREATE TABLE customers (
	'cid' INT UNSIGNED NOT NULL,
	'cname' TEXT NOT NULL,
	'csurname' TEXT NULL,
	'ccodeA' INT NULL,
	'ccodeB' FLOAT NULL
);

INSERT INTO customers 
	(cid, cname, csurname, ccodeA, ccodeB)
	VALUES
	(20001, 'Else', 'Baumann', -638832058, -4622540320.09400),
	(20002, 'Leonie', 'Voigt', 1356832582, 1122218759.78737),
	(20003, 'Willi', 'Roth', 26814793, -4376634517.39430),
	(20004, 'Daniel', 'Frank', -868473878, -3832535682.63377),
	(20005, 'Mathilda', 'Albrecht', 113384716, 334041065.22633),
	(20006, 'Kerstin', 'Schuster', -1050203857, 4213401474.62366),
	(20007, 'Luca', 'Scholz', 1643805150, 1166617011.72898),
	(20008, 'Zoe', 'Schubert', -603005252, 4007666590.16147),
	(20009, 'Christian', 'Schulze', 527030628, 4362154905.38727),
	(20010, 'Luisa', 'Kuhn', -1407291853, 4892744407.93914);

CREATE TABLE supplier (
	'sid' INT UNSIGNED NOT NULL,
	'sname' TEXT NOT NULL,
	'ssurname' TEXT NULL,
	'scodeA' INT NULL,
	'scodeB' FLOAT NULL
);

INSERT INTO supplier 
	(sid, sname, ssurname, scodeA, scodeB)
	VALUES
	(30001, 'Emil', 'Krüger', 52465577, -3679228838.84945),
	(30002, 'Lena', 'Lehmann', 797286194, 4846036098.82576),
	(30003, 'Sabine', 'Engel', -230248109, -1651222871.91973),
	(30004, 'Hanna', 'Schwarz', -1572781659, 853743164.73200),
	(30005, 'Wilhelm', 'Weiß', -354673743, -2784171229.12787),
	(30006, 'Fritz', 'Dietrich', 579279302, 3706605731.83867),
	(30007, 'Markus', 'Peters', -745906151, 696707133.06251),
	(30008, 'Jonas', 'Friedrich', -655783956, 2229061102.13560),
	(30009, 'Alina', 'Graf', 294233191, 4973077755.40886),
	(30010, 'Elsa', 'Baumann', 1115294317, 3550408421.34059);

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(50001, 'Jakob', 'Herrmann', 92481852, 2860930472.54762),
	(50002, 'Albert', 'Baumann', 524737760, -792230728.91693),
	(50003, 'Nils', 'Huber', -115809953, 4505732096.50150),
	(50004, 'Luca', 'Ludwig', -1094592542, 3484865416.99845),
	(50005, 'Sabine', 'Schmid', -1431162177, -1139333432.60518),
	(50006, 'Andrea', 'Walter', -887607723, -3139465482.97045),
	(50007, 'Frida', 'Haas', 828012897, 4658897588.80199),
	(50008, 'Erich', 'Bergmann', 1838111132, 2342768380.11237),
	(50009, 'Johanna', 'Weiß', -851466055, 4942739172.81196),
	(50010, 'Yvonne', 'Bauer', 811437580, 1595810557.06172);

PRAGMA secure_delete=0;
PRAGMA secure_delete;

DROP TABLE customers;

CREATE TABLE members (
	'mid' INT UNSIGNED NOT NULL,
	'mname' TEXT NOT NULL,
	'msurname' TEXT NULL,
	'mcodeA' INT NULL,
	'mcodeB' FLOAT NULL
);

INSERT INTO members 
	(mid, mname, msurname, mcodeA, mcodeB)
	VALUES
	(50001, 'Stefanie', 'Schuster', 794762503, -3863912159.04798),
	(50002, 'Stefan', 'Richter', -637933723, -745394963.65255),
	(50003, 'Henry', 'Schubert', -79316545, 4332708147.97502),
	(50004, 'Rudolf', 'Simon', 1634058353, -3528566112.98796),
	(50005, 'Jakob', 'Koch', -501958489, -3772401790.49429);

