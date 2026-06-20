PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=0;

CREATE TABLE 'members' (
	'mid' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'plz' INTEGER NULL
);

INSERT INTO 'members' 
	(mid, name, surname, plz)
	VALUES
	(30001, 'Luis', 'Günther', '59457'),
	(30002, 'Lea', 'Beck', '97638'),
	(30003, 'Erich', 'Hofmann', '91572'),
	(30004, 'Maja', 'Neumann', '96450'),
	(30005, 'Gustav', 'Albrecht', '80999'),
	(30006, 'Björn', 'Günther', '87561'),
	(30007, 'Daniela', 'Winkler', '59302'),
	(30008, 'Leni', 'Vogel', '74934'),
	(30009, 'Fritz', 'Otto', '72584'),
	(30010, 'Yvonne', 'Winkler', '42111'),
	(30011, 'Susanne', 'Meyer', '67112'),
	(30012, 'Isabell', 'Berger', '71292'),
	(30013, 'Herbert', 'Huber', '91452'),
	(30014, 'Emma', 'Weber', '56349'),
	(30015, 'Elisa', 'Haas', '56653'),
	(30016, 'Simon', 'Kaiser', '77974'),
	(30017, 'Matteo', 'Lorenz', '73569'),
	(30018, 'Daniela', 'Arnold', '60599'),
	(30019, 'Noah', 'Huber', '1768'),
	(30020, 'Jakob', 'Horn', '10781'),
	(30021, 'Meike', 'Günther', '67598'),
	(30022, 'Erna', 'Otto', '73760'),
	(30023, 'Philipp', 'Winkler', '94356'),
	(30024, 'Matteo', 'Franke', '89173'),
	(30025, 'Christine', 'Kaiser', '17491'),
	(30026, 'Lina', 'Günther', '51149'),
	(30027, 'Erich', 'Walter', '91741'),
	(30028, 'Sandra', 'Becker', '92703'),
	(30029, 'Hans', 'Stein', '29581'),
	(30030, 'Jakob', 'Haas', '63936');

CREATE TABLE 'users' (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'code' TEXT NULL,
	'plz' INTEGER NULL
);

INSERT INTO 'users' 
	(id, name, code, plz)
	VALUES
	(20001, 'Jan', 'R6jrI9oCPysXTvw7UL0MB4FWUSj8mI35EdnccCGS1ZGKl3H7EyJ7sfTcY4bbC587 l cOHWFwsgJmOGRdgPxmyBbsDeWzcTzoUD3rqzPKGoXlWFp3kOgKfj4JoQ sAzIk4CDk2iVzyJLkf2drHl2NvXnLDn44NDfH6JTZTFohf1tlTyDqKw56jiIOwCJa7QJ3qtS Z7i5ZDhJ2L0C9Wzi68YsBxuye5rvoave9F Y9ix1UouUaU', '93482'),
	(20002, 'Victoria', 'SqkgMJlH2HX4423z3RybfqWuLHwwBtfjLqqn1CWUaJO5BHuupUwvajQMRc ixft xKooda fKOacmwxCgVYh5FVNJVX82g8pSmFXoF30j43xqr0ycPH9lsMVeAU7HSnp6Tdlo7bz25XjmOIqtfpGz3sFtcD2WRhTBm5Qj7gb35mgJVx42OAsHTY2WsUJa3sCfnjplqsflFnWr', '74189'),
	(20003, 'Matthias', 'qhCZ1rROLBoMuHeAWpQ9H eTFtFX6m8muAbmTT2ukg7GOc7BtOA1OGKj0g8Wu6 Pxb3gWVC82zEHDB9XfzOV6p5Xx3KS0Kyn', '7607'),
	(20004, 'Gertrud', 'AdXy6n4DSwDGD3lo0CjO0doJ409iDrE5wstsGoXpLrXek9tbBEQsI53DV2MpkgkHzF17UPnv7aAiaVkDp1XZXQsJJ6ZVdasEGkBr1QNYSe8T0ingaa6YSoxslndppxUXJm', '21382'),
	(20005, 'Jonathan', 'TpMZnwPwLXxMTmv9LOk0TBfgm3QA8guSw8HLun86awJUJ5UlK5btxhBKbhaapwTNuqoQEnNFKmqkiawU7yduHF6JO8K5uuIQLYwgbaNNn4Yx6lh4LmpjSlTxkusGQ2mrQKyTLbw07ln4ywY Jdjrq4PBp9861koIWOrxRPnO2CIqZxrzBCSSwykNxiKou0XgEfFlVT1NmA5cYmCqPk9cJjR7trmOhaWNgrZ3bRHoiCr7QVo', '48624'),
	(20006, 'Tobias', 'zGyhETzRxISkl0CbTETqT2Tb0AXeXUtnrTvWDVD2umcGcFIW rdUkXXboLhbvCpNmMAQx4IThLplgY9hgc3s1QvfrDhO6ysjaT0zOyiXay9in8', '38324'),
	(20007, 'Henry', 'kO21 9jDgZAFhKH2B7H1fu3FubTsteuEUnwUmGouwQ0ErxxTv6LCqE8LGS51YqwIETsSq', '6779'),
	(20008, 'Anja', 'o3iGrHpOD2gUwfw4YsVMJhke2EXic0XrU6YcDeR78ZSu5foTzaw jHebc2lfT9yD6nHztoxrdgN9n3TN4fNeOSgRLsYusnZoCwPWMceQkSQyLzbGGPLkyT3 cSvv7lLzJqlluq3F9K4La6hHMUTaDNbGvy3sLESkV5xflrLl2GY3C6BfRlhkZkRlKLFl', '22309'),
	(20009, 'Erna', '1jV8wcJJ6gxZKurQbDYms 5FKGaXNpkEz7DWadv7kUXVeeBgIqu2qqx2YyPBO16eYA2ZEoXP9KAeP3lojHhBYFuM5 eK2bPRCHH7WuMW5c1L7d1gL9JAF4dA5iaXkRENpcKbxnZtrQ', '95362'),
	(20010, 'Ernst', 'XwwW6Yr12TWaVKmCf0SiBVHQK18rXncKKAxHoQygzlikXvO4mwdPiLvUDubqIf2jGpRV6g3wsbHgxmaLJeqTRNDk9GBHMtRjKz6GGZ401B7pO81odi9VXC6W yuNTcXtCT19JWZAnWQ3VIi0ShLFLIsM8NpRQdbjY4ixQ9Y5VFZHd9xXh tTIMwGqMo7QrgElq33pRYbmOKrN8fV8z', '66299'),
	(20011, 'Leon', '2etFtrmLzSYQLR7sG9GlJZZI6LHvheyajSHE UfAC5gdNdxjd5wOVmmRZUc70C9 lHFmrMNVH', '85128'),
	(20012, 'Sabine', 'Znv4jSJ55XMUIQSyiSzup5HHHltf7jqXyNSIvrDregcNXVc6DDrUz0s8bMd9XvXl9FUvXoN3vQHjCKf7eyREoaCrNGrA3eN2Kyo', '52146'),
	(20013, 'Markus', 'r KZjczqaEPT 5UCmx EZ3KCWk1aJF41FERQIh7JNMsNIcfVBgqr 1UWcMYNhSFOnmuWusw85PLETSqlZHD0zoMD1Ag jNOx0 klsHjonWT8E juINk92YCUpKUznzYeA9qTHA9VmSTST4drIorBdUltu7UJwJOYJ5HgwG3KpNs HwsfMKHRuUbQRWpew5360Bdn97YpLgpiEIphiYZEJ1kqOBwaxq8nSbBS9q8LxnU', '93343'),
	(20014, 'Oskar', 'b602BzUMRyeeACvyReBjYAAWcZaXTYZVVQNmfy0YY63oypOgufriHS6KI7yrWndI5SVag', '74399'),
	(20015, 'Rudolf', 'ITj89Zeu5xECfBdOyC7lRaUMTGO0jEVSn6RnVXJRkekqGo66R4hy53bOAQFKkrszn O YnR9s2pZgmWZg4ocYqRo7nZiFhJTinU7CB7WunLCAxrIsHLgYtvWHk6ctFXDTHBm y9uMLYd fNsOoACIXpf9ljtS7XCEpPEPO0spOxpVaJzp 3ZXi6Wvffdc4GIkmc114khIIxuJ8U08OPWXLJjSQoVLWtX9xO1rZ91xxm8v8YtME', '23974');

DELETE FROM members where mid == 30020;
DELETE FROM members where mid == 30024;
DELETE FROM members where mid == 30021;
DELETE FROM members where mid == 30014;
DELETE FROM members where mid == 30015;
DELETE FROM members where mid == 30023;
DELETE FROM members where mid == 30029;
DELETE FROM members where mid == 30001;
DELETE FROM members where mid == 30005;
DELETE FROM members where mid == 30011;

DELETE FROM users where id == 20010;
DELETE FROM users where id == 20012;
DELETE FROM users where id == 20015;
DELETE FROM users where id == 20002;
DELETE FROM users where id == 20007;

