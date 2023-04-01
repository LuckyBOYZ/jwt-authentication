CREATE TABLE `authentication`.`user` (
    `id` BIGINT(20) AUTO_INCREMENT PRIMARY KEY NOT NULL,
    `username` VARCHAR(50) UNIQUE NOT NULL,
    `password` VARCHAR(100) NOT NULL,
    `firstname` VARCHAR(30) NOT NULL,
    `lastname` VARCHAR(30) NOT NULL,
    `role` VARCHAR(30) NOT NULL,
    UNIQUE INDEX `username_UNIQUE` (`username` ASC) VISIBLE
);

CREATE TABLE `authentication`.`refreshtoken` (
    `refreshtoken_id` VARCHAR(36) PRIMARY KEY NOT NULL,
    `expiry_time` BIGINT(12) NOT NULL,
    `username` VARCHAR(50) UNIQUE NOT NULL,
    `enable` TINYINT(1) DEFAULT 0,
    UNIQUE INDEX `username_UNIQUE` (`username` ASC) VISIBLE
);
