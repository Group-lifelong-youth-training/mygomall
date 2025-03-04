CREATE DATABASE IF NOT EXISTS `user`  
   DEFAULT CHARACTER SET = 'utf8mb4';;
USE `user`;
-- CREATE TABLE IF NOT EXISTS `user` (
--   `id` bigint NOT NULL,
--   `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
--   `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
--   `email` varchar(255) NOT NULL,
--   `password_hashed` text NOT NULL,
--   PRIMARY KEY (`id`),
--   UNIQUE KEY `email` (`email`)
-- ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci

CREATE TABLE IF NOT EXISTS `user` (
  `id` bigint NOT NULL,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `email` varchar(255) NOT NULL,
  `password_hashed` text NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci

CREATE DATABASE IF NOT EXISTS `order`
   DEFAULT CHARACTER SET = 'utf8mb4';;
USE `order`;
CREATE TABLE IF NOT EXISTS `local_message` (
    `id` bigint NOT NULL,   -- 每条消息的唯一 UUID
    -- business_key VARCHAR(64) NOT NULL,        -- 业务主键（如订单 ID）
    `topic` VARCHAR(128) NOT NULL,              -- 目标消息队列 Topic
    `message_body` TEXT NOT NULL,               -- 消息内容（JSON 格式）
    `status` TINYINT NOT NULL DEFAULT 0,        -- 0-待发送, 1-已发送, 2-发送失败
    `retry_count` INT NOT NULL DEFAULT 0,       -- 重试次数
    `created_at` datetime(3) DEFAULT NULL,
    `updated_at` datetime(3) DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci

CREATE TABLE IF NOT EXISTS `order` (
    `id` bigint NOT NULL,
    `created_at` datetime(3) DEFAULT NULL,
    `updated_at` datetime(3) DEFAULT NULL,
    `deleted_at` bigint unsigned DEFAULT NULL,
    `user_id` int unsigned NOT NULL,
    `street_address` varchar(191) NOT NULL,
    `city` varchar(191) NOT NULL,
    `state` varchar(191) NOT NULL,
    `country` varchar(191) NOT NULL,
    `zip_code` int NOT NULL,
    `order_state` varchar(191) NOT NULL,
    PRIMARY KEY (`id`),
    INDEX idx_orders_user_deleted (user_id, deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- auto migrate生成的
-- CREATE TABLE `order` (
--   `id` bigint NOT NULL AUTO_INCREMENT,
--   `created_at` datetime(3) DEFAULT NULL,
--   `updated_at` datetime(3) DEFAULT NULL,
--   `user_id` int unsigned DEFAULT NULL,
--   `user_currency` longtext,
--   `email` longtext,
--   `street_address` longtext,
--   `city` longtext,
--   `state` longtext,
--   `country` longtext,
--   `zip_code` int DEFAULT NULL,
--   `order_state` longtext,
--   `deleted_at` bigint unsigned DEFAULT NULL,
--   PRIMARY KEY (`id`),
--   KEY `idx_orders_user_deleted` (`user_id`,`deleted_at`)
-- ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci

CREATE TABLE IF NOT EXISTS `order_item` (
    `id` bigint NOT NULL,
    `created_at` datetime(3) DEFAULT NULL,
    `updated_at` datetime(3) DEFAULT NULL,
    `order_id_refer` bigint NOT NULL,
    `quantity` int NOT NULL,
    `cost` float NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `idx_order_item_order_id_refer` (`order_id_refer`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- automigrate生成的
-- CREATE TABLE `order_item` (
--   `id` bigint NOT NULL AUTO_INCREMENT,
--   `created_at` datetime(3) DEFAULT NULL,
--   `updated_at` datetime(3) DEFAULT NULL,
--   `order_id_refer` bigint DEFAULT NULL,
--   `quantity` int DEFAULT NULL,
--   `cost` float DEFAULT NULL,
--   PRIMARY KEY (`id`),
--   KEY `idx_order_item_order_id_refer` (`order_id_refer`),
--   CONSTRAINT `fk_order_order_items` FOREIGN KEY (`order_id_refer`) REFERENCES `order` (`id`)
-- ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci



#product service database
#一个商品可能有多个类别(category)，product表用json存储所有类别的name，用类别的name从catagory表中可以查到catgory描述等其他信息
#商品id用雪花算法生成int64类型的数
CREATE DATABASE IF NOT EXISTS `product`
   DEFAULT CHARACTER SET = 'utf8mb4';
USE `product`;
#商品表
CREATE TABLE IF NOT EXISTS `product` (
  `id` BIGINT NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `name` VARCHAR(255) NOT NULL UNIQUE,
  `description` TEXT,
  `picture` VARCHAR(255),
  `price` FLOAT NOT NULL,
  `store` INT NOT NULL,
  `status` TINYINT(1) default 1,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci

#多对多 商品-类别表
CREATE TABLE IF NOT EXISTS `product_category` (
    `id` BIGINT NOT NULL,
    `product_id` BIGINT NOT NULL,
    `category_id` BIGINT NOT NULL,
    `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    `description` TEXT,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci

#类别表
CREATE TABLE IF NOT EXISTS `category` (
    `id` BIGINT NOT NULL,
    `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `name` VARCHAR(255) NOT NULL UNIQUE,
    `description` TEXT,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci

