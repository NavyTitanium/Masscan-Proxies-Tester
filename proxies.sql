DROP TABLE IF EXISTS `proxies`;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `proxies` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `ipv4` int(10) unsigned NOT NULL,
  `port` smallint(5) unsigned NOT NULL,
  `date_tested` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `reason` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
